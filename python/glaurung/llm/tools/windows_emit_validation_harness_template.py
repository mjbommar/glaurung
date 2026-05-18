from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import WindowsReviewPacket
from .windows_emit_vm_validation_plan import WindowsVmValidationPlan
from .windows_record_candidate_snapshot_mapping import WindowsCandidateSnapshotMapping


class WindowsEmitValidationHarnessTemplateArgs(BaseModel):
    candidate_packet: WindowsReviewPacket = Field(
        ...,
        description="Static candidate packet to scaffold validation for.",
    )
    validation_plan: WindowsVmValidationPlan | None = Field(
        None,
        description="Optional VM validation plan that supplies snapshot and artifact requirements.",
    )
    snapshot_mapping: WindowsCandidateSnapshotMapping | None = Field(
        None,
        description="Optional candidate/snapshot mapping to gate harness readiness.",
    )
    output_dir: str | None = Field(
        None,
        description="Optional directory where README and PowerShell template files are written.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add the harness template as a KB evidence node.",
    )


class WindowsValidationHarnessTemplate(BaseModel):
    candidate_id: str
    claim_level: str = "harness_template_not_execution"
    harness_id: str
    binary: str
    entrypoint: str
    sink_symbol: str
    harness_strategy: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    stock_steps: list[str] = Field(default_factory=list)
    current_steps: list[str] = Field(default_factory=list)
    artifact_requirements: list[str] = Field(default_factory=list)
    skeleton_commands: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    ready_to_collect_artifacts: bool
    markdown: str
    output_files: list[str] = Field(default_factory=list)


class WindowsEmitValidationHarnessTemplateResult(BaseModel):
    template: WindowsValidationHarnessTemplate
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsEmitValidationHarnessTemplateTool(
    MemoryTool[
        WindowsEmitValidationHarnessTemplateArgs,
        WindowsEmitValidationHarnessTemplateResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_emit_validation_harness_template",
                description=(
                    "Emit an operator-facing Windows validation harness template "
                    "from a candidate packet, optional VM validation plan, and "
                    "optional candidate/snapshot mapping. This writes scaffolding "
                    "only; it does not execute the harness or claim reproduction."
                ),
                tags=("windows", "pe", "validation", "harness", "template"),
            ),
            WindowsEmitValidationHarnessTemplateArgs,
            WindowsEmitValidationHarnessTemplateResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsEmitValidationHarnessTemplateArgs,
    ) -> WindowsEmitValidationHarnessTemplateResult:
        template = _build_template(args)
        if args.output_dir:
            template.output_files = _write_template_files(Path(args.output_dir), template)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_emit_validation_harness_template",
                    props={
                        "candidate_id": template.candidate_id,
                        "harness_id": template.harness_id,
                        "ready_to_collect_artifacts": template.ready_to_collect_artifacts,
                        "blocker_count": len(template.blockers),
                        "output_files": list(template.output_files),
                    },
                    text=template.markdown,
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsEmitValidationHarnessTemplateResult(
            template=template,
            evidence_node_id=evidence_node_id,
            notes=[
                "harness template only; execute it manually and record artifacts before finding promotion"
            ],
        )


def _build_template(
    args: WindowsEmitValidationHarnessTemplateArgs,
) -> WindowsValidationHarnessTemplate:
    packet = args.candidate_packet
    plan = args.validation_plan
    mapping = args.snapshot_mapping
    harness_id = _harness_id(packet.candidate_id)
    strategy = _harness_strategy(packet, plan)
    preconditions = _preconditions(packet, plan, mapping)
    stock_steps = _stock_steps(packet, plan)
    current_steps = _current_steps(packet, plan)
    artifacts = _artifact_requirements(plan)
    commands = _skeleton_commands(packet, plan)
    blockers = _blockers(strategy, plan, mapping, artifacts)
    markdown = _markdown(
        packet,
        harness_id=harness_id,
        strategy=strategy,
        preconditions=preconditions,
        stock_steps=stock_steps,
        current_steps=current_steps,
        artifacts=artifacts,
        commands=commands,
        blockers=blockers,
    )
    return WindowsValidationHarnessTemplate(
        candidate_id=packet.candidate_id,
        harness_id=harness_id,
        binary=packet.binary,
        entrypoint=packet.entrypoint,
        sink_symbol=packet.sink_symbol,
        harness_strategy=strategy,
        preconditions=preconditions,
        stock_steps=stock_steps,
        current_steps=current_steps,
        artifact_requirements=artifacts,
        skeleton_commands=commands,
        blockers=blockers,
        ready_to_collect_artifacts=not blockers,
        markdown=markdown,
    )


def _harness_id(candidate_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", candidate_id).strip("-").lower()
    return f"win-harness-{slug or 'candidate'}"


def _harness_strategy(
    packet: WindowsReviewPacket,
    plan: WindowsVmValidationPlan | None,
) -> list[str]:
    strategy: list[str] = []
    if plan is not None:
        strategy.extend(plan.harness_strategy)
    if packet.component_profile is not None and packet.component_profile.harness_strategy:
        strategy.append(packet.component_profile.harness_strategy)
    strategy.extend(
        step
        for step in packet.next_validation
        if any(token in step.lower() for token in ("harness", "ioctl", "alpc", "rpc", "vm"))
    )
    return _dedupe(strategy)


def _preconditions(
    packet: WindowsReviewPacket,
    plan: WindowsVmValidationPlan | None,
    mapping: WindowsCandidateSnapshotMapping | None,
) -> list[str]:
    values = [
        f"Confirm candidate id {packet.candidate_id}.",
        f"Verify {packet.binary} build identity before running the harness.",
        f"Exercise entrypoint {packet.entrypoint} and inspect sink {packet.sink_symbol}.",
    ]
    if plan is not None:
        values.extend(
            [
                f"Restore snapshot {plan.snapshot_name}.",
                f"Confirm QMP {plan.qmp_endpoint} and RDP {plan.rdp_endpoint}.",
                f"Confirm KDNET UDP port {plan.kdnet_port}: {plan.kdnet_status}.",
            ]
        )
    if mapping is not None:
        values.append(
            f"Review snapshot mapping confidence {mapping.mapping_confidence} before execution."
        )
    return _dedupe(values)


def _stock_steps(
    packet: WindowsReviewPacket,
    plan: WindowsVmValidationPlan | None,
) -> list[str]:
    if plan is not None and plan.stock_current_comparison:
        return [f"Stock: {step}" for step in plan.stock_current_comparison]
    return [
        f"Stock: run the {packet.binary} harness once on the baseline snapshot.",
        "Stock: save stdout, stderr, serial log, debugger transcript, and binary identity.",
    ]


def _current_steps(
    packet: WindowsReviewPacket,
    plan: WindowsVmValidationPlan | None,
) -> list[str]:
    steps = [
        f"Current: run the same harness against {packet.binary} with unchanged inputs.",
        "Current: save stdout, stderr, serial log, debugger transcript, and binary identity.",
        "Current: compare crash, status code, side effect, and artifact deltas against stock.",
    ]
    if plan is not None:
        steps.insert(0, f"Current: restore snapshot {plan.snapshot_name} before rerun.")
    return steps


def _artifact_requirements(plan: WindowsVmValidationPlan | None) -> list[str]:
    artifacts = [
        "kdnet attach transcript with timestamp",
        "harness stdout and stderr",
        "exact binary identity and PDB identity transcript",
        "stock/current comparison notes",
    ]
    if plan is not None:
        artifacts.extend(plan.expected_artifacts)
    return _dedupe(artifacts)


def _skeleton_commands(
    packet: WindowsReviewPacket,
    plan: WindowsVmValidationPlan | None,
) -> list[str]:
    commands = [
        "$ErrorActionPreference = 'Stop'",
        f"$CandidateId = '{packet.candidate_id}'",
        f"$Binary = '{packet.binary}'",
        f"$Entrypoint = '{packet.entrypoint}'",
        f"$Sink = '{packet.sink_symbol}'",
        "Write-Host \"TODO: verify binary and PDB identity\"",
        "Write-Host \"TODO: run component-specific trigger\"",
        "Write-Host \"TODO: copy KDNET transcript, serial log, stdout, stderr, and dumps\"",
        "Write-Host \"TODO: compute SHA256 for every required artifact\"",
    ]
    if plan is not None:
        commands.insert(5, f"$Snapshot = '{plan.snapshot_name}'")
        commands.insert(6, f"$KdnetPort = {plan.kdnet_port}")
    return commands


def _blockers(
    strategy: list[str],
    plan: WindowsVmValidationPlan | None,
    mapping: WindowsCandidateSnapshotMapping | None,
    artifacts: list[str],
) -> list[str]:
    blockers: list[str] = []
    if not strategy:
        blockers.append("component harness strategy is missing")
    if plan is None:
        blockers.append("VM validation plan is missing")
    elif plan.blockers:
        blockers.append("VM validation plan has blockers: " + "; ".join(plan.blockers[:6]))
    if mapping is not None:
        if mapping.mapping_blockers:
            blockers.append(
                "candidate snapshot mapping has blockers: "
                + "; ".join(mapping.mapping_blockers[:6])
            )
        if mapping.runtime_blockers:
            blockers.append(
                "candidate snapshot mapping has runtime blockers: "
                + "; ".join(mapping.runtime_blockers[:6])
            )
    if not artifacts:
        blockers.append("runtime artifact requirements are missing")
    return _dedupe(blockers)


def _markdown(
    packet: WindowsReviewPacket,
    *,
    harness_id: str,
    strategy: list[str],
    preconditions: list[str],
    stock_steps: list[str],
    current_steps: list[str],
    artifacts: list[str],
    commands: list[str],
    blockers: list[str],
) -> str:
    lines = [
        f"# Windows Validation Harness Template: {packet.candidate_id}",
        "",
        "Claim level: harness template, not execution or reproduction.",
        "",
        f"- Harness id: {harness_id}",
        f"- Binary: {packet.binary}",
        f"- Entrypoint: {packet.entrypoint}",
        f"- Source: {packet.source_role} / {packet.source_arg or 'unknown'}",
        f"- Sink: {packet.sink_symbol} ({packet.sink_kind})",
        f"- Ready to collect artifacts: {'yes' if not blockers else 'no'}",
        f"- Blockers: {_list_or_none(blockers)}",
        "",
        "## Harness Strategy",
        "",
        *_bullet_lines(strategy),
        "",
        "## Preconditions",
        "",
        *_bullet_lines(preconditions),
        "",
        "## Stock Run",
        "",
        *_numbered_lines(stock_steps),
        "",
        "## Current Run",
        "",
        *_numbered_lines(current_steps),
        "",
        "## Required Artifacts",
        "",
        *_bullet_lines(artifacts),
        "",
        "## PowerShell Skeleton",
        "",
        "```powershell",
        *commands,
        "```",
        "",
    ]
    return "\n".join(lines)


def _write_template_files(
    output_dir: Path,
    template: WindowsValidationHarnessTemplate,
) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    readme = output_dir / "README.md"
    script = output_dir / "run-validation-template.ps1"
    readme.write_text(template.markdown, encoding="utf-8")
    script.write_text("\n".join(template.skeleton_commands).rstrip() + "\n", encoding="utf-8")
    return [str(readme), str(script)]


def _bullet_lines(values: list[str]) -> list[str]:
    if not values:
        return ["- none"]
    return [f"- {value}" for value in values]


def _numbered_lines(values: list[str]) -> list[str]:
    if not values:
        return ["1. none"]
    return [f"{idx}. {value}" for idx, value in enumerate(values, start=1)]


def _list_or_none(values: list[str]) -> str:
    if not values:
        return "none"
    return "; ".join(values[:8])


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out


def build_tool() -> WindowsEmitValidationHarnessTemplateTool:
    return WindowsEmitValidationHarnessTemplateTool()
