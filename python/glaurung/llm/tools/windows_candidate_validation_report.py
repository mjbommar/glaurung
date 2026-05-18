from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_rank_candidate_packets import RankedWindowsCandidate
from .windows_record_validation_artifact_bundle import WindowsValidationArtifactBundle


class WindowsCandidateValidationReportArgs(BaseModel):
    ranked_candidates: list[RankedWindowsCandidate] = Field(
        ...,
        description="Ranked candidates emitted by windows_rank_candidate_packets.",
    )
    title: str = Field(
        "Windows Candidate Validation Report",
        description="Markdown report title.",
    )
    max_candidates: int = Field(
        10,
        ge=1,
        le=50,
        description="Maximum ranked candidates to include.",
    )
    artifact_bundles: list[WindowsValidationArtifactBundle] = Field(
        default_factory=list,
        description=(
            "Optional runtime artifact bundles emitted by "
            "windows_record_validation_artifact_bundle and joined by candidate_id."
        ),
    )
    markdown_path: str | None = Field(
        None,
        description="Optional path to write the markdown report.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add the report as a KB evidence node.",
    )


class WindowsCandidateValidationReportResult(BaseModel):
    markdown: str
    candidate_count: int
    validation_ready_count: int
    blocked_count: int
    markdown_path: str | None = None
    report_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsCandidateValidationReportTool(
    MemoryTool[
        WindowsCandidateValidationReportArgs,
        WindowsCandidateValidationReportResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_candidate_validation_report",
                description=(
                    "Render ranked Windows candidates and VM validation-plan "
                    "readiness into an operator-facing markdown report. This "
                    "does not execute validation or claim reproduction."
                ),
                tags=("windows", "pe", "candidate", "validation", "report"),
            ),
            WindowsCandidateValidationReportArgs,
            WindowsCandidateValidationReportResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsCandidateValidationReportArgs,
    ) -> WindowsCandidateValidationReportResult:
        candidates = args.ranked_candidates[: args.max_candidates]
        bundles = _artifact_bundles_by_candidate(args.artifact_bundles)
        markdown = _render_report(args.title, candidates, bundles)
        result = WindowsCandidateValidationReportResult(
            markdown=markdown,
            candidate_count=len(candidates),
            validation_ready_count=sum(1 for item in candidates if item.validation_ready),
            blocked_count=sum(1 for item in candidates if not item.validation_ready),
            notes=[
                "report is an operator handoff only; runtime artifacts are required before finding promotion"
            ],
        )

        if args.markdown_path:
            path = Path(args.markdown_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(markdown, encoding="utf-8")
            result.markdown_path = str(path)

        if args.add_to_kb:
            _add_report_node(kb, result)
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node and result.report_node_id:
                kb.add_edge(Edge(src=file_node.id, dst=result.report_node_id, kind="has_evidence"))

        return result


def _render_report(
    title: str,
    candidates: list[RankedWindowsCandidate],
    artifact_bundles: dict[str, WindowsValidationArtifactBundle] | None = None,
) -> str:
    artifact_bundles = artifact_bundles or {}
    ready_count = sum(1 for item in candidates if item.validation_ready)
    blocked_count = sum(1 for item in candidates if not item.validation_ready)
    lines = [
        f"# {title}",
        "",
        "Claim level: operator validation handoff, not reproduction.",
        "",
        "## Summary",
        "",
        f"- Candidates: {len(candidates)}",
        f"- Validation-ready: {ready_count}",
        f"- Runtime/static blocked: {blocked_count}",
        "",
    ]
    for item in candidates:
        lines.extend(_render_candidate(item, artifact_bundles.get(item.packet.candidate_id)))
    return "\n".join(lines).rstrip() + "\n"


def _render_candidate(
    item: RankedWindowsCandidate,
    artifact_bundle: WindowsValidationArtifactBundle | None = None,
) -> list[str]:
    packet = item.packet
    status = "ready" if item.validation_ready else "blocked"
    lines = [
        f"## Rank {item.rank}: {packet.candidate_id}",
        "",
        f"- Status: {status}",
        f"- Score: {item.score:.2f}",
        f"- Binary/build: {packet.binary} / {packet.build or 'unknown'}",
        f"- Entrypoint: {packet.entrypoint}",
        f"- Attacker/source: {packet.attacker_class} / {packet.source_role}",
        f"- Sink: {packet.sink_symbol} ({packet.sink_kind})",
        f"- Gate status: {packet.gate_status}",
        f"- Required gates: {_list_or_none(packet.required_gates)}",
        f"- Proven gates: {_list_or_none(packet.proven_gates)}",
        f"- Missing required gates: {_list_or_none(packet.missing_required_gates)}",
        f"- Promotion blockers: {_list_or_none(packet.promotion_blockers)}",
        f"- Ranking reasons: {_list_or_none(item.reasons)}",
    ]
    if item.validation_plan is not None:
        plan = item.validation_plan
        lines.extend(
            [
                f"- Validation substrate: {plan.validation_id}",
                f"- Snapshot: {plan.snapshot_name}",
                f"- QMP/RDP: {plan.qmp_endpoint} / {plan.rdp_endpoint}",
                f"- KDNET: port {plan.kdnet_port}, {plan.kdnet_status}",
                f"- KDNET attach proof: {plan.kdnet_attach_proof or 'none'}",
                f"- Validation blockers: {_list_or_none(item.validation_blockers)}",
                f"- Expected artifacts: {_list_or_none(plan.expected_artifacts)}",
                f"- Operator steps: {_list_or_none(plan.operator_steps)}",
            ]
        )
    else:
        lines.append("- Validation substrate: none attached")
    if artifact_bundle is not None:
        bundle_status = "ready" if artifact_bundle.ready_for_review else "blocked"
        lines.extend(
            [
                f"- Runtime artifacts: {bundle_status}",
                f"- Runtime execution: {artifact_bundle.execution_status}",
                f"- Runtime artifact count: {artifact_bundle.artifact_count}",
                f"- Missing runtime artifacts: {_list_or_none(artifact_bundle.missing_required_artifacts)}",
                f"- Runtime artifact blockers: {_list_or_none(artifact_bundle.runtime_blockers)}",
                f"- Runtime artifact summaries: {_artifact_summaries(artifact_bundle)}",
            ]
        )
    else:
        lines.append("- Runtime artifacts: none attached")
    lines.append("")
    return lines


def _list_or_none(values: list[str]) -> str:
    if not values:
        return "none"
    return "; ".join(values[:8])


def _artifact_summaries(bundle: WindowsValidationArtifactBundle) -> str:
    values = []
    for artifact in bundle.artifacts[:8]:
        digest = artifact.sha256[:12] if artifact.sha256 else "no-hash"
        values.append(f"{artifact.kind}:{digest}:{artifact.path}")
    return _list_or_none(values)


def _artifact_bundles_by_candidate(
    bundles: list[WindowsValidationArtifactBundle],
) -> dict[str, WindowsValidationArtifactBundle]:
    out: dict[str, WindowsValidationArtifactBundle] = {}
    for bundle in bundles:
        out.setdefault(bundle.candidate_id, bundle)
    return out


def _add_report_node(
    kb: KnowledgeBase,
    result: WindowsCandidateValidationReportResult,
) -> None:
    digest = hashlib.sha256(result.markdown.encode("utf-8")).hexdigest()[:16]
    node = Node(
        kind=NodeKind.evidence,
        label=f"windows candidate validation report {digest}",
        text=result.markdown,
        props={
            "tool": "windows_candidate_validation_report",
            "windows_candidate_validation_report_id": digest,
            **json.loads(
                result.model_dump_json(exclude={"markdown", "report_node_id"})
            ),
        },
        tags=["windows", "candidate", "validation", "report"],
    )
    kb.add_node(node)
    result.report_node_id = node.id


def build_tool() -> WindowsCandidateValidationReportTool:
    return WindowsCandidateValidationReportTool()
