from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import WindowsReviewPacket
from .windows_surface_metadata import _resolve_metadata_path


class WindowsEmitVmValidationPlanArgs(BaseModel):
    candidate_packet: WindowsReviewPacket = Field(
        ...,
        description="Static Windows review packet to convert into a VM validation plan.",
    )
    validation_inventory_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-validation-inventory.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    validation_id: str | None = Field(
        None,
        description="Optional explicit validation substrate id.",
    )
    build_label: str | None = Field(
        None,
        description="Optional build label used to select a validation substrate.",
    )
    require_kdnet_attach: bool = Field(
        True,
        description="If true, unvalidated KDNET attach is a plan blocker.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact VM validation-plan node to the KB.",
    )


class WindowsValidationSubstrate(BaseModel):
    id: str
    build_label: str
    build_number: str
    architecture: str
    sku: str
    snapshot_name: str
    baseline_kind: str
    image_path: str
    ovmf_vars_path: str
    qmp_endpoint: str
    rdp_endpoint: str
    kdnet_port: int
    kdnet_status: str
    debugger_status: str
    kdnet_attach_proof: str | None = None
    kdnet_last_attach_utc: str | None = None
    boot_script: str
    expected_artifacts: list[str] = Field(default_factory=list)
    stock_current_comparison: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsVmValidationPlan(BaseModel):
    candidate_id: str
    claim_level: str = "validation_plan_not_reproduction"
    binary: str
    build: str | None
    validation_id: str
    build_label: str
    snapshot_name: str
    image_path: str
    ovmf_vars_path: str
    qmp_endpoint: str
    rdp_endpoint: str
    kdnet_port: int
    kdnet_status: str
    debugger_status: str
    kdnet_attach_proof: str | None = None
    kdnet_last_attach_utc: str | None = None
    harness_strategy: list[str] = Field(default_factory=list)
    validation_requirements: list[str] = Field(default_factory=list)
    expected_artifacts: list[str] = Field(default_factory=list)
    stock_current_comparison: list[str] = Field(default_factory=list)
    operator_steps: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    ready_for_validation: bool
    notes: list[str] = Field(default_factory=list)


class WindowsEmitVmValidationPlanResult(BaseModel):
    inventory_path: str
    selected_by: str
    plan: WindowsVmValidationPlan
    evidence_node_id: str | None = None


class WindowsEmitVmValidationPlanTool(
    MemoryTool[WindowsEmitVmValidationPlanArgs, WindowsEmitVmValidationPlanResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_emit_vm_validation_plan",
                description=(
                    "Convert a static Windows candidate packet into a concrete "
                    "VM/snapshot/KDNET/harness validation plan. This does not "
                    "claim reproduction."
                ),
                tags=("windows", "pe", "validation", "vm", "candidate"),
            ),
            WindowsEmitVmValidationPlanArgs,
            WindowsEmitVmValidationPlanResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsEmitVmValidationPlanArgs,
    ) -> WindowsEmitVmValidationPlanResult:
        inventory_path = _resolve_metadata_path(
            args.validation_inventory_path,
            "data/kg/pe-validation-inventory.yaml",
        )
        substrates = _load_inventory(inventory_path)
        selected, selected_by, selection_blocker = _select_substrate(args, substrates)
        plan = _plan_from_packet(
            args.candidate_packet,
            selected,
            require_kdnet_attach=args.require_kdnet_attach,
            selection_blocker=selection_blocker,
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_emit_vm_validation_plan",
                    props={
                        "candidate_id": plan.candidate_id,
                        "validation_id": plan.validation_id,
                        "ready_for_validation": plan.ready_for_validation,
                        "blocker_count": len(plan.blockers),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsEmitVmValidationPlanResult(
            inventory_path=str(inventory_path),
            selected_by=selected_by,
            plan=plan,
            evidence_node_id=evidence_node_id,
        )


def _load_inventory(path: Path) -> list[WindowsValidationSubstrate]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[WindowsValidationSubstrate] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: validation inventory entry {idx} is not a mapping")
        out.append(WindowsValidationSubstrate(**entry))
    if not out:
        raise ValueError(f"{path}: validation inventory is empty")
    return out


def _select_substrate(
    args: WindowsEmitVmValidationPlanArgs,
    substrates: list[WindowsValidationSubstrate],
) -> tuple[WindowsValidationSubstrate, str, str | None]:
    packet = args.candidate_packet
    if args.validation_id:
        for substrate in substrates:
            if substrate.id == args.validation_id:
                return substrate, "validation_id", None
        return (
            substrates[0],
            "fallback_first_record",
            f"requested validation substrate {args.validation_id!r} was not found",
        )

    build_label = _requested_build_label(args)
    if build_label:
        for substrate in substrates:
            if substrate.build_label == build_label:
                return substrate, "build_label", None

    build = packet.build or ""
    for substrate in substrates:
        if substrate.build_number and substrate.build_number in build:
            return substrate, "build_number", None

    fallback_reason = (
        f"no validation substrate matched build label {build_label!r}"
        if build_label
        else "no build label or build number selected a validation substrate"
    )
    return substrates[0], "fallback_first_record", fallback_reason


def _requested_build_label(args: WindowsEmitVmValidationPlanArgs) -> str | None:
    packet = args.candidate_packet
    if args.build_label:
        return args.build_label
    if packet.project_facts is not None and packet.project_facts.build_label:
        return packet.project_facts.build_label
    if packet.ghidra_delta is not None and packet.ghidra_delta.build_label:
        return packet.ghidra_delta.build_label
    return None


def _plan_from_packet(
    packet: WindowsReviewPacket,
    substrate: WindowsValidationSubstrate,
    *,
    require_kdnet_attach: bool,
    selection_blocker: str | None,
) -> WindowsVmValidationPlan:
    harness_strategy = _harness_strategy(packet)
    validation_requirements = _validation_requirements(packet)
    blockers = _blockers(
        packet,
        substrate,
        require_kdnet_attach=require_kdnet_attach,
        selection_blocker=selection_blocker,
        harness_strategy=harness_strategy,
    )
    return WindowsVmValidationPlan(
        candidate_id=packet.candidate_id,
        binary=packet.binary,
        build=packet.build,
        validation_id=substrate.id,
        build_label=substrate.build_label,
        snapshot_name=substrate.snapshot_name,
        image_path=substrate.image_path,
        ovmf_vars_path=substrate.ovmf_vars_path,
        qmp_endpoint=substrate.qmp_endpoint,
        rdp_endpoint=substrate.rdp_endpoint,
        kdnet_port=substrate.kdnet_port,
        kdnet_status=substrate.kdnet_status,
        debugger_status=substrate.debugger_status,
        kdnet_attach_proof=substrate.kdnet_attach_proof,
        kdnet_last_attach_utc=substrate.kdnet_last_attach_utc,
        harness_strategy=harness_strategy,
        validation_requirements=validation_requirements,
        expected_artifacts=list(substrate.expected_artifacts),
        stock_current_comparison=list(substrate.stock_current_comparison),
        operator_steps=_operator_steps(packet, substrate, harness_strategy),
        blockers=blockers,
        ready_for_validation=not blockers,
        notes=[
            "validation plan only; execute it and capture artifacts before finding promotion",
            *(["substrate note: " + substrate.notes] if substrate.notes else []),
        ],
    )


def _harness_strategy(packet: WindowsReviewPacket) -> list[str]:
    if packet.component_profile is not None and packet.component_profile.harness_strategy:
        return [packet.component_profile.harness_strategy]
    return [
        step
        for step in packet.next_validation
        if any(token in step.lower() for token in ("harness", "vm", "snapshot", "kdnet"))
    ]


def _validation_requirements(packet: WindowsReviewPacket) -> list[str]:
    requirements: list[str] = []
    if packet.component_profile is not None:
        requirements.extend(packet.component_profile.validation_requirements)
    requirements.extend(packet.required_project_facts)
    if packet.required_gates:
        requirements.extend(f"gate:{gate}" for gate in packet.required_gates)
    return _dedupe(requirements)


def _operator_steps(
    packet: WindowsReviewPacket,
    substrate: WindowsValidationSubstrate,
    harness_strategy: list[str],
) -> list[str]:
    steps = [
        f"Prepare mutable VM from {substrate.image_path} and {substrate.ovmf_vars_path}.",
        f"Boot with {substrate.boot_script} and restore snapshot {substrate.snapshot_name}.",
        f"Confirm QMP on {substrate.qmp_endpoint} and RDP on {substrate.rdp_endpoint}.",
        f"Confirm KDNET UDP port {substrate.kdnet_port} status: {substrate.kdnet_status}.",
        "Record KDNET attach proof path or transcript before treating debug as validated.",
        f"Verify binary/PDB identity for {packet.binary} before running the harness.",
    ]
    if harness_strategy:
        steps.append("Run harness strategy: " + "; ".join(harness_strategy))
    else:
        steps.append("Define a component harness before attempting runtime validation.")
    steps.append("Run stock/current comparison and save every expected artifact.")
    return steps


def _blockers(
    packet: WindowsReviewPacket,
    substrate: WindowsValidationSubstrate,
    *,
    require_kdnet_attach: bool,
    selection_blocker: str | None,
    harness_strategy: list[str],
) -> list[str]:
    blockers: list[str] = []
    if selection_blocker:
        blockers.append(selection_blocker)
    if require_kdnet_attach and substrate.kdnet_status != "attach_validated":
        blockers.append(f"KDNET attach is not validated: {substrate.kdnet_status}")
    if substrate.kdnet_status == "guest_configured_host_forward_missing":
        blockers.append("KDNET host UDP forward is missing for the selected boot script")
    if substrate.debugger_status != "attached_once":
        blockers.append(f"debugger attach proof is missing: {substrate.debugger_status}")
    if require_kdnet_attach and not substrate.kdnet_attach_proof:
        blockers.append("KDNET attach proof artifact is missing")
    if not harness_strategy:
        blockers.append("component harness strategy is missing")
    if not packet.promotion_preconditions_met:
        blockers.append(
            "static packet promotion blockers remain: "
            + "; ".join(packet.promotion_blockers or ["unknown"])
        )
    if packet.missing_required_gates:
        blockers.append(
            "required gate semantics still missing: "
            + ", ".join(packet.missing_required_gates)
        )
    return _dedupe(blockers)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out


def build_tool() -> WindowsEmitVmValidationPlanTool:
    return WindowsEmitVmValidationPlanTool()
