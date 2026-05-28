from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import WindowsReviewPacket
from .windows_emit_vm_validation_plan import (
    WindowsValidationSubstrate,
    WindowsVmValidationPlan,
    _load_inventory,
)
from .windows_record_validation_artifact_bundle import WindowsValidationArtifactBundle
from .windows_surface_metadata import _resolve_metadata_path


class WindowsRecordCandidateSnapshotMappingArgs(BaseModel):
    candidate_packet: WindowsReviewPacket = Field(
        ...,
        description="Static candidate packet to map onto a validation snapshot.",
    )
    validation_plan: WindowsVmValidationPlan = Field(
        ...,
        description="VM validation plan selected for the candidate.",
    )
    artifact_bundle: WindowsValidationArtifactBundle | None = Field(
        None,
        description="Optional runtime artifact bundle collected against the plan.",
    )
    validation_inventory_path: str | None = Field(
        None,
        description=(
            "Optional ASB data/kg/pe-validation-inventory.yaml path used to "
            "cross-check the plan's validation_id and build number."
        ),
    )
    require_artifact_bundle: bool = Field(
        False,
        description="If true, a ready artifact bundle is required for mapping readiness.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add the candidate/snapshot mapping as a KB evidence node.",
    )


class WindowsCandidateSnapshotMapping(BaseModel):
    candidate_id: str
    claim_level: str = "candidate_snapshot_mapping_not_reproduction"
    binary: str
    candidate_build: str | None = None
    candidate_build_label: str | None = None
    validation_id: str
    validation_build_label: str
    validation_build_number: str | None = None
    snapshot_name: str
    image_path: str
    ovmf_vars_path: str
    qmp_endpoint: str
    rdp_endpoint: str
    kdnet_port: int
    mapping_confidence: str
    mapping_evidence: list[str] = Field(default_factory=list)
    mapping_blockers: list[str] = Field(default_factory=list)
    runtime_blockers: list[str] = Field(default_factory=list)
    ready_for_runtime_validation: bool


class WindowsRecordCandidateSnapshotMappingResult(BaseModel):
    mapping: WindowsCandidateSnapshotMapping
    inventory_path: str | None = None
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsRecordCandidateSnapshotMappingTool(
    MemoryTool[
        WindowsRecordCandidateSnapshotMappingArgs,
        WindowsRecordCandidateSnapshotMappingResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_record_candidate_snapshot_mapping",
                description=(
                    "Record why a Windows candidate maps to a specific VM "
                    "validation snapshot. This checks candidate id, binary, "
                    "build label, optional inventory build number, and optional "
                    "runtime artifact bundle readiness without claiming reproduction."
                ),
                tags=("windows", "pe", "validation", "snapshot", "candidate"),
            ),
            WindowsRecordCandidateSnapshotMappingArgs,
            WindowsRecordCandidateSnapshotMappingResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRecordCandidateSnapshotMappingArgs,
    ) -> WindowsRecordCandidateSnapshotMappingResult:
        inventory_path, substrate = _load_optional_substrate(
            args.validation_inventory_path,
            args.validation_plan.validation_id,
        )
        mapping = _build_mapping(args, substrate)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_record_candidate_snapshot_mapping",
                    props={
                        "candidate_id": mapping.candidate_id,
                        "validation_id": mapping.validation_id,
                        "snapshot_name": mapping.snapshot_name,
                        "ready_for_runtime_validation": mapping.ready_for_runtime_validation,
                        "mapping_confidence": mapping.mapping_confidence,
                        "mapping_blocker_count": len(mapping.mapping_blockers),
                        "runtime_blocker_count": len(mapping.runtime_blockers),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsRecordCandidateSnapshotMappingResult(
            mapping=mapping,
            inventory_path=str(inventory_path) if inventory_path is not None else None,
            evidence_node_id=evidence_node_id,
            notes=[
                "snapshot mapping only; execute validation and review artifacts before finding promotion"
            ],
        )


def _load_optional_substrate(
    validation_inventory_path: str | None,
    validation_id: str,
) -> tuple[Path | None, WindowsValidationSubstrate | None]:
    if not validation_inventory_path:
        return None, None
    path = _resolve_metadata_path(
        validation_inventory_path,
        "data/kg/pe-validation-inventory.yaml",
    )
    for substrate in _load_inventory(path):
        if substrate.id == validation_id:
            return path, substrate
    return path, None


def _build_mapping(
    args: WindowsRecordCandidateSnapshotMappingArgs,
    substrate: WindowsValidationSubstrate | None,
) -> WindowsCandidateSnapshotMapping:
    packet = args.candidate_packet
    plan = args.validation_plan
    artifact_bundle = args.artifact_bundle
    candidate_build_label = _packet_build_label(packet)
    evidence: list[str] = []
    blockers: list[str] = []
    runtime_blockers: list[str] = list(plan.blockers)

    if packet.candidate_id == plan.candidate_id:
        evidence.append("candidate_id matches validation plan")
    else:
        blockers.append(
            f"candidate_id mismatch: packet={packet.candidate_id} plan={plan.candidate_id}"
        )

    if _casefold(packet.binary) == _casefold(plan.binary):
        evidence.append("binary name matches validation plan")
    else:
        blockers.append(f"binary mismatch: packet={packet.binary} plan={plan.binary}")

    if candidate_build_label and candidate_build_label == plan.build_label:
        evidence.append(f"candidate build label matches snapshot: {candidate_build_label}")
    elif candidate_build_label:
        blockers.append(
            "candidate build label mismatch: "
            f"packet={candidate_build_label} plan={plan.build_label}"
        )
    else:
        blockers.append("candidate packet lacks project or Ghidra build_label")

    if substrate is not None:
        evidence.append(f"validation inventory contains substrate {substrate.id}")
        if substrate.build_label == plan.build_label:
            evidence.append("inventory build_label matches validation plan")
        else:
            blockers.append(
                "inventory build_label mismatch: "
                f"inventory={substrate.build_label} plan={plan.build_label}"
            )
        if packet.build and substrate.build_number and substrate.build_number in packet.build:
            evidence.append(f"candidate build contains inventory build number {substrate.build_number}")
        elif substrate.build_number:
            blockers.append(
                "candidate build does not contain inventory build number "
                f"{substrate.build_number}"
            )
    elif args.validation_inventory_path:
        blockers.append(f"validation inventory lacks substrate {plan.validation_id}")

    if plan.snapshot_name:
        evidence.append(f"snapshot selected: {plan.snapshot_name}")
    else:
        blockers.append("validation plan lacks snapshot_name")
    if plan.image_path and plan.ovmf_vars_path:
        evidence.append("validation image and OVMF paths are present")
    else:
        blockers.append("validation image or OVMF path is missing")

    if artifact_bundle is not None:
        if artifact_bundle.candidate_id == packet.candidate_id:
            evidence.append("artifact bundle candidate_id matches candidate")
        else:
            blockers.append(
                "artifact bundle candidate_id mismatch: "
                f"bundle={artifact_bundle.candidate_id} packet={packet.candidate_id}"
            )
        if artifact_bundle.validation_id == plan.validation_id:
            evidence.append("artifact bundle validation_id matches validation plan")
        else:
            blockers.append(
                "artifact bundle validation_id mismatch: "
                f"bundle={artifact_bundle.validation_id} plan={plan.validation_id}"
            )
        if artifact_bundle.ready_for_review:
            evidence.append("artifact bundle is ready for review")
        else:
            runtime_blockers.extend(artifact_bundle.runtime_blockers)
            blockers.append("artifact bundle is not ready for review")
    elif args.require_artifact_bundle:
        blockers.append("ready artifact bundle is required but none was supplied")

    blockers = _dedupe(blockers)
    runtime_blockers = _dedupe(runtime_blockers)
    confidence = _confidence(evidence, blockers, runtime_blockers)
    return WindowsCandidateSnapshotMapping(
        candidate_id=packet.candidate_id,
        binary=packet.binary,
        candidate_build=packet.build,
        candidate_build_label=candidate_build_label,
        validation_id=plan.validation_id,
        validation_build_label=plan.build_label,
        validation_build_number=substrate.build_number if substrate is not None else None,
        snapshot_name=plan.snapshot_name,
        image_path=plan.image_path,
        ovmf_vars_path=plan.ovmf_vars_path,
        qmp_endpoint=plan.qmp_endpoint,
        rdp_endpoint=plan.rdp_endpoint,
        kdnet_port=plan.kdnet_port,
        mapping_confidence=confidence,
        mapping_evidence=evidence,
        mapping_blockers=blockers,
        runtime_blockers=runtime_blockers,
        ready_for_runtime_validation=not blockers and not runtime_blockers,
    )


def _packet_build_label(packet: WindowsReviewPacket) -> str | None:
    if packet.project_facts is not None and packet.project_facts.build_label:
        return packet.project_facts.build_label
    if packet.ghidra_delta is not None and packet.ghidra_delta.build_label:
        return packet.ghidra_delta.build_label
    return None


def _confidence(
    evidence: list[str],
    blockers: list[str],
    runtime_blockers: list[str],
) -> str:
    if blockers:
        return "blocked"
    if runtime_blockers:
        return "mapped_static_runtime_blocked"
    if len(evidence) >= 7:
        return "high"
    return "medium"


def _casefold(value: str | None) -> str:
    return (value or "").casefold()


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out


def build_tool() -> WindowsRecordCandidateSnapshotMappingTool:
    return WindowsRecordCandidateSnapshotMappingTool()
