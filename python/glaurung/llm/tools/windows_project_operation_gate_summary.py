from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import WindowsReviewPacket
from .windows_project_sink_call_packets import (
    WindowsProjectSinkCallPacketsArgs,
    WindowsProjectSinkCallPacketsTool,
)


class WindowsProjectOperationGateSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary: str = Field(..., description="Binary or driver filename.")
    build: str | None = Field(None, description="Windows build or corpus label.")
    attacker_class: str = Field(
        "unknown",
        description="Attacker class to attach to internal review packets.",
    )
    source_role: str = Field(
        "unknown",
        description="Source role to attach before source-specific rules refine packets.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    binary_id: int | None = Field(None, description="Optional project binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter sink callsites.",
    )
    call_symbol: str | None = Field(
        None,
        description="Optional sink/callee symbol filter, e.g. RtlCopyMemory.",
    )
    sink_kind: str | None = Field(
        None,
        description="Optional ASB sink kind filter, e.g. copy, free, completion.",
    )
    max_packets: int = Field(
        256,
        ge=0,
        le=4096,
        description="Maximum sink-call packets to scan before aggregation.",
    )
    max_groups: int = Field(
        128,
        ge=0,
        le=2048,
        description="Maximum operation gate summary groups to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-gate-summary evidence node.",
    )


class WindowsProjectOperationGateSample(BaseModel):
    candidate_id: str
    sink_symbol: str
    gate_status: str
    proven_gates: list[str] = Field(default_factory=list)
    missing_required_gates: list[str] = Field(default_factory=list)


class WindowsProjectOperationGateGroup(BaseModel):
    sink_kind: str
    sink_symbol: str
    packet_count: int
    fully_proven_packet_count: int
    partially_proven_packet_count: int
    unproven_packet_count: int
    gate_status_counts: dict[str, int] = Field(default_factory=dict)
    required_gates: list[str] = Field(default_factory=list)
    proven_gates: list[str] = Field(default_factory=list)
    missing_required_gates: list[str] = Field(default_factory=list)
    sample_packets: list[WindowsProjectOperationGateSample] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectOperationGateSummaryResult(BaseModel):
    project_path: str
    packet_count: int
    operation_gate_group_count: int
    gate_refinement_count: int
    gate_missing_required_count: int
    groups: list[WindowsProjectOperationGateGroup]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOperationGateSummaryTool(
    MemoryTool[
        WindowsProjectOperationGateSummaryArgs,
        WindowsProjectOperationGateSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_operation_gate_summary",
                description=(
                    "Aggregate project sink-call packets by sink operation and "
                    "summarize required gate coverage."
                ),
                tags=("windows", "pe", "project", "sinks", "gates", "summary"),
            ),
            WindowsProjectOperationGateSummaryArgs,
            WindowsProjectOperationGateSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOperationGateSummaryArgs,
    ) -> WindowsProjectOperationGateSummaryResult:
        project_path = Path(args.project_path)
        packet_tool = WindowsProjectSinkCallPacketsTool()
        packets = packet_tool.run(
            ctx,
            kb,
            WindowsProjectSinkCallPacketsArgs(
                project_path=args.project_path,
                binary=args.binary,
                build=args.build,
                attacker_class=args.attacker_class,
                source_role=args.source_role,
                binary_id=args.binary_id,
                function_va=args.function_va,
                call_symbol=args.call_symbol,
                sink_kind=args.sink_kind,
                sinks_path=args.sinks_path,
                gates_path=args.gates_path,
                refine_gates=True,
                max_packets=args.max_packets,
                add_to_kb=False,
            ),
        )

        groups = _groups(packets.packets, args.max_groups)
        coverage = _coverage(groups)
        missing = _missing_capabilities(groups)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_operation_gate_summary",
                    props={
                        "project_path": str(project_path),
                        "packet_count": packets.packet_count,
                        "operation_gate_group_count": len(groups),
                        "gate_refinement_count": packets.gate_refinement_count,
                        "gate_missing_required_count": packets.gate_missing_required_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOperationGateSummaryResult(
            project_path=str(project_path),
            packet_count=packets.packet_count,
            operation_gate_group_count=len(groups),
            gate_refinement_count=packets.gate_refinement_count,
            gate_missing_required_count=packets.gate_missing_required_count,
            groups=groups,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "operation gate summaries aggregate static packet gate coverage; "
                "they do not prove source reachability or argument value flow"
            ],
        )


def _groups(
    packets: list[WindowsReviewPacket],
    max_groups: int,
) -> list[WindowsProjectOperationGateGroup]:
    grouped: dict[tuple[str, str], list[WindowsReviewPacket]] = defaultdict(list)
    for packet in packets:
        grouped[(packet.sink_kind, packet.sink_symbol)].append(packet)

    out: list[WindowsProjectOperationGateGroup] = []
    for (sink_kind, sink_symbol), group_packets in grouped.items():
        out.append(
            WindowsProjectOperationGateGroup(
                sink_kind=sink_kind,
                sink_symbol=sink_symbol,
                packet_count=len(group_packets),
                fully_proven_packet_count=sum(
                    1
                    for packet in group_packets
                    if packet.required_gates and not packet.missing_required_gates
                ),
                partially_proven_packet_count=sum(
                    1
                    for packet in group_packets
                    if packet.proven_gates and packet.missing_required_gates
                ),
                unproven_packet_count=sum(
                    1
                    for packet in group_packets
                    if packet.required_gates and not packet.proven_gates
                ),
                gate_status_counts=dict(
                    sorted(Counter(packet.gate_status for packet in group_packets).items())
                ),
                required_gates=_uniq(
                    gate for packet in group_packets for gate in packet.required_gates
                ),
                proven_gates=_uniq(
                    gate for packet in group_packets for gate in packet.proven_gates
                ),
                missing_required_gates=_uniq(
                    gate
                    for packet in group_packets
                    for gate in packet.missing_required_gates
                ),
                sample_packets=[
                    WindowsProjectOperationGateSample(
                        candidate_id=packet.candidate_id,
                        sink_symbol=packet.sink_symbol,
                        gate_status=packet.gate_status,
                        proven_gates=packet.proven_gates,
                        missing_required_gates=packet.missing_required_gates,
                    )
                    for packet in group_packets[:5]
                ],
                confidence=_confidence(group_packets),
                provenance=[
                    "windows_project_sink_call_packets",
                    "windows_project_callsite_facts",
                    "windows_cfg_dominance",
                    "asb_pe_gate_metadata",
                    "asb_pe_sink_metadata",
                    "project_operation_gate_summary",
                ],
            )
        )
        if len(out) >= max_groups:
            break
    return out


def _coverage(groups: list[WindowsProjectOperationGateGroup]) -> list[str]:
    coverage = []
    if groups:
        coverage.extend(
            [
                "project_operation_gate_summary",
                "operation_gate_status_counts",
                "operation_missing_required_gate_summary",
            ]
        )
        if any(group.proven_gates for group in groups):
            coverage.append("operation_proven_gate_summary")
    return coverage


def _missing_capabilities(groups: list[WindowsProjectOperationGateGroup]) -> list[str]:
    missing = []
    if not groups:
        missing.append("project_operation_gate_summary")
    missing.extend(
        [
            "source_reachability",
            "argument_value_flow",
            "path_sensitive_gate_conditions",
        ]
    )
    return missing


def _confidence(packets: list[WindowsReviewPacket]) -> float:
    if not packets:
        return 0.0
    if all(packet.gate_status == "dominated" for packet in packets):
        return 0.84
    if any(packet.proven_gates for packet in packets):
        return 0.68
    return 0.48


def _uniq(values) -> list[str]:
    out = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def build_tool() -> WindowsProjectOperationGateSummaryTool:
    return WindowsProjectOperationGateSummaryTool()
