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


class WindowsProjectOperationSourceSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary: str = Field(..., description="Binary or driver filename.")
    binary_path: str | None = Field(
        None,
        description=(
            "Optional PE binary path. When supplied, local call-argument snapshots "
            "can turn inferred source roles into matched source/sink evidence."
        ),
    )
    build: str | None = Field(None, description="Windows build or corpus label.")
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sources_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sources.yaml. Defaults to ASB_REPO or sibling repo.",
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
        description="Maximum operation source summary groups to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-source-summary evidence node.",
    )


class WindowsProjectOperationSourceSample(BaseModel):
    candidate_id: str
    sink_symbol: str
    source_refinement_status: str
    source_role: str
    source_arg: str | None = None
    source_refinement_sources: list[str] = Field(default_factory=list)
    source_refinement_blockers: list[str] = Field(default_factory=list)


class WindowsProjectOperationSourceGroup(BaseModel):
    sink_kind: str
    sink_symbol: str
    packet_count: int
    source_refinement_status_counts: dict[str, int] = Field(default_factory=dict)
    matched_packet_count: int
    inferred_packet_count: int
    missing_packet_count: int
    source_roles: list[str] = Field(default_factory=list)
    source_args: list[str] = Field(default_factory=list)
    source_refinement_blockers: list[str] = Field(default_factory=list)
    sample_packets: list[WindowsProjectOperationSourceSample] = Field(
        default_factory=list
    )
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectOperationSourceSummaryResult(BaseModel):
    project_path: str
    packet_count: int
    operation_source_group_count: int
    source_role_inference_count: int
    source_value_match_count: int
    source_refinement_status_counts: dict[str, int] = Field(default_factory=dict)
    groups: list[WindowsProjectOperationSourceGroup]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOperationSourceSummaryTool(
    MemoryTool[
        WindowsProjectOperationSourceSummaryArgs,
        WindowsProjectOperationSourceSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_operation_source_summary",
                description=(
                    "Aggregate project sink-call packets by sink operation and "
                    "summarize ASB source-role inference and local source/sink "
                    "refinement status."
                ),
                tags=("windows", "pe", "project", "sources", "operations", "summary"),
            ),
            WindowsProjectOperationSourceSummaryArgs,
            WindowsProjectOperationSourceSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOperationSourceSummaryArgs,
    ) -> WindowsProjectOperationSourceSummaryResult:
        project_path = Path(args.project_path)
        packet_tool = WindowsProjectSinkCallPacketsTool()
        packets = packet_tool.run(
            ctx,
            kb,
            WindowsProjectSinkCallPacketsArgs(
                project_path=args.project_path,
                binary_path=args.binary_path,
                binary=args.binary,
                build=args.build,
                attacker_class="unknown",
                source_role="unknown",
                binary_id=args.binary_id,
                function_va=args.function_va,
                call_symbol=args.call_symbol,
                sink_kind=args.sink_kind,
                sinks_path=args.sinks_path,
                sources_path=args.sources_path,
                infer_source_roles=True,
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
                    label="windows_project_operation_source_summary",
                    props={
                        "project_path": str(project_path),
                        "packet_count": packets.packet_count,
                        "operation_source_group_count": len(groups),
                        "source_role_inference_count": packets.source_role_inference_count,
                        "source_value_match_count": packets.source_value_match_count,
                        "source_refinement_status_counts": (
                            packets.source_refinement_status_counts
                        ),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOperationSourceSummaryResult(
            project_path=str(project_path),
            packet_count=packets.packet_count,
            operation_source_group_count=len(groups),
            source_role_inference_count=packets.source_role_inference_count,
            source_value_match_count=packets.source_value_match_count,
            source_refinement_status_counts=packets.source_refinement_status_counts,
            groups=groups,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "operation source summaries aggregate ASB source metadata and local "
                "source/sink refinement status; they do not prove end-to-end "
                "attacker reachability or path-sensitive value flow"
            ],
        )


def _groups(
    packets: list[WindowsReviewPacket],
    max_groups: int,
) -> list[WindowsProjectOperationSourceGroup]:
    grouped: dict[tuple[str, str], list[WindowsReviewPacket]] = defaultdict(list)
    for packet in packets:
        grouped[(packet.sink_kind, packet.sink_symbol)].append(packet)

    out: list[WindowsProjectOperationSourceGroup] = []
    for (sink_kind, sink_symbol), group_packets in grouped.items():
        status_counts = Counter(
            packet.source_refinement_status for packet in group_packets
        )
        out.append(
            WindowsProjectOperationSourceGroup(
                sink_kind=sink_kind,
                sink_symbol=sink_symbol,
                packet_count=len(group_packets),
                source_refinement_status_counts=dict(sorted(status_counts.items())),
                matched_packet_count=status_counts.get("matched", 0),
                inferred_packet_count=status_counts.get("inferred", 0),
                missing_packet_count=status_counts.get("missing", 0),
                source_roles=_source_roles(group_packets),
                source_args=_source_args(group_packets),
                source_refinement_blockers=_uniq(
                    blocker
                    for packet in group_packets
                    for blocker in packet.source_refinement_blockers
                ),
                sample_packets=[
                    WindowsProjectOperationSourceSample(
                        candidate_id=packet.candidate_id,
                        sink_symbol=packet.sink_symbol,
                        source_refinement_status=packet.source_refinement_status,
                        source_role=packet.source_role,
                        source_arg=packet.source_arg,
                        source_refinement_sources=packet.source_refinement_sources,
                        source_refinement_blockers=packet.source_refinement_blockers,
                    )
                    for packet in group_packets[:5]
                ],
                confidence=_confidence(group_packets),
                provenance=[
                    "windows_project_sink_call_packets",
                    "windows_function_arg_roles",
                    "asb_pe_source_metadata",
                    "windows_project_call_argument_snapshot",
                    "project_operation_source_summary",
                ],
            )
        )
        if len(out) >= max_groups:
            break
    return out


def _coverage(groups: list[WindowsProjectOperationSourceGroup]) -> list[str]:
    coverage = []
    if groups:
        coverage.extend(
            [
                "project_operation_source_summary",
                "operation_source_refinement_status_counts",
            ]
        )
        if any(group.inferred_packet_count for group in groups):
            coverage.append("operation_source_role_inference_summary")
        if any(group.matched_packet_count for group in groups):
            coverage.append("operation_source_value_match_summary")
    return coverage


def _missing_capabilities(
    groups: list[WindowsProjectOperationSourceGroup],
) -> list[str]:
    missing = []
    if not groups:
        missing.append("project_operation_source_summary")
    if not any(group.matched_packet_count for group in groups):
        missing.append("operation_source_value_match_summary")
    missing.extend(
        [
            "end_to_end_source_reachability",
            "path_sensitive_argument_values",
            "interprocedural_source_propagation",
        ]
    )
    return list(dict.fromkeys(missing))


def _source_roles(packets: list[WindowsReviewPacket]) -> list[str]:
    values = []
    for packet in packets:
        if packet.source_role and packet.source_role != "unknown":
            values.append(packet.source_role)
        for source in packet.source_refinement_sources:
            parts = source.split(":")
            if len(parts) >= 3 and parts[1]:
                values.append(parts[1])
            if source.startswith("source_role="):
                values.append(source.split("=", 1)[1])
    return _uniq(values)


def _source_args(packets: list[WindowsReviewPacket]) -> list[str]:
    values = []
    for packet in packets:
        if packet.source_arg:
            values.append(packet.source_arg)
        for source in packet.source_refinement_sources:
            if source.startswith("source_arg="):
                values.append(source.split("=", 1)[1])
            elif source.count(":") >= 2:
                values.append(source.split(":", 1)[0])
    return _uniq(values)


def _confidence(packets: list[WindowsReviewPacket]) -> float:
    if not packets:
        return 0.0
    statuses = {packet.source_refinement_status for packet in packets}
    if statuses == {"matched"}:
        return 0.82
    if "matched" in statuses:
        return 0.68
    if "inferred" in statuses:
        return 0.54
    return 0.36


def _uniq(values) -> list[str]:
    out = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def build_tool() -> WindowsProjectOperationSourceSummaryTool:
    return WindowsProjectOperationSourceSummaryTool()
