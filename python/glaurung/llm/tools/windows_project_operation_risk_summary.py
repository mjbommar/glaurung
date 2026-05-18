from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_project_operation_gate_summary import (
    WindowsProjectOperationGateGroup,
    WindowsProjectOperationGateSummaryArgs,
    WindowsProjectOperationGateSummaryTool,
)
from .windows_project_operation_source_summary import (
    WindowsProjectOperationSourceGroup,
    WindowsProjectOperationSourceSummaryArgs,
    WindowsProjectOperationSourceSummaryTool,
)


class WindowsProjectOperationRiskSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary: str = Field(..., description="Binary or driver filename.")
    binary_path: str | None = Field(
        None,
        description=(
            "Optional PE binary path. When supplied, source summaries can include "
            "local source/sink value matches from call-argument snapshots."
        ),
    )
    build: str | None = Field(None, description="Windows build or corpus label.")
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
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
        64,
        ge=0,
        le=2048,
        description="Maximum ranked operation groups to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-risk-summary evidence node.",
    )


class WindowsProjectOperationRiskGroup(BaseModel):
    rank: int
    score: float
    priority: str
    sink_kind: str
    sink_symbol: str
    packet_count: int
    missing_required_gates: list[str] = Field(default_factory=list)
    proven_gates: list[str] = Field(default_factory=list)
    source_roles: list[str] = Field(default_factory=list)
    source_args: list[str] = Field(default_factory=list)
    source_refinement_status_counts: dict[str, int] = Field(default_factory=dict)
    gate_status_counts: dict[str, int] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectOperationRiskSummaryResult(BaseModel):
    project_path: str
    gate_group_count: int
    source_group_count: int
    ranked_group_count: int
    groups: list[WindowsProjectOperationRiskGroup]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOperationRiskSummaryTool(
    MemoryTool[
        WindowsProjectOperationRiskSummaryArgs,
        WindowsProjectOperationRiskSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_operation_risk_summary",
                description=(
                    "Join operation-level gate and source summaries into ranked "
                    "static triage groups without promoting them to findings."
                ),
                tags=("windows", "pe", "project", "operations", "ranking", "summary"),
            ),
            WindowsProjectOperationRiskSummaryArgs,
            WindowsProjectOperationRiskSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOperationRiskSummaryArgs,
    ) -> WindowsProjectOperationRiskSummaryResult:
        project_path = Path(args.project_path)
        gate_summary = WindowsProjectOperationGateSummaryTool().run(
            ctx,
            kb,
            WindowsProjectOperationGateSummaryArgs(
                project_path=args.project_path,
                binary=args.binary,
                build=args.build,
                sinks_path=args.sinks_path,
                gates_path=args.gates_path,
                binary_id=args.binary_id,
                function_va=args.function_va,
                call_symbol=args.call_symbol,
                sink_kind=args.sink_kind,
                max_packets=args.max_packets,
                max_groups=args.max_groups,
                add_to_kb=False,
            ),
        )
        source_summary = WindowsProjectOperationSourceSummaryTool().run(
            ctx,
            kb,
            WindowsProjectOperationSourceSummaryArgs(
                project_path=args.project_path,
                binary_path=args.binary_path,
                binary=args.binary,
                build=args.build,
                sinks_path=args.sinks_path,
                sources_path=args.sources_path,
                binary_id=args.binary_id,
                function_va=args.function_va,
                call_symbol=args.call_symbol,
                sink_kind=args.sink_kind,
                max_packets=args.max_packets,
                max_groups=args.max_groups,
                add_to_kb=False,
            ),
        )

        groups = _ranked_groups(gate_summary.groups, source_summary.groups)
        groups = groups[: args.max_groups]
        for idx, group in enumerate(groups, start=1):
            group.rank = idx

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_operation_risk_summary",
                    props={
                        "project_path": str(project_path),
                        "gate_group_count": len(gate_summary.groups),
                        "source_group_count": len(source_summary.groups),
                        "ranked_group_count": len(groups),
                        "top_group": (
                            f"{groups[0].sink_kind}:{groups[0].sink_symbol}"
                            if groups
                            else None
                        ),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOperationRiskSummaryResult(
            project_path=str(project_path),
            gate_group_count=len(gate_summary.groups),
            source_group_count=len(source_summary.groups),
            ranked_group_count=len(groups),
            groups=groups,
            coverage=_coverage(groups),
            missing_capabilities=_missing_capabilities(groups),
            evidence_node_id=evidence_node_id,
            notes=[
                "operation risk summaries rank static operation groups for review; "
                "they do not prove end-to-end reachability, exploitability, or "
                "runtime behavior"
            ],
        )


def _ranked_groups(
    gate_groups: list[WindowsProjectOperationGateGroup],
    source_groups: list[WindowsProjectOperationSourceGroup],
) -> list[WindowsProjectOperationRiskGroup]:
    source_by_key = {
        (group.sink_kind, group.sink_symbol): group for group in source_groups
    }
    keys = {
        (group.sink_kind, group.sink_symbol) for group in gate_groups
    } | set(source_by_key)
    gate_by_key = {(group.sink_kind, group.sink_symbol): group for group in gate_groups}

    ranked = [
        _risk_group(key, gate_by_key.get(key), source_by_key.get(key))
        for key in sorted(keys)
    ]
    ranked.sort(key=lambda group: group.score, reverse=True)
    return ranked


def _risk_group(
    key: tuple[str, str],
    gate: WindowsProjectOperationGateGroup | None,
    source: WindowsProjectOperationSourceGroup | None,
) -> WindowsProjectOperationRiskGroup:
    sink_kind, sink_symbol = key
    packet_count = max(gate.packet_count if gate else 0, source.packet_count if source else 0)
    score = 0.0
    reasons: list[str] = []
    blockers: list[str] = []

    if sink_kind in {"copy", "write"}:
        score += 20.0
        reasons.append("memory write/copy operation")
    elif sink_kind in {"free", "refcount", "completion"}:
        score += 16.0
        reasons.append("lifetime or ownership operation")
    elif sink_kind in {"callback", "dispatch"}:
        score += 14.0
        reasons.append("control-transfer operation")
    else:
        score += 8.0
        reasons.append(f"sink kind {sink_kind}")

    if packet_count:
        score += min(12.0, packet_count * 3.0)
        reasons.append(f"{packet_count} packet(s) in operation group")

    if gate:
        if gate.missing_required_gates:
            score += min(20.0, len(gate.missing_required_gates) * 5.0)
            reasons.append("missing required gate semantics")
        if gate.partially_proven_packet_count:
            score += 8.0
            reasons.append("some gate semantics proven but coverage incomplete")
        if gate.unproven_packet_count:
            score += 10.0
            reasons.append("ungated or unproven packets present")
        if gate.fully_proven_packet_count and not gate.missing_required_gates:
            score -= 8.0
            reasons.append("all observed required gate semantics proven")
    else:
        blockers.append("operation gate summary missing")

    if source:
        if source.matched_packet_count:
            score += 18.0
            reasons.append("local source/sink value match present")
        if source.inferred_packet_count:
            score += 8.0
            reasons.append("ASB source metadata inference present")
        if source.missing_packet_count:
            blockers.append("some packets lack source refinement")
    else:
        blockers.append("operation source summary missing")

    blockers.extend(
        [
            "end-to-end attacker reachability not proven",
            "path-sensitive argument value flow not proven",
        ]
    )

    priority = "high" if score >= 55.0 else ("medium" if score >= 32.0 else "low")
    return WindowsProjectOperationRiskGroup(
        rank=0,
        score=round(max(0.0, score), 2),
        priority=priority,
        sink_kind=sink_kind,
        sink_symbol=sink_symbol,
        packet_count=packet_count,
        missing_required_gates=gate.missing_required_gates if gate else [],
        proven_gates=gate.proven_gates if gate else [],
        source_roles=source.source_roles if source else [],
        source_args=source.source_args if source else [],
        source_refinement_status_counts=(
            source.source_refinement_status_counts if source else {}
        ),
        gate_status_counts=gate.gate_status_counts if gate else {},
        reasons=reasons,
        blockers=list(dict.fromkeys(blockers)),
        provenance=[
            "windows_project_operation_gate_summary",
            "windows_project_operation_source_summary",
            "project_operation_risk_summary",
        ],
    )


def _coverage(groups: list[WindowsProjectOperationRiskGroup]) -> list[str]:
    coverage = []
    if groups:
        coverage.extend(
            [
                "project_operation_risk_summary",
                "operation_gate_source_summary_join",
                "operation_review_priority_score",
            ]
        )
    return coverage


def _missing_capabilities(groups: list[WindowsProjectOperationRiskGroup]) -> list[str]:
    missing = []
    if not groups:
        missing.append("project_operation_risk_summary")
    missing.extend(
        [
            "end_to_end_source_reachability",
            "path_sensitive_argument_values",
            "runtime_validation_artifacts",
        ]
    )
    return list(dict.fromkeys(missing))


def build_tool() -> WindowsProjectOperationRiskSummaryTool:
    return WindowsProjectOperationRiskSummaryTool()
