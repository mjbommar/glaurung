from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_cfg_dominance import (
    CfgBlockFact,
    WindowsCfgDominanceArgs,
    WindowsCfgDominanceTool,
)
from .windows_emit_review_packet import GateStatus
from .windows_operation_metadata import OperationRecord
from .windows_surface_metadata import GateRecord, _resolve_metadata_path
from .windows_check_gate_to_sink import (
    _gate_record,
    _gates_by_symbol,
    _load_yaml_list,
    _matches_by_symbol,
    _operation_record,
    _operations_by_symbol,
)


CfgGateSinkStatus = Literal[
    "dominated",
    "not_dominated",
    "same_block",
    "unreachable",
    "unknown",
    "missing_metadata",
]


class WindowsCfgGateToSinkArgs(BaseModel):
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    function_va: int | None = Field(
        None,
        description="Function entry VA. Required when cfg_blocks is omitted.",
    )
    gate_va: int = Field(..., description="VA of the validation gate call or branch.")
    sink_va: int = Field(..., description="VA of the sink call or memory operation.")
    gate_symbol: str = Field(..., description="Gate symbol at gate_va.")
    sink_symbol: str = Field(..., description="Sink symbol at sink_va.")
    gate_kind: str | None = Field(None, description="Optional gate kind filter.")
    sink_kind: str | None = Field(None, description="Optional sink kind filter.")
    cfg_blocks: list[CfgBlockFact] = Field(
        default_factory=list,
        description="Optional explicit CFG blocks; if omitted, native CFG analysis is used.",
    )
    max_functions: int = Field(256, description="Native function discovery cap.")
    max_blocks: int = Field(512, description="Native per-function basic block cap.")
    max_instructions: int = Field(20_000, description="Native instruction cap.")
    timeout_ms: int = Field(1000, description="Native analysis timeout in milliseconds.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact CFG gate-to-sink evidence node to the KB.",
    )


class CfgGateSite(BaseModel):
    symbol: str
    va: int
    gate: GateRecord | None = None


class CfgSinkSite(BaseModel):
    symbol: str
    va: int
    operation: OperationRecord | None = None


class WindowsCfgGateToSinkResult(BaseModel):
    gates_path: str
    sinks_path: str
    gate: CfgGateSite
    sink: CfgSinkSite
    status: CfgGateSinkStatus
    suggested_packet_gate_status: GateStatus
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    dominance_provenance: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsCfgGateToSinkTool(
    MemoryTool[WindowsCfgGateToSinkArgs, WindowsCfgGateToSinkResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_cfg_gate_to_sink",
                description=(
                    "Join ASB gate/sink metadata with CFG dominance between "
                    "concrete gate and sink callsite VAs."
                ),
                tags=("windows", "pe", "cfg", "gates", "sinks"),
            ),
            WindowsCfgGateToSinkArgs,
            WindowsCfgGateToSinkResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsCfgGateToSinkArgs,
    ) -> WindowsCfgGateToSinkResult:
        gates_path = _resolve_metadata_path(args.gates_path, "data/kg/pe-gates.yaml")
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        gate = _select_gate(args, gates_path)
        operation = _select_operation(args, sinks_path)

        if gate is None or operation is None:
            result = _missing_metadata_result(args, gates_path, sinks_path, gate, operation)
        else:
            dominance = WindowsCfgDominanceTool().run(
                ctx,
                kb,
                WindowsCfgDominanceArgs(
                    function_va=args.function_va,
                    gate_va=args.gate_va,
                    sink_va=args.sink_va,
                    cfg_blocks=args.cfg_blocks,
                    max_functions=args.max_functions,
                    max_blocks=args.max_blocks,
                    max_instructions=args.max_instructions,
                    timeout_ms=args.timeout_ms,
                ),
            )
            result = _result_from_dominance(
                args,
                gates_path,
                sinks_path,
                gate,
                operation,
                dominance,
            )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_cfg_gate_to_sink",
                    props={
                        "gate_symbol": args.gate_symbol,
                        "sink_symbol": args.sink_symbol,
                        "gate_va": args.gate_va,
                        "sink_va": args.sink_va,
                        "status": result.status,
                        "suggested_packet_gate_status": result.suggested_packet_gate_status,
                    },
                )
            )
            result.evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return result


def _select_gate(args: WindowsCfgGateToSinkArgs, gates_path) -> GateRecord | None:
    gates = [_gate_record(entry, gates_path) for entry in _load_yaml_list(gates_path)]
    matches = _matches_by_symbol(args.gate_symbol, _gates_by_symbol(gates))
    if args.gate_kind:
        matches = [gate for gate in matches if gate.gate_kind == args.gate_kind]
    return matches[0] if matches else None


def _select_operation(args: WindowsCfgGateToSinkArgs, sinks_path) -> OperationRecord | None:
    operations = [
        _operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)
    ]
    matches = _matches_by_symbol(args.sink_symbol, _operations_by_symbol(operations))
    if args.sink_kind:
        matches = [operation for operation in matches if operation.sink_kind == args.sink_kind]
    return matches[0] if matches else None


def _missing_metadata_result(
    args: WindowsCfgGateToSinkArgs,
    gates_path,
    sinks_path,
    gate: GateRecord | None,
    operation: OperationRecord | None,
) -> WindowsCfgGateToSinkResult:
    missing = []
    if gate is None:
        missing.append(f"gate metadata for {args.gate_symbol}")
    if operation is None:
        missing.append(f"sink metadata for {args.sink_symbol}")
    return WindowsCfgGateToSinkResult(
        gates_path=str(gates_path),
        sinks_path=str(sinks_path),
        gate=CfgGateSite(symbol=args.gate_symbol, va=args.gate_va, gate=gate),
        sink=CfgSinkSite(symbol=args.sink_symbol, va=args.sink_va, operation=operation),
        status="missing_metadata",
        suggested_packet_gate_status="unknown",
        confidence=0.0,
        reason="missing " + ", ".join(missing),
        notes=["metadata-backed gate/sink classification failed"],
    )


def _result_from_dominance(
    args: WindowsCfgGateToSinkArgs,
    gates_path,
    sinks_path,
    gate: GateRecord,
    operation: OperationRecord,
    dominance,
) -> WindowsCfgGateToSinkResult:
    packet_status = _packet_status(dominance.status)
    return WindowsCfgGateToSinkResult(
        gates_path=str(gates_path),
        sinks_path=str(sinks_path),
        gate=CfgGateSite(symbol=args.gate_symbol, va=args.gate_va, gate=gate),
        sink=CfgSinkSite(symbol=args.sink_symbol, va=args.sink_va, operation=operation),
        status=dominance.status,
        suggested_packet_gate_status=packet_status,
        confidence=dominance.confidence,
        reason=(
            f"{args.gate_symbol}@0x{args.gate_va:x} vs "
            f"{args.sink_symbol}@0x{args.sink_va:x}: {dominance.reason}"
        ),
        dominance_provenance=dominance.provenance,
        notes=[
            "CFG dominance evidence does not prove source value equivalence or sink argument roles"
        ],
    )


def _packet_status(status: str) -> GateStatus:
    if status == "dominated":
        return "dominated"
    if status == "not_dominated":
        return "not_dominated"
    if status == "same_block":
        return "gate_same_line"
    return "unknown"


def build_tool() -> WindowsCfgGateToSinkTool:
    return WindowsCfgGateToSinkTool()
