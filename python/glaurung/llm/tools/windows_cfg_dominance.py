from __future__ import annotations

from collections import deque
from typing import Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


DominanceStatus = Literal[
    "dominated",
    "not_dominated",
    "same_block",
    "unreachable",
    "unknown",
]


class CfgBlockFact(BaseModel):
    id: str
    start_va: int
    end_va: int
    successor_ids: list[str] = Field(default_factory=list)
    predecessor_ids: list[str] = Field(default_factory=list)


class WindowsCfgDominanceArgs(BaseModel):
    function_va: int | None = Field(
        None,
        description="Function entry VA. Required when cfg_blocks is omitted.",
    )
    gate_va: int = Field(..., description="VA of the validation gate call or branch.")
    sink_va: int = Field(..., description="VA of the sink call or memory operation.")
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
        description="If true, add a compact CFG dominance evidence node to the KB.",
    )


class WindowsCfgDominanceResult(BaseModel):
    function_va: int | None
    gate_va: int
    sink_va: int
    gate_block_id: str | None = None
    sink_block_id: str | None = None
    entry_block_id: str | None = None
    block_count: int
    edge_count: int
    status: DominanceStatus
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    provenance: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsCfgDominanceTool(
    MemoryTool[WindowsCfgDominanceArgs, WindowsCfgDominanceResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_cfg_dominance",
                description=(
                    "Check whether a gate basic block dominates a sink basic "
                    "block in a Windows PE function CFG."
                ),
                tags=("windows", "pe", "cfg", "dominance", "gates"),
            ),
            WindowsCfgDominanceArgs,
            WindowsCfgDominanceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsCfgDominanceArgs,
    ) -> WindowsCfgDominanceResult:
        blocks, function_va, provenance, notes = _blocks(ctx, args)
        result = _assess(args, blocks, function_va, provenance, notes)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_cfg_dominance",
                    props={
                        "function_va": result.function_va,
                        "gate_va": result.gate_va,
                        "sink_va": result.sink_va,
                        "status": result.status,
                        "confidence": result.confidence,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result.evidence_node_id = evidence_node_id

        return result


def _blocks(
    ctx: MemoryContext,
    args: WindowsCfgDominanceArgs,
) -> tuple[list[CfgBlockFact], int | None, list[str], list[str]]:
    if args.cfg_blocks:
        return args.cfg_blocks, args.function_va, ["supplied_cfg_blocks"], []
    if args.function_va is None:
        return [], None, ["native_cfg_not_run"], ["function_va or cfg_blocks is required"]
    try:
        funcs, _cg = g.analysis.analyze_functions_path(
            str(ctx.file_path),
            ctx.budgets.max_read_bytes,
            ctx.budgets.max_file_size,
            max_functions=args.max_functions,
            max_blocks=args.max_blocks,
            max_instructions=args.max_instructions,
            timeout_ms=args.timeout_ms,
        )
    except Exception as exc:
        return [], args.function_va, ["native_cfg_failed"], [f"native CFG analysis failed: {exc}"]

    for func in funcs:
        entry = int(getattr(getattr(func, "entry_point", 0), "value", 0) or 0)
        if entry != args.function_va:
            continue
        return (
            [_block_from_native(block) for block in getattr(func, "basic_blocks", [])],
            entry,
            ["glaurung_native_cfg"],
            [],
        )
    return [], args.function_va, ["glaurung_native_cfg"], ["function_va not found"]


def _block_from_native(block: object) -> CfgBlockFact:
    return CfgBlockFact(
        id=str(getattr(block, "id")),
        start_va=int(getattr(getattr(block, "start_address"), "value")),
        end_va=int(getattr(getattr(block, "end_address"), "value")),
        successor_ids=[str(value) for value in getattr(block, "successor_ids", [])],
        predecessor_ids=[str(value) for value in getattr(block, "predecessor_ids", [])],
    )


def _assess(
    args: WindowsCfgDominanceArgs,
    blocks: list[CfgBlockFact],
    function_va: int | None,
    provenance: list[str],
    notes: list[str],
) -> WindowsCfgDominanceResult:
    edge_count = sum(len(block.successor_ids) for block in blocks)
    if not blocks:
        return _result(args, function_va, None, None, None, 0, 0, "unknown", 0.0, "no CFG blocks available", provenance, notes)

    by_id = {block.id: block for block in blocks}
    entry = _entry_block(blocks)
    gate = _containing_block(blocks, args.gate_va)
    sink = _containing_block(blocks, args.sink_va)
    if gate is None or sink is None:
        missing = []
        if gate is None:
            missing.append(f"gate_va 0x{args.gate_va:x}")
        if sink is None:
            missing.append(f"sink_va 0x{args.sink_va:x}")
        return _result(
            args,
            function_va,
            gate.id if gate else None,
            sink.id if sink else None,
            entry.id if entry else None,
            len(blocks),
            edge_count,
            "unknown",
            0.2,
            "no containing block for " + ", ".join(missing),
            provenance,
            notes,
        )
    if gate.id == sink.id:
        return _result(
            args,
            function_va,
            gate.id,
            sink.id,
            entry.id if entry else None,
            len(blocks),
            edge_count,
            "same_block",
            0.65,
            "gate and sink are in the same basic block; instruction order still matters",
            provenance,
            notes,
        )
    if entry is None:
        return _result(
            args,
            function_va,
            gate.id,
            sink.id,
            None,
            len(blocks),
            edge_count,
            "unknown",
            0.2,
            "no entry block found for dominance calculation",
            provenance,
            notes,
        )

    reachable = _reachable(entry.id, by_id)
    if sink.id not in reachable:
        return _result(
            args,
            function_va,
            gate.id,
            sink.id,
            entry.id,
            len(blocks),
            edge_count,
            "unreachable",
            0.5,
            "sink block is not reachable from the entry block",
            provenance,
            notes,
        )
    dominators = _dominators(blocks, entry.id)
    if gate.id in dominators.get(sink.id, set()):
        return _result(
            args,
            function_va,
            gate.id,
            sink.id,
            entry.id,
            len(blocks),
            edge_count,
            "dominated",
            0.85,
            f"gate block {gate.id} dominates sink block {sink.id}",
            provenance,
            notes,
        )
    return _result(
        args,
        function_va,
        gate.id,
        sink.id,
        entry.id,
        len(blocks),
        edge_count,
        "not_dominated",
        0.85,
        f"there is an entry-to-sink path that does not pass through gate block {gate.id}",
        provenance,
        notes,
    )


def _result(
    args: WindowsCfgDominanceArgs,
    function_va: int | None,
    gate_block_id: str | None,
    sink_block_id: str | None,
    entry_block_id: str | None,
    block_count: int,
    edge_count: int,
    status: DominanceStatus,
    confidence: float,
    reason: str,
    provenance: list[str],
    notes: list[str],
) -> WindowsCfgDominanceResult:
    return WindowsCfgDominanceResult(
        function_va=function_va,
        gate_va=args.gate_va,
        sink_va=args.sink_va,
        gate_block_id=gate_block_id,
        sink_block_id=sink_block_id,
        entry_block_id=entry_block_id,
        block_count=block_count,
        edge_count=edge_count,
        status=status,
        confidence=confidence,
        reason=reason,
        provenance=provenance,
        notes=notes,
    )


def _entry_block(blocks: list[CfgBlockFact]) -> CfgBlockFact | None:
    no_preds = [block for block in blocks if not block.predecessor_ids]
    if no_preds:
        return min(no_preds, key=lambda block: block.start_va)
    return min(blocks, key=lambda block: block.start_va) if blocks else None


def _containing_block(blocks: list[CfgBlockFact], va: int) -> CfgBlockFact | None:
    return next((block for block in blocks if block.start_va <= va < block.end_va), None)


def _reachable(entry_id: str, by_id: dict[str, CfgBlockFact]) -> set[str]:
    seen: set[str] = set()
    queue: deque[str] = deque([entry_id])
    while queue:
        block_id = queue.popleft()
        if block_id in seen or block_id not in by_id:
            continue
        seen.add(block_id)
        queue.extend(by_id[block_id].successor_ids)
    return seen


def _dominators(blocks: list[CfgBlockFact], entry_id: str) -> dict[str, set[str]]:
    ids = {block.id for block in blocks}
    predecessors = {
        block.id: set(block.predecessor_ids) & ids
        for block in blocks
    }
    dom = {block_id: set(ids) for block_id in ids}
    dom[entry_id] = {entry_id}

    changed = True
    while changed:
        changed = False
        for block_id in sorted(ids - {entry_id}):
            preds = predecessors.get(block_id, set())
            if preds:
                new = set.intersection(*(dom[pred] for pred in preds)) | {block_id}
            else:
                new = {block_id}
            if new != dom[block_id]:
                dom[block_id] = new
                changed = True
    return dom


def build_tool() -> WindowsCfgDominanceTool:
    return WindowsCfgDominanceTool()
