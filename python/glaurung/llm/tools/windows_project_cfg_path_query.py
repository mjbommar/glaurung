from __future__ import annotations

import sqlite3
from collections import deque
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


PathCoverageStatus = Literal[
    "covered",
    "bypass",
    "same_block",
    "unreachable",
    "unknown",
    "not_requested",
]


class WindowsProjectCfgPathQueryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    sink_va: int = Field(..., description="VA of the target sink call or operation.")
    function_va: int | None = Field(
        None,
        description="Optional function VA. If omitted, resolved from supplied VAs.",
    )
    branch_va: int | None = Field(
        None,
        description="Optional branch/source VA used for branch-to-sink reachability.",
    )
    gate_va: int | None = Field(
        None,
        description="Optional gate VA used for all-path gate coverage.",
    )
    max_path_blocks: int = Field(
        32,
        ge=1,
        description="Maximum block ids to include in a sample path.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact CFG path-query evidence node to the KB.",
    )


class WindowsProjectCfgPathQueryResult(BaseModel):
    project_path: str
    function_va: int | None = None
    entry_block_id: str | None = None
    branch_block_id: str | None = None
    gate_block_id: str | None = None
    sink_block_id: str | None = None
    block_count: int = 0
    edge_count: int = 0
    branch_reaches_sink: bool | None = None
    entry_reaches_sink: bool | None = None
    gate_reaches_sink: bool | None = None
    all_paths_to_sink_pass_gate: bool | None = None
    status: PathCoverageStatus = "unknown"
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    reason: str
    bypass_path_block_ids: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectCfgPathQueryTool(
    MemoryTool[WindowsProjectCfgPathQueryArgs, WindowsProjectCfgPathQueryResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_cfg_path_query",
                description=(
                    "Query persisted .glaurung CFG tables for containing blocks, "
                    "branch-to-sink reachability, and all-path gate coverage."
                ),
                tags=("windows", "pe", "project", "cfg", "dominance", "gates"),
            ),
            WindowsProjectCfgPathQueryArgs,
            WindowsProjectCfgPathQueryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectCfgPathQueryArgs,
    ) -> WindowsProjectCfgPathQueryResult:
        result = _query(args)

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_cfg_path_query",
                    props={
                        "project_path": result.project_path,
                        "function_va": result.function_va,
                        "sink_va": args.sink_va,
                        "gate_va": args.gate_va,
                        "branch_va": args.branch_va,
                        "status": result.status,
                        "confidence": result.confidence,
                    },
                )
            )
            result.evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return result


def _query(args: WindowsProjectCfgPathQueryArgs) -> WindowsProjectCfgPathQueryResult:
    project_path = Path(args.project_path)
    if not project_path.exists():
        return _unknown(args, f"{project_path}: .glaurung project does not exist")
    try:
        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return _unknown(args, f"failed to open project: {exc}")
    try:
        present = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        required = {"basic_blocks", "cfg_edges"}
        if not required.issubset(present):
            missing = ", ".join(sorted(required - present))
            return _unknown(args, f"project lacks persisted CFG table(s): {missing}")

        resolved = _resolve_function(conn, args)
        if resolved is None:
            return _unknown(args, "no persisted CFG function contains requested VA set")
        binary_id, function_va = resolved
        blocks = _blocks(conn, binary_id, function_va)
        if not blocks:
            return _unknown(args, f"no persisted CFG blocks for function 0x{function_va:x}")
        successors, predecessors = _edges(conn, binary_id, function_va)
    except sqlite3.Error as exc:
        return _unknown(args, f"failed to read persisted CFG facts: {exc}")
    finally:
        conn.close()

    entry_id = _entry_block(blocks)
    sink_id = _containing_block(blocks, args.sink_va)
    gate_id = _containing_block(blocks, args.gate_va) if args.gate_va is not None else None
    branch_id = (
        _containing_block(blocks, args.branch_va)
        if args.branch_va is not None
        else None
    )
    if sink_id is None:
        return _result(
            args,
            function_va,
            entry_id,
            branch_id,
            gate_id,
            None,
            blocks,
            successors,
            "unknown",
            0.2,
            f"no persisted CFG block contains sink_va 0x{args.sink_va:x}",
        )
    if entry_id is None:
        return _result(
            args,
            function_va,
            None,
            branch_id,
            gate_id,
            sink_id,
            blocks,
            successors,
            "unknown",
            0.2,
            "no entry block found for function",
        )

    entry_path = _find_path(entry_id, sink_id, successors)
    branch_path = (
        _find_path(branch_id, sink_id, successors) if branch_id is not None else None
    )
    gate_path = _find_path(gate_id, sink_id, successors) if gate_id is not None else None

    status: PathCoverageStatus
    confidence: float
    reason: str
    bypass_path: list[str] = []
    all_paths_pass_gate: bool | None = None

    if entry_path is None:
        status = "unreachable"
        confidence = 0.75
        reason = "sink block is not reachable from the function entry block"
    elif args.gate_va is None:
        status = "not_requested"
        confidence = 0.8
        reason = "entry-to-sink reachability was computed; no gate_va supplied"
    elif gate_id is None:
        status = "unknown"
        confidence = 0.2
        reason = f"no persisted CFG block contains gate_va 0x{args.gate_va:x}"
    elif gate_id == sink_id:
        status = "same_block"
        confidence = 0.65
        all_paths_pass_gate = True
        reason = "gate and sink are in the same basic block; instruction order still matters"
    else:
        bypass_path = _find_path(entry_id, sink_id, successors, blocked={gate_id}) or []
        all_paths_pass_gate = not bypass_path
        if all_paths_pass_gate:
            status = "covered"
            confidence = 0.9
            reason = f"all entry-to-sink paths pass through gate block {gate_id}"
        else:
            status = "bypass"
            confidence = 0.9
            reason = f"an entry-to-sink path bypasses gate block {gate_id}"

    result = _result(
        args,
        function_va,
        entry_id,
        branch_id,
        gate_id,
        sink_id,
        blocks,
        successors,
        status,
        confidence,
        reason,
        bypass_path_block_ids=bypass_path[: args.max_path_blocks],
    )
    result.entry_reaches_sink = entry_path is not None
    result.branch_reaches_sink = branch_path is not None if branch_id is not None else None
    result.gate_reaches_sink = gate_path is not None if gate_id is not None else None
    result.all_paths_to_sink_pass_gate = all_paths_pass_gate
    return result


def _resolve_function(
    conn: sqlite3.Connection,
    args: WindowsProjectCfgPathQueryArgs,
) -> tuple[int, int] | None:
    if args.function_va is not None:
        row = conn.execute(
            "SELECT binary_id, function_va FROM basic_blocks "
            "WHERE function_va = ? ORDER BY binary_id LIMIT 1",
            (args.function_va,),
        ).fetchone()
        return (int(row[0]), int(row[1])) if row else None

    vas = [args.sink_va]
    if args.branch_va is not None:
        vas.append(args.branch_va)
    if args.gate_va is not None:
        vas.append(args.gate_va)
    matches: set[tuple[int, int]] | None = None
    for va in vas:
        rows = conn.execute(
            "SELECT binary_id, function_va FROM basic_blocks "
            "WHERE start_va <= ? AND ? < end_va",
            (va, va),
        ).fetchall()
        current = {(int(row[0]), int(row[1])) for row in rows}
        matches = current if matches is None else matches & current
    if not matches:
        return None
    return sorted(matches)[0]


def _blocks(
    conn: sqlite3.Connection,
    binary_id: int,
    function_va: int,
) -> dict[str, tuple[int, int, bool]]:
    return {
        str(row[0]): (int(row[1]), int(row[2]), bool(row[3]))
        for row in conn.execute(
            "SELECT block_id, start_va, end_va, is_entry FROM basic_blocks "
            "WHERE binary_id = ? AND function_va = ? ORDER BY start_va",
            (binary_id, function_va),
        ).fetchall()
    }


def _edges(
    conn: sqlite3.Connection,
    binary_id: int,
    function_va: int,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    successors: dict[str, set[str]] = {}
    predecessors: dict[str, set[str]] = {}
    for src, dst in conn.execute(
        "SELECT src_block_id, dst_block_id FROM cfg_edges "
        "WHERE binary_id = ? AND function_va = ?",
        (binary_id, function_va),
    ).fetchall():
        src_id = str(src)
        dst_id = str(dst)
        successors.setdefault(src_id, set()).add(dst_id)
        predecessors.setdefault(dst_id, set()).add(src_id)
    return successors, predecessors


def _entry_block(blocks: dict[str, tuple[int, int, bool]]) -> str | None:
    entries = [block_id for block_id, row in blocks.items() if row[2]]
    if entries:
        return min(entries, key=lambda block_id: blocks[block_id][0])
    return min(blocks, key=lambda block_id: blocks[block_id][0]) if blocks else None


def _containing_block(
    blocks: dict[str, tuple[int, int, bool]],
    va: int | None,
) -> str | None:
    if va is None:
        return None
    return next(
        (
            block_id
            for block_id, (start_va, end_va, _is_entry) in blocks.items()
            if start_va <= va < end_va
        ),
        None,
    )


def _find_path(
    start: str | None,
    target: str,
    successors: dict[str, set[str]],
    *,
    blocked: set[str] | None = None,
) -> list[str] | None:
    if start is None:
        return None
    blocked = blocked or set()
    if start in blocked:
        return None
    queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
    seen: set[str] = set()
    while queue:
        block_id, path = queue.popleft()
        if block_id in seen:
            continue
        seen.add(block_id)
        if block_id == target:
            return path
        for successor in sorted(successors.get(block_id, set())):
            if successor not in seen and successor not in blocked:
                queue.append((successor, [*path, successor]))
    return None


def _result(
    args: WindowsProjectCfgPathQueryArgs,
    function_va: int | None,
    entry_id: str | None,
    branch_id: str | None,
    gate_id: str | None,
    sink_id: str | None,
    blocks: dict[str, tuple[int, int, bool]],
    successors: dict[str, set[str]],
    status: PathCoverageStatus,
    confidence: float,
    reason: str,
    *,
    bypass_path_block_ids: list[str] | None = None,
) -> WindowsProjectCfgPathQueryResult:
    return WindowsProjectCfgPathQueryResult(
        project_path=args.project_path,
        function_va=function_va,
        entry_block_id=entry_id,
        branch_block_id=branch_id,
        gate_block_id=gate_id,
        sink_block_id=sink_id,
        block_count=len(blocks),
        edge_count=sum(len(values) for values in successors.values()),
        status=status,
        confidence=confidence,
        reason=reason,
        bypass_path_block_ids=bypass_path_block_ids or [],
        provenance=["persisted_project_cfg_sql"],
        notes=[
            "CFG path coverage does not prove source value equivalence or sink argument roles"
        ],
    )


def _unknown(
    args: WindowsProjectCfgPathQueryArgs,
    reason: str,
) -> WindowsProjectCfgPathQueryResult:
    return WindowsProjectCfgPathQueryResult(
        project_path=args.project_path,
        reason=reason,
        status="unknown",
        confidence=0.0,
        provenance=["persisted_project_cfg_sql"],
    )


def build_tool() -> WindowsProjectCfgPathQueryTool:
    return WindowsProjectCfgPathQueryTool()
