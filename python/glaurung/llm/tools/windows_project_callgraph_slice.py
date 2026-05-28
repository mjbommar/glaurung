from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


CallgraphDirection = Literal["incoming", "outgoing", "both"]


class WindowsProjectCallgraphSliceArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Function entry VA to center the callgraph slice on.",
    )
    function_name: str | None = Field(
        None,
        description="Function name filter used when function_va is not supplied.",
    )
    direction: CallgraphDirection = Field(
        "both",
        description="Return incoming callers, outgoing callees, or both.",
    )
    max_edges: int = Field(64, ge=0, description="Maximum call edges to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact callgraph-slice evidence node to the KB.",
    )


class ProjectCallgraphFunction(BaseModel):
    binary_id: int
    entry_va: int
    canonical: str | None = None
    demangled: str | None = None


class ProjectCallgraphEdge(BaseModel):
    binary_id: int
    direction: Literal["incoming", "outgoing"]
    callsite_va: int
    caller_va: int | None = None
    caller_name: str | None = None
    caller_demangled: str | None = None
    callee_va: int
    callee_name: str | None = None
    callee_demangled: str | None = None
    evidence_kind: str = "project_call_xref"
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectCallgraphSliceResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    target: ProjectCallgraphFunction | None = None
    incoming_count_total: int
    outgoing_count_total: int
    edges: list[ProjectCallgraphEdge]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectCallgraphSliceTool(
    MemoryTool[WindowsProjectCallgraphSliceArgs, WindowsProjectCallgraphSliceResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_callgraph_slice",
                description=(
                    "Return incoming and outgoing PE callgraph edges for one "
                    "function from persisted .glaurung call xrefs."
                ),
                tags=("windows", "pe", "project", "callgraph", "xrefs"),
            ),
            WindowsProjectCallgraphSliceArgs,
            WindowsProjectCallgraphSliceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectCallgraphSliceArgs,
    ) -> WindowsProjectCallgraphSliceResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            target = _resolve_target(conn, present, binary_id, args)
            incoming_total, outgoing_total, rows = _query_edges(
                conn,
                present,
                binary_id,
                target.entry_va if target else None,
                args,
            )
        finally:
            conn.close()

        edges = [_edge_from_row(row) for row in rows]
        coverage = _coverage(present, target, incoming_total, outgoing_total)
        missing = _missing_capabilities(present, target, incoming_total, outgoing_total)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_callgraph_slice",
                    props={
                        "project_path": str(project_path),
                        "binary_id": binary_id,
                        "function_va": args.function_va,
                        "function_name": args.function_name,
                        "target_va": target.entry_va if target else None,
                        "direction": args.direction,
                        "edge_count": len(edges),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectCallgraphSliceResult(
            project_path=str(project_path),
            binary_id=binary_id,
            target=target,
            incoming_count_total=incoming_total,
            outgoing_count_total=outgoing_total,
            edges=edges,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "project callgraph slices come from persisted call xrefs; CFG dominance and argument flow are separate facts"
            ],
        )


def _present_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _first_binary_id(conn: sqlite3.Connection, present: set[str]) -> int | None:
    if "binaries" not in present:
        return None
    row = conn.execute("SELECT binary_id FROM binaries ORDER BY binary_id LIMIT 1").fetchone()
    return int(row[0]) if row else None


def _resolve_target(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectCallgraphSliceArgs,
) -> ProjectCallgraphFunction | None:
    if args.function_va is not None:
        return _function_at_va(conn, present, binary_id, args.function_va)
    if args.function_name:
        return _function_by_name(conn, present, binary_id, args.function_name)
    return None


def _function_at_va(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_va: int,
) -> ProjectCallgraphFunction:
    if "function_names" not in present:
        return ProjectCallgraphFunction(
            binary_id=int(binary_id or 0),
            entry_va=function_va,
        )
    clauses = ["entry_va = ?"]
    params: list[object] = [function_va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        "SELECT binary_id, entry_va, canonical, demangled FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY binary_id LIMIT 1",
        params,
    ).fetchone()
    if row:
        return ProjectCallgraphFunction(
            binary_id=int(row[0]),
            entry_va=int(row[1]),
            canonical=row[2],
            demangled=row[3],
        )
    return ProjectCallgraphFunction(
        binary_id=int(binary_id or 0),
        entry_va=function_va,
    )


def _function_by_name(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_name: str,
) -> ProjectCallgraphFunction | None:
    if "function_names" not in present:
        return None
    needle = _short_symbol(function_name).lower()
    clauses = [
        "(LOWER(canonical) = ? OR LOWER(demangled) = ? "
        "OR LOWER(canonical) LIKE ? OR LOWER(demangled) LIKE ?)"
    ]
    params: list[object] = [
        function_name.lower(),
        function_name.lower(),
        f"%{needle}",
        f"%{needle}",
    ]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        "SELECT binary_id, entry_va, canonical, demangled FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY entry_va LIMIT 1",
        params,
    ).fetchone()
    if not row:
        return None
    return ProjectCallgraphFunction(
        binary_id=int(row[0]),
        entry_va=int(row[1]),
        canonical=row[2],
        demangled=row[3],
    )


def _query_edges(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    target_va: int | None,
    args: WindowsProjectCallgraphSliceArgs,
) -> tuple[int, int, list[dict[str, Any]]]:
    if "xrefs" not in present or target_va is None:
        return 0, 0, []
    incoming_total = _edge_count(conn, binary_id, "dst_va = ?", target_va)
    outgoing_total = _edge_count(conn, binary_id, "src_function_va = ?", target_va)

    rows: list[dict[str, Any]] = []
    limit = max(0, args.max_edges)
    if limit == 0:
        return incoming_total, outgoing_total, rows
    if args.direction in {"incoming", "both"}:
        rows.extend(
            _edge_rows(
                conn,
                present,
                binary_id,
                "incoming",
                "x.dst_va = ?",
                target_va,
                limit - len(rows),
            )
        )
    if args.direction in {"outgoing", "both"} and len(rows) < limit:
        rows.extend(
            _edge_rows(
                conn,
                present,
                binary_id,
                "outgoing",
                "x.src_function_va = ?",
                target_va,
                limit - len(rows),
            )
        )
    return incoming_total, outgoing_total, rows


def _edge_count(
    conn: sqlite3.Connection,
    binary_id: int | None,
    clause: str,
    target_va: int,
) -> int:
    clauses = ["kind = 'call'", clause]
    params: list[object] = [target_va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        f"SELECT COUNT(*) FROM xrefs WHERE {' AND '.join(clauses)}",
        params,
    ).fetchone()
    return int(row[0] if row else 0)


def _edge_rows(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    direction: Literal["incoming", "outgoing"],
    clause: str,
    target_va: int,
    limit: int,
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []
    clauses = ["x.kind = 'call'", clause]
    params: list[object] = [target_va]
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    params.append(limit)
    query = _edge_query(
        fn_join="function_names" in present,
        where=" AND ".join(clauses),
        direction=direction,
    )
    cur = conn.execute(query, params)
    columns = [col[0] for col in cur.description or []]
    return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]


def _edge_query(*, fn_join: bool, where: str, direction: str) -> str:
    caller_select = (
        "caller.canonical AS caller_name, caller.demangled AS caller_demangled"
        if fn_join
        else "NULL AS caller_name, NULL AS caller_demangled"
    )
    callee_select = (
        "callee.canonical AS callee_name, callee.demangled AS callee_demangled"
        if fn_join
        else "NULL AS callee_name, NULL AS callee_demangled"
    )
    joins = ""
    if fn_join:
        joins = """
LEFT JOIN function_names caller ON
    caller.binary_id = x.binary_id AND caller.entry_va = x.src_function_va
LEFT JOIN function_names callee ON
    callee.binary_id = x.binary_id AND callee.entry_va = x.dst_va
"""
    return f"""
SELECT
    x.binary_id AS binary_id,
    '{direction}' AS direction,
    x.src_va AS callsite_va,
    x.src_function_va AS caller_va,
    x.dst_va AS callee_va,
    {caller_select},
    {callee_select}
FROM xrefs x
{joins}
WHERE {where}
ORDER BY x.src_va
LIMIT ?
"""


def _edge_from_row(row: dict[str, Any]) -> ProjectCallgraphEdge:
    provenance = ["glaurung_project_xrefs"]
    if row.get("caller_name") or row.get("callee_name"):
        provenance.append("glaurung_function_names")
    return ProjectCallgraphEdge(
        binary_id=int(row["binary_id"]),
        direction=row["direction"],
        callsite_va=int(row["callsite_va"]),
        caller_va=int(row["caller_va"]) if row["caller_va"] is not None else None,
        caller_name=row.get("caller_name"),
        caller_demangled=row.get("caller_demangled"),
        callee_va=int(row["callee_va"]),
        callee_name=row.get("callee_name"),
        callee_demangled=row.get("callee_demangled"),
        confidence=0.86 if row.get("caller_name") and row.get("callee_name") else 0.7,
        provenance=provenance,
    )


def _short_symbol(symbol: str) -> str:
    return symbol.rsplit("!", 1)[-1].rsplit("::", 1)[-1]


def _coverage(
    present: set[str],
    target: ProjectCallgraphFunction | None,
    incoming_total: int,
    outgoing_total: int,
) -> list[str]:
    coverage: list[str] = []
    if "xrefs" in present and (incoming_total or outgoing_total):
        coverage.append("project_call_xrefs")
    if target and target.canonical:
        coverage.append("target_function_name")
    if "function_names" in present:
        coverage.append("callee_caller_names")
    return coverage


def _missing_capabilities(
    present: set[str],
    target: ProjectCallgraphFunction | None,
    incoming_total: int,
    outgoing_total: int,
) -> list[str]:
    missing: list[str] = []
    if target is None:
        missing.append("target_function")
    if "xrefs" not in present or not (incoming_total or outgoing_total):
        missing.append("project_call_xrefs")
    if "function_names" not in present:
        missing.append("function_names")
    missing.append("call_argument_operands")
    missing.append("cfg_dominance")
    return missing


def build_tool() -> MemoryTool[
    WindowsProjectCallgraphSliceArgs, WindowsProjectCallgraphSliceResult
]:
    return WindowsProjectCallgraphSliceTool()
