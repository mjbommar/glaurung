from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


XrefQueryKind = Literal[
    "refs_to",
    "refs_from",
    "callers",
    "callees",
    "reads_from",
    "writes_to",
    "all",
]
XrefTargetKind = Literal["function", "data", "unknown"]


class WindowsProjectXrefQueryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    query: XrefQueryKind = Field(
        "all",
        description=(
            "IDA/Ghidra-style query: refs_to, refs_from, callers, callees, "
            "reads_from, writes_to, or all."
        ),
    )
    va: int | None = Field(
        None,
        description="Optional VA to query. If omitted, symbol must resolve to a VA.",
    )
    symbol: str | None = Field(
        None,
        description="Optional function or data symbol/name to resolve and query.",
    )
    kind: str | None = Field(
        None,
        description="Optional raw xref kind filter, for example call or data_write.",
    )
    max_rows: int = Field(128, ge=0, description="Maximum xref rows to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact xref-query evidence node to the KB.",
    )


class WindowsProjectXrefTarget(BaseModel):
    va: int | None = None
    name: str | None = None
    demangled: str | None = None
    target_kind: XrefTargetKind = "unknown"
    c_type: str | None = None
    size: int | None = None
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectXrefRow(BaseModel):
    binary_id: int
    src_va: int
    dst_va: int
    kind: str
    src_function_va: int | None = None
    src_function_name: str | None = None
    src_function_demangled: str | None = None
    dst_function_name: str | None = None
    dst_function_demangled: str | None = None
    dst_data_label: str | None = None
    dst_data_type: str | None = None
    relation: str
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectXrefQueryResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    query: XrefQueryKind
    target: WindowsProjectXrefTarget
    total_count: int
    returned_count: int
    rows: list[WindowsProjectXrefRow]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectXrefQueryTool(
    MemoryTool[WindowsProjectXrefQueryArgs, WindowsProjectXrefQueryResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_xref_query",
                description=(
                    "Run IDA/Ghidra-style project xref queries over persisted "
                    "Windows PE xrefs: callers, callees, reads, writes, refs-to, "
                    "and refs-from by VA or symbol."
                ),
                tags=("windows", "pe", "project", "xrefs", "navigation"),
            ),
            WindowsProjectXrefQueryArgs,
            WindowsProjectXrefQueryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectXrefQueryArgs,
    ) -> WindowsProjectXrefQueryResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            target = _resolve_target(conn, present, binary_id, args)
            total_count, rows = _query_xrefs(conn, present, binary_id, target, args)
        finally:
            conn.close()

        xrefs = [_xref_row(row, target=target, query=args.query) for row in rows]
        coverage = _coverage(present, target, xrefs)
        missing = _missing_capabilities(present, target, xrefs)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_xref_query",
                    props={
                        "project_path": str(project_path),
                        "binary_id": binary_id,
                        "query": args.query,
                        "va": args.va,
                        "symbol": args.symbol,
                        "total_count": total_count,
                        "returned_count": len(xrefs),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectXrefQueryResult(
            project_path=str(project_path),
            binary_id=binary_id,
            query=args.query,
            target=target,
            total_count=total_count,
            returned_count=len(xrefs),
            rows=xrefs,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "project xref queries use persisted .glaurung xrefs; re-run project bootstrap if expected refs are missing"
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
    row = conn.execute(
        "SELECT binary_id FROM binaries ORDER BY binary_id LIMIT 1"
    ).fetchone()
    return int(row[0]) if row else None


def _resolve_target(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectXrefQueryArgs,
) -> WindowsProjectXrefTarget:
    if args.va is not None:
        return _target_for_va(conn, present, binary_id, int(args.va))
    if args.symbol:
        target = _target_for_symbol(conn, present, binary_id, args.symbol)
        if target is not None:
            return target
    return WindowsProjectXrefTarget(provenance=["unresolved_target"])


def _target_for_va(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
) -> WindowsProjectXrefTarget:
    function = _function_at_va(conn, present, binary_id, va)
    if function is not None:
        return function
    data = _data_at_va(conn, present, binary_id, va)
    if data is not None:
        return data
    return WindowsProjectXrefTarget(
        va=va,
        target_kind="unknown",
        provenance=["explicit_va"],
    )


def _target_for_symbol(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    symbol: str,
) -> WindowsProjectXrefTarget | None:
    function = _function_by_symbol(conn, present, binary_id, symbol)
    if function is not None:
        return function
    return _data_by_symbol(conn, present, binary_id, symbol)


def _function_at_va(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
) -> WindowsProjectXrefTarget | None:
    if "function_names" not in present:
        return None
    clauses = ["entry_va = ?"]
    params: list[object] = [va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        "SELECT entry_va, canonical, demangled FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY binary_id LIMIT 1",
        params,
    ).fetchone()
    if not row:
        return None
    return WindowsProjectXrefTarget(
        va=int(row[0]),
        name=row[1],
        demangled=row[2],
        target_kind="function",
        provenance=["function_names"],
    )


def _function_by_symbol(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    symbol: str,
) -> WindowsProjectXrefTarget | None:
    if "function_names" not in present:
        return None
    needle = _short_symbol(symbol).lower()
    clauses = [
        "(LOWER(canonical) = ? OR LOWER(demangled) = ? "
        "OR LOWER(canonical) LIKE ? OR LOWER(demangled) LIKE ?)"
    ]
    params: list[object] = [
        symbol.lower(),
        symbol.lower(),
        f"%{needle}",
        f"%{needle}",
    ]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        "SELECT entry_va, canonical, demangled FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY entry_va LIMIT 1",
        params,
    ).fetchone()
    if not row:
        return None
    return WindowsProjectXrefTarget(
        va=int(row[0]),
        name=row[1],
        demangled=row[2],
        target_kind="function",
        provenance=["function_names", "symbol_lookup"],
    )


def _data_at_va(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
) -> WindowsProjectXrefTarget | None:
    if "data_labels" not in present:
        return None
    clauses = ["va = ?"]
    params: list[object] = [va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        "SELECT va, name, c_type, size FROM data_labels "
        f"WHERE {' AND '.join(clauses)} ORDER BY binary_id LIMIT 1",
        params,
    ).fetchone()
    if not row:
        return None
    return WindowsProjectXrefTarget(
        va=int(row[0]),
        name=row[1],
        target_kind="data",
        c_type=row[2],
        size=int(row[3]) if row[3] is not None else None,
        provenance=["data_labels"],
    )


def _data_by_symbol(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    symbol: str,
) -> WindowsProjectXrefTarget | None:
    if "data_labels" not in present:
        return None
    needle = _short_symbol(symbol).lower()
    clauses = ["(LOWER(name) = ? OR LOWER(name) LIKE ?)"]
    params: list[object] = [symbol.lower(), f"%{needle}"]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        "SELECT va, name, c_type, size FROM data_labels "
        f"WHERE {' AND '.join(clauses)} ORDER BY va LIMIT 1",
        params,
    ).fetchone()
    if not row:
        return None
    return WindowsProjectXrefTarget(
        va=int(row[0]),
        name=row[1],
        target_kind="data",
        c_type=row[2],
        size=int(row[3]) if row[3] is not None else None,
        provenance=["data_labels", "symbol_lookup"],
    )


def _query_xrefs(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    target: WindowsProjectXrefTarget,
    args: WindowsProjectXrefQueryArgs,
) -> tuple[int, list[dict[str, Any]]]:
    if "xrefs" not in present or target.va is None:
        return 0, []
    where, params = _xref_where(binary_id, int(target.va), args)
    total_row = conn.execute(
        f"SELECT COUNT(*) FROM xrefs x WHERE {where}",
        params,
    ).fetchone()
    total = int(total_row[0]) if total_row else 0
    if args.max_rows == 0:
        return total, []
    query = _xref_query(present, where)
    cur = conn.execute(query, [*params, args.max_rows])
    columns = [col[0] for col in cur.description or []]
    return total, [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]


def _xref_where(
    binary_id: int | None,
    target_va: int,
    args: WindowsProjectXrefQueryArgs,
) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if args.kind:
        clauses.append("x.kind = ?")
        params.append(args.kind)

    if args.query == "callers":
        clauses.append("x.kind = 'call'")
        clauses.append("x.dst_va = ?")
        params.append(target_va)
    elif args.query == "callees":
        clauses.append("x.kind = 'call'")
        clauses.append("(x.src_function_va = ? OR x.src_va = ?)")
        params.extend([target_va, target_va])
    elif args.query == "reads_from":
        clauses.append("x.kind = 'data_read'")
        clauses.append("x.dst_va = ?")
        params.append(target_va)
    elif args.query == "writes_to":
        clauses.append("x.kind = 'data_write'")
        clauses.append("x.dst_va = ?")
        params.append(target_va)
    elif args.query == "refs_to":
        clauses.append("x.dst_va = ?")
        params.append(target_va)
    elif args.query == "refs_from":
        clauses.append("(x.src_function_va = ? OR x.src_va = ?)")
        params.extend([target_va, target_va])
    else:
        clauses.append("(x.dst_va = ? OR x.src_function_va = ? OR x.src_va = ?)")
        params.extend([target_va, target_va, target_va])
    return " AND ".join(clauses), params


def _xref_query(present: set[str], where: str) -> str:
    function_joins = ""
    function_select = """
    NULL AS src_function_name,
    NULL AS src_function_demangled,
    NULL AS dst_function_name,
    NULL AS dst_function_demangled
"""
    if "function_names" in present:
        function_joins = """
LEFT JOIN function_names src_fn ON
    src_fn.binary_id = x.binary_id AND src_fn.entry_va = x.src_function_va
LEFT JOIN function_names dst_fn ON
    dst_fn.binary_id = x.binary_id AND dst_fn.entry_va = x.dst_va
"""
        function_select = """
    src_fn.canonical AS src_function_name,
    src_fn.demangled AS src_function_demangled,
    dst_fn.canonical AS dst_function_name,
    dst_fn.demangled AS dst_function_demangled
"""
    data_join = ""
    data_select = "NULL AS dst_data_label, NULL AS dst_data_type"
    if "data_labels" in present:
        data_join = """
LEFT JOIN data_labels dst_data ON
    dst_data.binary_id = x.binary_id AND dst_data.va = x.dst_va
"""
        data_select = (
            "dst_data.name AS dst_data_label, dst_data.c_type AS dst_data_type"
        )
    return f"""
SELECT
    x.binary_id AS binary_id,
    x.src_va AS src_va,
    x.dst_va AS dst_va,
    x.kind AS kind,
    x.src_function_va AS src_function_va,
    {function_select},
    {data_select}
FROM xrefs x
{function_joins}
{data_join}
WHERE {where}
ORDER BY x.kind, x.src_va, x.dst_va
LIMIT ?
"""


def _xref_row(
    row: dict[str, Any],
    *,
    target: WindowsProjectXrefTarget,
    query: XrefQueryKind,
) -> WindowsProjectXrefRow:
    provenance = ["glaurung_project_xrefs"]
    if row.get("src_function_name") or row.get("dst_function_name"):
        provenance.append("function_names")
    if row.get("dst_data_label"):
        provenance.append("data_labels")
    return WindowsProjectXrefRow(
        binary_id=int(row["binary_id"]),
        src_va=int(row["src_va"]),
        dst_va=int(row["dst_va"]),
        kind=str(row["kind"]),
        src_function_va=int(row["src_function_va"])
        if row["src_function_va"] is not None
        else None,
        src_function_name=row.get("src_function_name"),
        src_function_demangled=row.get("src_function_demangled"),
        dst_function_name=row.get("dst_function_name"),
        dst_function_demangled=row.get("dst_function_demangled"),
        dst_data_label=row.get("dst_data_label"),
        dst_data_type=row.get("dst_data_type"),
        relation=_relation(str(row["kind"]), target=target, query=query),
        confidence=0.9
        if "function_names" in provenance or "data_labels" in provenance
        else 0.72,
        provenance=provenance,
    )


def _relation(
    kind: str,
    *,
    target: WindowsProjectXrefTarget,
    query: XrefQueryKind,
) -> str:
    if kind == "call":
        return "caller" if query in {"callers", "refs_to"} else "callee"
    if kind == "data_read":
        return "reader"
    if kind == "data_write":
        return "writer"
    if kind == "jump":
        return "jumper" if query in {"refs_to", "all"} else "jump_target"
    if kind == "struct_field":
        return "field_ref"
    if target.target_kind == "data":
        return "data_ref"
    return "xref"


def _coverage(
    present: set[str],
    target: WindowsProjectXrefTarget,
    rows: list[WindowsProjectXrefRow],
) -> list[str]:
    coverage: list[str] = []
    if "xrefs" in present and rows:
        coverage.append("project_xrefs")
    if target.va is not None:
        coverage.append("target_va")
    if target.target_kind == "function":
        coverage.append("target_function")
    if target.target_kind == "data":
        coverage.append("target_data_label")
    if "function_names" in present:
        coverage.append("function_names")
    if "data_labels" in present:
        coverage.append("data_labels")
    if any(row.kind == "data_write" for row in rows):
        coverage.append("data_write_xrefs")
    if any(row.kind == "data_read" for row in rows):
        coverage.append("data_read_xrefs")
    if any(row.kind == "call" for row in rows):
        coverage.append("call_xrefs")
    return coverage


def _missing_capabilities(
    present: set[str],
    target: WindowsProjectXrefTarget,
    rows: list[WindowsProjectXrefRow],
) -> list[str]:
    missing: list[str] = []
    if "xrefs" not in present:
        missing.append("project_xrefs")
    if target.va is None:
        missing.append("target_resolution")
    if not rows:
        missing.append("matching_xrefs")
    if "function_names" not in present:
        missing.append("function_names")
    if "data_labels" not in present:
        missing.append("data_labels")
    missing.append("operand_snippets")
    missing.append("cfg_dominance")
    return missing


def _short_symbol(symbol: str) -> str:
    return symbol.rsplit("!", 1)[-1].rsplit("::", 1)[-1]


def build_tool() -> WindowsProjectXrefQueryTool:
    return WindowsProjectXrefQueryTool()
