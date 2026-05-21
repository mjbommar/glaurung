from __future__ import annotations

import sqlite3
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


CORE_TABLES = (
    "binaries",
    "function_names",
    "xrefs",
    "xref_index_state",
    "data_xref_index_state",
    "data_labels",
    "function_prototypes",
    "stack_frame_vars",
    "comments",
    "evidence_log",
    "basic_blocks",
    "cfg_edges",
    "cfg_dominance",
    "cfg_dominance_index_state",
    "cfg_branch_facts",
    "cfg_branch_index_state",
    "function_boundaries",
    "function_chunk_facts",
    "memory_operand_facts",
    "windows_sysinfo_dispatch",
    "callsite_argument_facts",
    "callsite_path_conditions",
)


class WindowsProjectFactSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional function entry VA used to summarize per-function facts.",
    )
    function_name_contains: str | None = Field(
        None,
        description="Optional case-insensitive substring filter for function names.",
    )
    max_rows: int = Field(16, ge=0, description="Maximum function/xref sample rows.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact project-fact evidence node to the KB.",
    )


class ProjectFactTableStatus(BaseModel):
    name: str
    present: bool
    row_count: int = 0


class ProjectFactCounts(BaseModel):
    binary_count: int = 0
    function_name_count: int = 0
    xref_count: int = 0
    call_xref_count: int = 0
    jump_xref_count: int = 0
    data_read_xref_count: int = 0
    data_write_xref_count: int = 0
    data_label_count: int = 0
    function_prototype_count: int = 0
    stack_frame_var_count: int = 0
    comment_count: int = 0
    basic_block_count: int = 0
    cfg_edge_count: int = 0
    cfg_dominance_count: int = 0
    cfg_branch_fact_count: int = 0
    function_boundary_count: int = 0
    function_chunk_fact_count: int = 0
    memory_operand_fact_count: int = 0
    sysinfo_dispatch_count: int = 0
    callsite_argument_fact_count: int = 0
    callsite_path_condition_count: int = 0


class ProjectFunctionFact(BaseModel):
    entry_va: int
    canonical: str
    demangled: str | None = None
    flavor: str | None = None
    set_by: str | None = None
    call_out_count: int = 0
    data_read_count: int = 0
    data_write_count: int = 0
    stack_var_count: int = 0
    comment_count: int = 0


class ProjectXrefFact(BaseModel):
    src_va: int
    dst_va: int
    kind: str
    src_function_va: int | None = None


class WindowsProjectFactSummaryResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    tables: list[ProjectFactTableStatus]
    counts: ProjectFactCounts
    functions: list[ProjectFunctionFact] = Field(default_factory=list)
    xrefs: list[ProjectXrefFact] = Field(default_factory=list)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectFactSummaryTool(
    MemoryTool[WindowsProjectFactSummaryArgs, WindowsProjectFactSummaryResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_fact_summary",
                description=(
                    "Summarize queryable .glaurung project facts for PE "
                    "functions, call/data xrefs, prototypes, and CFG coverage."
                ),
                tags=("windows", "pe", "project", "xrefs", "cfg"),
            ),
            WindowsProjectFactSummaryArgs,
            WindowsProjectFactSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectFactSummaryArgs,
    ) -> WindowsProjectFactSummaryResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            tables = _table_statuses(conn)
            present = {table.name for table in tables if table.present}
            binary_id = args.binary_id or _first_binary_id(conn, present)
            counts = _counts(conn, present, binary_id)
            functions = _function_facts(conn, present, binary_id, args)
            xrefs = _xref_facts(conn, present, binary_id, args)
            coverage = _coverage(counts, present)
            missing = _missing_capabilities(counts, present)
        finally:
            conn.close()

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_fact_summary",
                    props={
                        "project_path": str(project_path),
                        "binary_id": binary_id,
                        "function_count": counts.function_name_count,
                        "xref_count": counts.xref_count,
                        "coverage": coverage,
                        "missing_capabilities": missing,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectFactSummaryResult(
            project_path=str(project_path),
            binary_id=binary_id,
            tables=tables,
            counts=counts,
            functions=functions,
            xrefs=xrefs,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "project fact summary reports available substrate, not source reachability or vulnerability truth"
            ],
        )


def _table_statuses(conn: sqlite3.Connection) -> list[ProjectFactTableStatus]:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    present = {str(row[0]) for row in cur.fetchall()}
    statuses = []
    for table in CORE_TABLES:
        count = _table_count(conn, table) if table in present else 0
        statuses.append(
            ProjectFactTableStatus(
                name=table, present=table in present, row_count=count
            )
        )
    return statuses


def _table_count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _first_binary_id(conn: sqlite3.Connection, present: set[str]) -> int | None:
    if "binaries" not in present:
        return None
    row = conn.execute(
        "SELECT binary_id FROM binaries ORDER BY binary_id LIMIT 1"
    ).fetchone()
    return int(row[0]) if row else None


def _counts(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
) -> ProjectFactCounts:
    return ProjectFactCounts(
        binary_count=_count(conn, present, "binaries", None, None),
        function_name_count=_count(conn, present, "function_names", binary_id, None),
        xref_count=_count(conn, present, "xrefs", binary_id, None),
        call_xref_count=_count(conn, present, "xrefs", binary_id, "kind = 'call'"),
        jump_xref_count=_count(conn, present, "xrefs", binary_id, "kind = 'jump'"),
        data_read_xref_count=_count(
            conn, present, "xrefs", binary_id, "kind = 'data_read'"
        ),
        data_write_xref_count=_count(
            conn, present, "xrefs", binary_id, "kind = 'data_write'"
        ),
        data_label_count=_count(conn, present, "data_labels", binary_id, None),
        function_prototype_count=_count(
            conn,
            present,
            "function_prototypes",
            binary_id,
            None,
        ),
        stack_frame_var_count=_count(
            conn, present, "stack_frame_vars", binary_id, None
        ),
        comment_count=_count(conn, present, "comments", binary_id, None),
        basic_block_count=_count(conn, present, "basic_blocks", binary_id, None),
        cfg_edge_count=_count(conn, present, "cfg_edges", binary_id, None),
        cfg_dominance_count=_count(conn, present, "cfg_dominance", binary_id, None),
        cfg_branch_fact_count=_count(
            conn, present, "cfg_branch_facts", binary_id, None
        ),
        function_boundary_count=_count(
            conn,
            present,
            "function_boundaries",
            binary_id,
            None,
        ),
        function_chunk_fact_count=_count(
            conn,
            present,
            "function_chunk_facts",
            binary_id,
            None,
        ),
        memory_operand_fact_count=_count(
            conn,
            present,
            "memory_operand_facts",
            binary_id,
            None,
        ),
        sysinfo_dispatch_count=_count(
            conn,
            present,
            "windows_sysinfo_dispatch",
            binary_id,
            None,
        ),
        callsite_argument_fact_count=_count(
            conn,
            present,
            "callsite_argument_facts",
            binary_id,
            None,
        ),
        callsite_path_condition_count=_count(
            conn,
            present,
            "callsite_path_conditions",
            binary_id,
            None,
        ),
    )


def _count(
    conn: sqlite3.Connection,
    present: set[str],
    table: str,
    binary_id: int | None,
    extra_where: str | None,
) -> int:
    if table not in present:
        return 0
    clauses = []
    params: list[object] = []
    columns = _columns(conn, table)
    if binary_id is not None and "binary_id" in columns:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    if extra_where:
        clauses.append(extra_where)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return int(
        conn.execute(f"SELECT COUNT(*) FROM {table}{where}", params).fetchone()[0]
    )


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _function_facts(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectFactSummaryArgs,
) -> list[ProjectFunctionFact]:
    if "function_names" not in present or args.max_rows == 0:
        return []
    clauses = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    if args.function_va is not None:
        clauses.append("entry_va = ?")
        params.append(args.function_va)
    if args.function_name_contains:
        clauses.append("LOWER(canonical) LIKE ?")
        params.append(f"%{args.function_name_contains.lower()}%")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(args.max_rows)
    rows = conn.execute(
        "SELECT entry_va, canonical, demangled, flavor, set_by "
        f"FROM function_names{where} ORDER BY entry_va LIMIT ?",
        params,
    ).fetchall()
    return [
        ProjectFunctionFact(
            entry_va=int(row[0]),
            canonical=str(row[1]),
            demangled=row[2],
            flavor=row[3],
            set_by=row[4],
            call_out_count=_per_function_count(
                conn, present, binary_id, int(row[0]), "call"
            ),
            data_read_count=_per_function_count(
                conn,
                present,
                binary_id,
                int(row[0]),
                "data_read",
            ),
            data_write_count=_per_function_count(
                conn,
                present,
                binary_id,
                int(row[0]),
                "data_write",
            ),
            stack_var_count=_stack_var_count(conn, present, binary_id, int(row[0])),
            comment_count=_comment_count(conn, present, binary_id, int(row[0])),
        )
        for row in rows
    ]


def _per_function_count(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_va: int,
    kind: str,
) -> int:
    if "xrefs" not in present:
        return 0
    clauses = ["src_function_va = ?", "kind = ?"]
    params: list[object] = [function_va, kind]
    if binary_id is not None:
        clauses.insert(0, "binary_id = ?")
        params.insert(0, binary_id)
    where = " AND ".join(clauses)
    return int(
        conn.execute(f"SELECT COUNT(*) FROM xrefs WHERE {where}", params).fetchone()[0]
    )


def _stack_var_count(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_va: int,
) -> int:
    if "stack_frame_vars" not in present:
        return 0
    clauses = ["function_va = ?"]
    params: list[object] = [function_va]
    if binary_id is not None:
        clauses.insert(0, "binary_id = ?")
        params.insert(0, binary_id)
    return int(
        conn.execute(
            f"SELECT COUNT(*) FROM stack_frame_vars WHERE {' AND '.join(clauses)}",
            params,
        ).fetchone()[0]
    )


def _comment_count(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_va: int,
) -> int:
    if "comments" not in present:
        return 0
    clauses = ["va = ?"]
    params: list[object] = [function_va]
    if binary_id is not None:
        clauses.insert(0, "binary_id = ?")
        params.insert(0, binary_id)
    return int(
        conn.execute(
            f"SELECT COUNT(*) FROM comments WHERE {' AND '.join(clauses)}",
            params,
        ).fetchone()[0]
    )


def _xref_facts(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectFactSummaryArgs,
) -> list[ProjectXrefFact]:
    if "xrefs" not in present or args.max_rows == 0:
        return []
    clauses = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    if args.function_va is not None:
        clauses.append("src_function_va = ?")
        params.append(args.function_va)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(args.max_rows)
    rows = conn.execute(
        "SELECT src_va, dst_va, kind, src_function_va "
        f"FROM xrefs{where} ORDER BY src_va LIMIT ?",
        params,
    ).fetchall()
    return [
        ProjectXrefFact(
            src_va=int(row[0]),
            dst_va=int(row[1]),
            kind=str(row[2]),
            src_function_va=int(row[3]) if row[3] is not None else None,
        )
        for row in rows
    ]


def _coverage(counts: ProjectFactCounts, present: set[str]) -> list[str]:
    coverage: list[str] = []
    if counts.function_name_count:
        coverage.append("function_names")
    if counts.call_xref_count:
        coverage.append("call_xrefs")
    if counts.data_read_xref_count or counts.data_write_xref_count:
        coverage.append("data_xrefs")
    if counts.function_prototype_count:
        coverage.append("function_prototypes")
    if counts.stack_frame_var_count:
        coverage.append("stack_frame_vars")
    if counts.basic_block_count or counts.cfg_edge_count:
        coverage.append("cfg")
    if counts.cfg_dominance_count:
        coverage.append("cfg_dominance")
    if counts.cfg_branch_fact_count:
        coverage.append("branch_conditions")
    if counts.function_boundary_count:
        coverage.append("function_boundaries")
    if counts.function_chunk_fact_count:
        coverage.append("function_chunks")
    if counts.memory_operand_fact_count:
        coverage.append("memory_operand_facts")
    if counts.sysinfo_dispatch_count:
        coverage.append("sysinfo_dispatch")
    if counts.callsite_argument_fact_count:
        coverage.append("callsite_argument_facts")
    if counts.callsite_path_condition_count:
        coverage.append("callsite_path_conditions")
    if "xref_index_state" in present:
        coverage.append("callgraph_index_state")
    return coverage


def _missing_capabilities(counts: ProjectFactCounts, present: set[str]) -> list[str]:
    missing: list[str] = []
    if not counts.function_name_count:
        missing.append("function_names")
    if not counts.call_xref_count:
        missing.append("call_xrefs")
    if not (counts.data_read_xref_count or counts.data_write_xref_count):
        missing.append("data_xrefs")
    if not counts.function_prototype_count:
        missing.append("function_prototypes")
    if not counts.function_boundary_count:
        missing.append("function_boundaries")
    if not counts.function_chunk_fact_count:
        missing.append("function_chunks")
    if not counts.memory_operand_fact_count:
        missing.append("memory_operand_facts")
    if not (counts.basic_block_count or counts.cfg_edge_count):
        missing.append("persisted_cfg")
    elif not counts.cfg_dominance_count:
        missing.append("cfg_dominance")
    if (
        counts.basic_block_count or counts.cfg_edge_count
    ) and not counts.cfg_branch_fact_count:
        missing.append("branch_conditions")
    if not counts.sysinfo_dispatch_count:
        missing.append("sysinfo_dispatch")
    if not counts.callsite_argument_fact_count:
        missing.append("callsite_argument_facts")
    if not counts.callsite_path_condition_count:
        missing.append("callsite_path_conditions")
    if "basic_blocks" not in present and "cfg_edges" not in present:
        missing.append("cfg_tables")
    return missing


def build_tool() -> WindowsProjectFactSummaryTool:
    return WindowsProjectFactSummaryTool()
