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


ReachabilityMode = Literal["source_to_target", "upstream_to_target"]


class WindowsProjectCallgraphReachabilityArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    source_function_va: int | None = Field(
        None,
        description="Optional source function VA. If omitted, sample upstream paths.",
    )
    source_function_name: str | None = Field(
        None,
        description="Optional source function name when source_function_va is absent.",
    )
    target_function_va: int | None = Field(
        None,
        description="Target function/sink VA. Use this or target_function_name.",
    )
    target_function_name: str | None = Field(
        None,
        description="Target function/sink name when target_function_va is absent.",
    )
    include_jumps: bool = Field(
        False,
        description="If true, include persisted jump xrefs as callgraph edges.",
    )
    max_depth: int = Field(6, ge=0, le=32)
    max_edges: int = Field(50_000, ge=0, le=1_000_000)
    max_paths: int = Field(8, ge=0, le=256)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact reachability evidence node to the KB.",
    )


class ProjectReachabilityFunction(BaseModel):
    va: int
    address: str
    name: str | None = None
    demangled: str | None = None
    resolution: list[str] = Field(default_factory=list)


class ProjectReachabilityEdge(BaseModel):
    caller_va: int
    caller: str
    caller_name: str | None = None
    caller_demangled: str | None = None
    callsite_va: int
    callsite: str
    callee_va: int
    callee: str
    callee_name: str | None = None
    callee_demangled: str | None = None
    kind: str


class ProjectReachabilityPath(BaseModel):
    source: ProjectReachabilityFunction
    target: ProjectReachabilityFunction
    depth: int
    edges: list[ProjectReachabilityEdge]
    function_sequence: list[ProjectReachabilityFunction]
    stop_reason: str


class WindowsProjectCallgraphReachabilityResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    mode: ReachabilityMode
    source: ProjectReachabilityFunction | None = None
    target: ProjectReachabilityFunction | None = None
    reachable: bool
    path_count: int
    visited_function_count: int
    explored_edge_count: int
    truncated: bool = False
    paths: list[ProjectReachabilityPath] = Field(default_factory=list)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectCallgraphReachabilityTool(
    MemoryTool[
        WindowsProjectCallgraphReachabilityArgs,
        WindowsProjectCallgraphReachabilityResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_callgraph_reachability",
                description=(
                    "Find bounded source-to-target or upstream-to-target callgraph "
                    "paths from persisted .glaurung Windows PE call xrefs."
                ),
                tags=("windows", "pe", "project", "callgraph", "reachability"),
            ),
            WindowsProjectCallgraphReachabilityArgs,
            WindowsProjectCallgraphReachabilityResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectCallgraphReachabilityArgs,
    ) -> WindowsProjectCallgraphReachabilityResult:
        project_path = Path(args.project_path).expanduser()
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")
        if args.target_function_va is None and not args.target_function_name:
            raise ValueError("target_function_va or target_function_name is required")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            source = _resolve_function(
                conn,
                present,
                binary_id,
                args.source_function_va,
                args.source_function_name,
                role="source",
            )
            target = _resolve_function(
                conn,
                present,
                binary_id,
                args.target_function_va,
                args.target_function_name,
                role="target",
            )
            graph = _load_graph(conn, present, binary_id, args)
        finally:
            conn.close()

        mode: ReachabilityMode = (
            "source_to_target" if source is not None else "upstream_to_target"
        )
        if target is None:
            result = _empty_result(
                project_path, binary_id, mode, source, target, present
            )
        elif source is not None:
            result = _source_to_target(
                project_path, binary_id, source, target, graph, present, args
            )
        else:
            result = _upstream_to_target(
                project_path, binary_id, target, graph, present, args
            )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_callgraph_reachability",
                    props={
                        "project_path": result.project_path,
                        "binary_id": result.binary_id,
                        "mode": result.mode,
                        "source_va": result.source.va if result.source else None,
                        "target_va": result.target.va if result.target else None,
                        "reachable": result.reachable,
                        "path_count": result.path_count,
                        "truncated": result.truncated,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": evidence_node_id})

        return result


class _Graph(BaseModel):
    by_caller: dict[int, list[ProjectReachabilityEdge]] = Field(default_factory=dict)
    by_callee: dict[int, list[ProjectReachabilityEdge]] = Field(default_factory=dict)
    functions: dict[int, ProjectReachabilityFunction] = Field(default_factory=dict)
    edge_count: int = 0
    truncated: bool = False


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


def _resolve_function(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int | None,
    name: str | None,
    *,
    role: str,
) -> ProjectReachabilityFunction | None:
    if va is not None:
        found = _function_at_va(conn, present, binary_id, int(va), role)
        if found is not None:
            return found
        return ProjectReachabilityFunction(
            va=int(va),
            address=_hex(int(va)),
            resolution=[f"{role}_explicit_va"],
        )
    if name:
        return _function_by_name(conn, present, binary_id, name, role)
    return None


def _function_at_va(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    va: int,
    role: str,
) -> ProjectReachabilityFunction | None:
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
    return _function_ref(
        int(row[0]),
        row[1],
        row[2],
        [f"{role}_explicit_va", "function_names"],
    )


def _function_by_name(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    name: str,
    role: str,
) -> ProjectReachabilityFunction | None:
    if "function_names" not in present:
        return None
    needle = _short_symbol(name).lower()
    clauses = [
        "(LOWER(canonical) = ? OR LOWER(demangled) = ? "
        "OR LOWER(canonical) LIKE ? OR LOWER(demangled) LIKE ?)"
    ]
    params: list[object] = [name.lower(), name.lower(), f"%{needle}", f"%{needle}"]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        "SELECT entry_va, canonical, demangled FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY "
        "CASE WHEN canonical = ? OR demangled = ? THEN 0 ELSE 1 END, entry_va",
        (*params, name, name),
    ).fetchall()
    if not rows:
        return None
    exact = [row for row in rows if _symbol_exact(row, name)]
    selected = exact or rows
    if len(selected) > 1:
        raise ValueError(f"{role} function name {name!r} matched multiple functions")
    row = selected[0]
    return _function_ref(
        int(row[0]),
        row[1],
        row[2],
        [f"{role}_name", "function_names"],
    )


def _load_graph(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectCallgraphReachabilityArgs,
) -> _Graph:
    if "xrefs" not in present or args.max_edges == 0:
        return _Graph()
    kinds = ["call", "jump"] if args.include_jumps else ["call"]
    clauses = [
        "x.kind IN (" + ",".join("?" for _ in kinds) + ")",
        "x.src_function_va IS NOT NULL",
    ]
    params: list[object] = [*kinds]
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    params.append(args.max_edges + 1)
    fn_join = "function_names" in present
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
LEFT JOIN function_names caller
  ON caller.binary_id = x.binary_id AND caller.entry_va = x.src_function_va
LEFT JOIN function_names callee
  ON callee.binary_id = x.binary_id AND callee.entry_va = x.dst_va
"""
    rows = conn.execute(
        f"""
SELECT x.src_function_va, x.src_va, x.dst_va, x.kind,
       {caller_select}, {callee_select}
FROM xrefs x
{joins}
WHERE {" AND ".join(clauses)}
ORDER BY x.src_function_va, x.src_va, x.dst_va
LIMIT ?
""",
        params,
    ).fetchall()
    truncated = len(rows) > args.max_edges
    if truncated:
        rows = rows[: args.max_edges]
    by_caller: dict[int, list[ProjectReachabilityEdge]] = {}
    by_callee: dict[int, list[ProjectReachabilityEdge]] = {}
    functions: dict[int, ProjectReachabilityFunction] = {}
    for row in rows:
        caller_va = int(row[0])
        callsite_va = int(row[1])
        callee_va = int(row[2])
        edge = ProjectReachabilityEdge(
            caller_va=caller_va,
            caller=_hex(caller_va),
            caller_name=str(row[4]) if row[4] is not None else None,
            caller_demangled=str(row[5]) if row[5] is not None else None,
            callsite_va=callsite_va,
            callsite=_hex(callsite_va),
            callee_va=callee_va,
            callee=_hex(callee_va),
            callee_name=str(row[6]) if row[6] is not None else None,
            callee_demangled=str(row[7]) if row[7] is not None else None,
            kind=str(row[3]),
        )
        by_caller.setdefault(caller_va, []).append(edge)
        by_callee.setdefault(callee_va, []).append(edge)
        functions.setdefault(
            caller_va,
            _function_ref(caller_va, row[4], row[5], ["callgraph_edge"]),
        )
        functions.setdefault(
            callee_va,
            _function_ref(callee_va, row[6], row[7], ["callgraph_edge"]),
        )
    return _Graph(
        by_caller=by_caller,
        by_callee=by_callee,
        functions=functions,
        edge_count=len(rows),
        truncated=truncated,
    )


def _source_to_target(
    project_path: Path,
    binary_id: int | None,
    source: ProjectReachabilityFunction,
    target: ProjectReachabilityFunction,
    graph: _Graph,
    present: set[str],
    args: WindowsProjectCallgraphReachabilityArgs,
) -> WindowsProjectCallgraphReachabilityResult:
    paths: list[ProjectReachabilityPath] = []
    visited: set[int] = {source.va}
    explored = 0
    truncated = graph.truncated
    queue = deque([(source.va, [])])
    while queue and len(paths) < args.max_paths:
        current, path_edges = queue.popleft()
        if len(path_edges) > args.max_depth:
            truncated = True
            continue
        if current == target.va:
            paths.append(_path_from_edges(path_edges, graph, "target_reached"))
            continue
        if len(path_edges) == args.max_depth:
            continue
        for edge in graph.by_caller.get(current, []):
            explored += 1
            if edge.callee_va in {item.caller_va for item in path_edges}:
                continue
            next_path = [*path_edges, edge]
            if edge.callee_va == target.va:
                paths.append(_path_from_edges(next_path, graph, "target_reached"))
                if len(paths) >= args.max_paths:
                    break
                continue
            if edge.callee_va not in visited:
                visited.add(edge.callee_va)
                queue.append((edge.callee_va, next_path))
    if queue or len(paths) >= args.max_paths:
        truncated = truncated or bool(queue)
    stop_reasons = ["target_reached"] if paths else ["target_not_reached"]
    if graph.truncated:
        stop_reasons.append("edge_limit_reached")
    if truncated and "truncated" not in stop_reasons:
        stop_reasons.append("truncated")
    return _build_result(
        project_path,
        binary_id,
        "source_to_target",
        source,
        target,
        paths,
        len(visited),
        explored,
        truncated,
        stop_reasons,
        present,
        graph,
    )


def _upstream_to_target(
    project_path: Path,
    binary_id: int | None,
    target: ProjectReachabilityFunction,
    graph: _Graph,
    present: set[str],
    args: WindowsProjectCallgraphReachabilityArgs,
) -> WindowsProjectCallgraphReachabilityResult:
    paths: list[ProjectReachabilityPath] = []
    visited: set[int] = {target.va}
    explored = 0
    truncated = graph.truncated
    queue = deque([(target.va, [])])
    while queue and len(paths) < args.max_paths:
        current, reverse_edges = queue.popleft()
        incoming = graph.by_callee.get(current, [])
        if not incoming or len(reverse_edges) == args.max_depth:
            if reverse_edges:
                edges = list(reversed(reverse_edges))
                paths.append(_path_from_edges(edges, graph, "upstream_boundary"))
            continue
        for edge in incoming:
            explored += 1
            if edge.caller_va in {item.callee_va for item in reverse_edges}:
                continue
            visited.add(edge.caller_va)
            queue.append((edge.caller_va, [*reverse_edges, edge]))
    if queue or len(paths) >= args.max_paths:
        truncated = truncated or bool(queue)
    stop_reasons = ["upstream_paths_found"] if paths else ["no_upstream_callers"]
    if graph.truncated:
        stop_reasons.append("edge_limit_reached")
    if truncated and "truncated" not in stop_reasons:
        stop_reasons.append("truncated")
    return _build_result(
        project_path,
        binary_id,
        "upstream_to_target",
        None,
        target,
        paths,
        len(visited),
        explored,
        truncated,
        stop_reasons,
        present,
        graph,
    )


def _build_result(
    project_path: Path,
    binary_id: int | None,
    mode: ReachabilityMode,
    source: ProjectReachabilityFunction | None,
    target: ProjectReachabilityFunction,
    paths: list[ProjectReachabilityPath],
    visited_count: int,
    explored_count: int,
    truncated: bool,
    stop_reasons: list[str],
    present: set[str],
    graph: _Graph,
) -> WindowsProjectCallgraphReachabilityResult:
    return WindowsProjectCallgraphReachabilityResult(
        project_path=str(project_path),
        binary_id=binary_id,
        mode=mode,
        source=source,
        target=target,
        reachable=bool(paths),
        path_count=len(paths),
        visited_function_count=visited_count,
        explored_edge_count=explored_count,
        truncated=truncated,
        paths=paths,
        coverage=_coverage(present, graph, paths, source, target),
        missing_capabilities=_missing(present, graph, paths, source, target),
        stop_reasons=_dedupe(stop_reasons),
        notes=[
            "project callgraph reachability uses persisted call xrefs only",
            "path existence is topology evidence, not attacker reachability or value-flow proof",
        ],
    )


def _empty_result(
    project_path: Path,
    binary_id: int | None,
    mode: ReachabilityMode,
    source: ProjectReachabilityFunction | None,
    target: ProjectReachabilityFunction | None,
    present: set[str],
) -> WindowsProjectCallgraphReachabilityResult:
    return WindowsProjectCallgraphReachabilityResult(
        project_path=str(project_path),
        binary_id=binary_id,
        mode=mode,
        source=source,
        target=target,
        reachable=False,
        path_count=0,
        visited_function_count=0,
        explored_edge_count=0,
        coverage=[f"{table}_present" for table in sorted(present)],
        missing_capabilities=_table_missing(present) + ["target_resolution"],
        stop_reasons=["target_not_resolved"],
        notes=[
            "target function could not be resolved from the project",
            "path existence is topology evidence, not attacker reachability or value-flow proof",
        ],
    )


def _path_from_edges(
    edges: list[ProjectReachabilityEdge],
    graph: _Graph,
    stop_reason: str,
) -> ProjectReachabilityPath:
    if not edges:
        raise ValueError("reachability path requires at least one edge")
    sequence = [
        graph.functions.get(
            edges[0].caller_va,
            _function_ref(edges[0].caller_va, edges[0].caller_name, None, ["path"]),
        )
    ]
    for edge in edges:
        sequence.append(
            graph.functions.get(
                edge.callee_va,
                _function_ref(edge.callee_va, edge.callee_name, None, ["path"]),
            )
        )
    return ProjectReachabilityPath(
        source=sequence[0],
        target=sequence[-1],
        depth=len(edges),
        edges=edges,
        function_sequence=sequence,
        stop_reason=stop_reason,
    )


def _coverage(
    present: set[str],
    graph: _Graph,
    paths: list[ProjectReachabilityPath],
    source: ProjectReachabilityFunction | None,
    target: ProjectReachabilityFunction | None,
) -> list[str]:
    coverage: list[str] = []
    if "xrefs" in present:
        coverage.append("project_call_xrefs")
    if graph.edge_count:
        coverage.append("callgraph_edges")
    if "function_names" in present:
        coverage.append("function_names")
    if source and source.name:
        coverage.append("source_function_name")
    if target and target.name:
        coverage.append("target_function_name")
    if paths:
        coverage.append("callgraph_paths")
    return coverage


def _missing(
    present: set[str],
    graph: _Graph,
    paths: list[ProjectReachabilityPath],
    source: ProjectReachabilityFunction | None,
    target: ProjectReachabilityFunction | None,
) -> list[str]:
    missing = _table_missing(present)
    if source is None:
        missing.append("source_function")
    if target is None:
        missing.append("target_function")
    if graph.edge_count == 0:
        missing.append("project_call_xrefs")
    if not paths:
        missing.append("callgraph_path")
    missing.append("call_argument_operands")
    missing.append("interprocedural_value_flow")
    missing.append("attacker_source_reachability")
    return _dedupe(missing)


def _table_missing(present: set[str]) -> list[str]:
    required = {"xrefs", "function_names"}
    return [f"{table}_table" for table in sorted(required - present)]


def _function_ref(
    va: int,
    name: object | None,
    demangled: object | None,
    resolution: list[str],
) -> ProjectReachabilityFunction:
    return ProjectReachabilityFunction(
        va=va,
        address=_hex(va),
        name=str(name) if name is not None else None,
        demangled=str(demangled) if demangled is not None else None,
        resolution=resolution,
    )


def _symbol_exact(row: tuple, symbol: str) -> bool:
    values = [str(row[1])]
    if row[2] is not None:
        values.append(str(row[2]))
    for value in values:
        if value == symbol:
            return True
        if value.rsplit("!", 1)[-1] == symbol:
            return True
    return False


def _short_symbol(symbol: str) -> str:
    return symbol.rsplit("!", 1)[-1].rsplit("::", 1)[-1]


def _hex(va: int) -> str:
    return f"0x{va:x}"


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def build_tool() -> WindowsProjectCallgraphReachabilityTool:
    return WindowsProjectCallgraphReachabilityTool()
