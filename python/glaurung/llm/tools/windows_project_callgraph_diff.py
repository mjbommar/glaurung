from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


CallgraphDeltaStatus = Literal["added", "removed", "changed", "unchanged"]
CallgraphDiffKind = Literal["all", "call", "jump"]


class ProjectCallgraphEdgeSnapshot(BaseModel):
    edge_key: str
    kind: str
    caller_va: int | None = None
    caller: str | None = None
    caller_name: str | None = None
    caller_demangled: str | None = None
    callee_va: int
    callee: str
    callee_name: str | None = None
    callee_demangled: str | None = None
    callsite_vas: list[int] = Field(default_factory=list)
    callsites: list[str] = Field(default_factory=list)
    callsite_count: int = 0


class ProjectCallgraphDelta(BaseModel):
    edge_key: str
    status: CallgraphDeltaStatus
    kind: str
    caller_name: str | None = None
    callee_name: str | None = None
    before: ProjectCallgraphEdgeSnapshot | None = None
    after: ProjectCallgraphEdgeSnapshot | None = None
    changed_fields: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)
    review_priority: int = Field(ge=0)


class WindowsProjectCallgraphDiffArgs(BaseModel):
    before_project_path: str = Field(..., description="Pre-change .glaurung project.")
    after_project_path: str = Field(..., description="Post-change .glaurung project.")
    before_binary_id: int | None = Field(None, description="Optional before binary_id.")
    after_binary_id: int | None = Field(None, description="Optional after binary_id.")
    kind: CallgraphDiffKind = Field(
        "all",
        description="Compare calls, jumps, or both.",
    )
    function_name_contains: str | None = Field(
        None,
        description="Optional case-insensitive caller or callee name substring filter.",
    )
    target_name_contains: str | None = Field(
        None,
        description="Optional case-insensitive callee name substring filter.",
    )
    include_unchanged: bool = Field(
        False,
        description="If true, include unchanged callgraph edges.",
    )
    max_rows: int = Field(128, ge=0, le=4096)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact callgraph-diff evidence node.",
    )


class WindowsProjectCallgraphDiffResult(BaseModel):
    before_project_path: str
    after_project_path: str
    before_binary_id: int | None = None
    after_binary_id: int | None = None
    before_edge_count: int
    after_edge_count: int
    added_count: int
    removed_count: int
    changed_count: int
    unchanged_count: int
    returned_count: int
    deltas: list[ProjectCallgraphDelta]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectCallgraphDiffTool(
    MemoryTool[WindowsProjectCallgraphDiffArgs, WindowsProjectCallgraphDiffResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_callgraph_diff",
                description=(
                    "Compare persisted Windows project call/jump xrefs across "
                    "two .glaurung projects and report added, removed, or "
                    "moved caller-to-callee edges for patch/build diff triage."
                ),
                tags=("windows", "pe", "project", "patch", "diff", "callgraph"),
            ),
            WindowsProjectCallgraphDiffArgs,
            WindowsProjectCallgraphDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectCallgraphDiffArgs,
    ) -> WindowsProjectCallgraphDiffResult:
        before_path = Path(args.before_project_path).expanduser()
        after_path = Path(args.after_project_path).expanduser()
        if not before_path.exists():
            raise ValueError(f"{before_path}: before .glaurung project does not exist")
        if not after_path.exists():
            raise ValueError(f"{after_path}: after .glaurung project does not exist")

        before = _load_project_edges(
            before_path,
            binary_id=args.before_binary_id,
            kind=args.kind,
        )
        after = _load_project_edges(
            after_path,
            binary_id=args.after_binary_id,
            kind=args.kind,
        )
        deltas_all = _deltas(
            before.edges,
            after.edges,
            include_unchanged=args.include_unchanged,
            function_name_contains=args.function_name_contains,
            target_name_contains=args.target_name_contains,
        )
        counts = _counts(deltas_all)
        deltas = deltas_all[: args.max_rows] if args.max_rows else []
        result = WindowsProjectCallgraphDiffResult(
            before_project_path=str(before_path),
            after_project_path=str(after_path),
            before_binary_id=before.binary_id,
            after_binary_id=after.binary_id,
            before_edge_count=len(before.edges),
            after_edge_count=len(after.edges),
            added_count=counts["added"],
            removed_count=counts["removed"],
            changed_count=counts["changed"],
            unchanged_count=counts["unchanged"],
            returned_count=len(deltas),
            deltas=deltas,
            coverage=_coverage(before.tables, after.tables, deltas_all),
            missing_capabilities=_missing(before.tables, after.tables, deltas_all),
            notes=[
                "project callgraph diff is patch-triage metadata, not vulnerability evidence",
                "added or removed sink/helper calls should feed xref, argument, and gate review before promotion",
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_callgraph_diff",
                    props={
                        "before_project_path": result.before_project_path,
                        "after_project_path": result.after_project_path,
                        "changed_count": result.changed_count,
                        "added_count": result.added_count,
                        "removed_count": result.removed_count,
                    },
                )
            )
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": node.id})

        return result


class _ProjectEdges(BaseModel):
    path: str
    binary_id: int | None = None
    tables: set[str] = Field(default_factory=set)
    edges: dict[str, ProjectCallgraphEdgeSnapshot] = Field(default_factory=dict)


def _load_project_edges(
    path: Path,
    *,
    binary_id: int | None,
    kind: CallgraphDiffKind,
) -> _ProjectEdges:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = _present_tables(conn)
        selected_binary_id = (
            binary_id if binary_id is not None else _first_binary_id(conn, tables)
        )
        return _ProjectEdges(
            path=str(path),
            binary_id=selected_binary_id,
            tables=tables,
            edges=_load_edges(conn, tables, selected_binary_id, kind),
        )
    finally:
        conn.close()


def _present_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _first_binary_id(conn: sqlite3.Connection, tables: set[str]) -> int | None:
    if "binaries" not in tables:
        return None
    row = conn.execute(
        "SELECT binary_id FROM binaries ORDER BY binary_id LIMIT 1"
    ).fetchone()
    return int(row[0]) if row else None


def _load_edges(
    conn: sqlite3.Connection,
    tables: set[str],
    binary_id: int | None,
    kind: CallgraphDiffKind,
) -> dict[str, ProjectCallgraphEdgeSnapshot]:
    if "xrefs" not in tables:
        return {}
    clauses = ["x.kind IN ('call', 'jump')"]
    params: list[object] = []
    if kind != "all":
        clauses.append("x.kind = ?")
        params.append(kind)
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if "function_names" in tables:
        joins = """
LEFT JOIN function_names caller
  ON caller.binary_id = x.binary_id AND caller.entry_va = x.src_function_va
LEFT JOIN function_names callee
  ON callee.binary_id = x.binary_id AND callee.entry_va = x.dst_va
"""
        name_columns = (
            "caller.canonical, caller.demangled, callee.canonical, callee.demangled"
        )
    else:
        joins = ""
        name_columns = "NULL, NULL, NULL, NULL"
    rows = conn.execute(
        f"""
SELECT x.src_va, x.dst_va, x.kind, x.src_function_va, {name_columns}
FROM xrefs x
{joins}
WHERE {" AND ".join(clauses)}
ORDER BY x.kind, x.src_function_va, x.dst_va, x.src_va
LIMIT 1000000
""",
        params,
    ).fetchall()
    grouped: dict[str, ProjectCallgraphEdgeSnapshot] = {}
    for row in rows:
        callsite_va = int(row[0])
        callee_va = int(row[1])
        edge_kind = str(row[2])
        caller_va = int(row[3]) if row[3] is not None else callsite_va
        caller_name = str(row[4]) if row[4] is not None else None
        caller_demangled = str(row[5]) if row[5] is not None else None
        callee_name = str(row[6]) if row[6] is not None else None
        callee_demangled = str(row[7]) if row[7] is not None else None
        key = _edge_key(
            kind=edge_kind,
            caller_va=caller_va,
            caller_name=caller_name,
            callee_va=callee_va,
            callee_name=callee_name,
        )
        current = grouped.get(key)
        if current is None:
            current = ProjectCallgraphEdgeSnapshot(
                edge_key=key,
                kind=edge_kind,
                caller_va=caller_va,
                caller=hex(caller_va) if caller_va is not None else None,
                caller_name=caller_name,
                caller_demangled=caller_demangled,
                callee_va=callee_va,
                callee=hex(callee_va),
                callee_name=callee_name,
                callee_demangled=callee_demangled,
            )
            grouped[key] = current
        current.callsite_vas.append(callsite_va)
    for edge in grouped.values():
        edge.callsite_vas.sort()
        edge.callsites = [hex(value) for value in edge.callsite_vas]
        edge.callsite_count = len(edge.callsite_vas)
    return grouped


def _edge_key(
    *,
    kind: str,
    caller_va: int | None,
    caller_name: str | None,
    callee_va: int,
    callee_name: str | None,
) -> str:
    caller = f"name:{caller_name.lower()}" if caller_name else f"va:{caller_va:x}"
    callee = f"name:{callee_name.lower()}" if callee_name else f"va:{callee_va:x}"
    return f"{kind}:{caller}->{callee}"


def _deltas(
    before: dict[str, ProjectCallgraphEdgeSnapshot],
    after: dict[str, ProjectCallgraphEdgeSnapshot],
    *,
    include_unchanged: bool,
    function_name_contains: str | None,
    target_name_contains: str | None,
) -> list[ProjectCallgraphDelta]:
    function_needle = function_name_contains.lower() if function_name_contains else None
    target_needle = target_name_contains.lower() if target_name_contains else None
    out: list[ProjectCallgraphDelta] = []
    for key in sorted(set(before) | set(after)):
        old = before.get(key)
        new = after.get(key)
        status, changed = _status_and_changes(old, new)
        if status == "unchanged" and not include_unchanged:
            continue
        item = new or old
        if item is None:
            continue
        if function_needle and not _matches_function(item, function_needle):
            continue
        if target_needle and not _matches_target(item, target_needle):
            continue
        relevance = _security_relevance(status, changed, old, new)
        out.append(
            ProjectCallgraphDelta(
                edge_key=key,
                status=status,
                kind=item.kind,
                caller_name=item.caller_name,
                callee_name=item.callee_name,
                before=old,
                after=new,
                changed_fields=changed,
                reason_codes=_reason_codes(status, changed, relevance, item),
                security_relevance=relevance,
                review_priority=_priority(status, changed, relevance, item),
            )
        )
    return sorted(out, key=_sort_key)


def _status_and_changes(
    before: ProjectCallgraphEdgeSnapshot | None,
    after: ProjectCallgraphEdgeSnapshot | None,
) -> tuple[CallgraphDeltaStatus, list[str]]:
    if before is None and after is not None:
        return "added", ["edge"]
    if before is not None and after is None:
        return "removed", ["edge"]
    if before is None or after is None:
        return "unchanged", []
    changed: list[str] = []
    for field in (
        "kind",
        "caller_va",
        "caller_name",
        "callee_va",
        "callee_name",
        "callsite_count",
    ):
        if getattr(before, field) != getattr(after, field):
            changed.append(field)
    if before.callsite_vas != after.callsite_vas:
        changed.append("callsites")
    return ("changed" if changed else "unchanged"), changed


def _security_relevance(
    status: CallgraphDeltaStatus,
    changed: list[str],
    before: ProjectCallgraphEdgeSnapshot | None,
    after: ProjectCallgraphEdgeSnapshot | None,
) -> list[str]:
    edge = after or before
    relevance: list[str] = []
    if status in {"added", "removed"}:
        relevance.append(f"callgraph_edge_{status}")
    if "callsites" in changed or "callsite_count" in changed:
        relevance.append("callsite_delta")
    if edge is not None and edge.kind == "jump":
        relevance.append("jump_edge_delta")
    if edge is not None and _is_sink_like(edge.callee_name):
        relevance.append("sink_or_api_call_delta")
    return _dedupe(relevance)


def _reason_codes(
    status: CallgraphDeltaStatus,
    changed: list[str],
    relevance: list[str],
    edge: ProjectCallgraphEdgeSnapshot,
) -> list[str]:
    return _dedupe(
        [
            f"callgraph_{status}",
            f"xref_kind:{edge.kind}",
            *(f"changed_{field}" for field in changed if field != "edge"),
            *relevance,
        ]
    )


def _priority(
    status: CallgraphDeltaStatus,
    changed: list[str],
    relevance: list[str],
    edge: ProjectCallgraphEdgeSnapshot,
) -> int:
    priority = 42
    if status == "added":
        priority += 18
    if status == "removed":
        priority += 14
    if status == "changed":
        priority += 10
    if "sink_or_api_call_delta" in relevance:
        priority += 20
    if edge.kind == "jump":
        priority += 8
    if {"callsites", "callsite_count", "callee_va"} & set(changed):
        priority += 8
    return priority


def _matches_function(edge: ProjectCallgraphEdgeSnapshot, needle: str) -> bool:
    return (
        needle
        in " ".join(
            value
            for value in (
                edge.caller_name,
                edge.caller_demangled,
                edge.caller,
                edge.callee_name,
                edge.callee_demangled,
                edge.callee,
            )
            if value
        ).lower()
    )


def _matches_target(edge: ProjectCallgraphEdgeSnapshot, needle: str) -> bool:
    return (
        needle
        in " ".join(
            value
            for value in (
                edge.callee_name,
                edge.callee_demangled,
                edge.callee,
            )
            if value
        ).lower()
    )


def _is_sink_like(name: str | None) -> bool:
    if not name:
        return False
    short = name.rsplit("!", 1)[-1].lower()
    prefixes = (
        "zw",
        "nt",
        "rtl",
        "wdfrequest",
        "exallocate",
        "exfree",
        "mm",
        "ob",
        "ps",
        "io",
        "ke",
        "se",
        "probe",
    )
    exact = {
        "memcpy",
        "memmove",
        "strcpy",
        "strncpy",
        "sprintf",
        "snprintf",
        "copymemory",
        "probeforread",
        "probeforwrite",
    }
    return short in exact or short.startswith(prefixes)


def _counts(deltas: list[ProjectCallgraphDelta]) -> dict[str, int]:
    return {
        status: sum(1 for delta in deltas if delta.status == status)
        for status in ("added", "removed", "changed", "unchanged")
    }


def _coverage(
    before_tables: set[str],
    after_tables: set[str],
    deltas: list[ProjectCallgraphDelta],
) -> list[str]:
    coverage = _dedupe(
        [f"before:{table}" for table in sorted(before_tables)]
        + [f"after:{table}" for table in sorted(after_tables)]
    )
    if "xrefs" in before_tables or "xrefs" in after_tables:
        coverage.append("project_call_xrefs")
    if "function_names" in before_tables or "function_names" in after_tables:
        coverage.append("project_function_names")
    if deltas:
        coverage.append("callgraph_deltas")
    if any("sink_or_api_call_delta" in delta.security_relevance for delta in deltas):
        coverage.append("sink_or_api_call_deltas")
    return coverage


def _missing(
    before_tables: set[str],
    after_tables: set[str],
    deltas: list[ProjectCallgraphDelta],
) -> list[str]:
    missing: list[str] = []
    if "xrefs" not in before_tables:
        missing.append("before:xrefs")
    if "xrefs" not in after_tables:
        missing.append("after:xrefs")
    if "function_names" not in before_tables:
        missing.append("before:function_names")
    if "function_names" not in after_tables:
        missing.append("after:function_names")
    if not deltas:
        missing.append("callgraph_deltas")
    return missing


def _sort_key(delta: ProjectCallgraphDelta) -> tuple[int, str, str, str]:
    return (
        -delta.review_priority,
        delta.kind,
        delta.caller_name or "",
        delta.callee_name or delta.edge_key,
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsProjectCallgraphDiffTool:
    return WindowsProjectCallgraphDiffTool()
