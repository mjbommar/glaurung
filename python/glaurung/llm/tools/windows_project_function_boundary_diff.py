from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Callable, Literal, TypeVar

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


ProjectBoundaryDeltaStatus = Literal["added", "removed", "changed", "unchanged"]
ProjectBoundaryRecordKind = Literal["function_boundary", "function_chunk"]
T = TypeVar("T")


class ProjectFunctionBoundarySnapshot(BaseModel):
    binary_id: int | None = None
    entry_va: int
    entry: str
    end_va: int | None = None
    end: str | None = None
    size: int | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    name: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ProjectFunctionChunkSnapshot(BaseModel):
    binary_id: int | None = None
    identity_key: str | None = None
    owner_entry_va: int | None = None
    owner_entry: str | None = None
    chunk_start_va: int
    chunk_start: str
    chunk_end_va: int | None = None
    chunk_end: str | None = None
    chunk_size: int | None = None
    chunk_kind: str
    relation_kind: str
    target_va: int | None = None
    target: str | None = None
    target_name: str | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    name: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ProjectFunctionBoundaryDelta(BaseModel):
    record_kind: ProjectBoundaryRecordKind
    identity_key: str
    status: ProjectBoundaryDeltaStatus
    address_va: int
    address: str
    name: str | None = None
    before_boundary: ProjectFunctionBoundarySnapshot | None = None
    after_boundary: ProjectFunctionBoundarySnapshot | None = None
    before_chunk: ProjectFunctionChunkSnapshot | None = None
    after_chunk: ProjectFunctionChunkSnapshot | None = None
    changed_fields: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)
    review_priority: int = Field(ge=0)


class WindowsProjectFunctionBoundaryDiffArgs(BaseModel):
    before_project_path: str = Field(..., description="Pre-change .glaurung project.")
    after_project_path: str = Field(..., description="Post-change .glaurung project.")
    before_binary_id: int | None = Field(None, description="Optional before binary_id.")
    after_binary_id: int | None = Field(None, description="Optional after binary_id.")
    include_unchanged: bool = Field(
        False,
        description="If true, include unchanged boundaries and chunks.",
    )
    function_name_contains: str | None = Field(
        None,
        description="Optional case-insensitive function/chunk name substring filter.",
    )
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    max_rows: int = Field(128, ge=0, le=4096)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact boundary-diff evidence node.",
    )


class WindowsProjectFunctionBoundaryDiffResult(BaseModel):
    before_project_path: str
    after_project_path: str
    before_binary_id: int | None = None
    after_binary_id: int | None = None
    before_boundary_count: int
    after_boundary_count: int
    before_chunk_count: int
    after_chunk_count: int
    added_count: int
    removed_count: int
    changed_count: int
    unchanged_count: int
    returned_count: int
    deltas: list[ProjectFunctionBoundaryDelta]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectFunctionBoundaryDiffTool(
    MemoryTool[
        WindowsProjectFunctionBoundaryDiffArgs,
        WindowsProjectFunctionBoundaryDiffResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_function_boundary_diff",
                description=(
                    "Compare persisted function_boundaries and "
                    "function_chunk_facts across two .glaurung Windows projects "
                    "to find range, thunk, tailcall, funclet, and split-body drift."
                ),
                tags=("windows", "pe", "project", "patch", "diff", "boundaries"),
            ),
            WindowsProjectFunctionBoundaryDiffArgs,
            WindowsProjectFunctionBoundaryDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectFunctionBoundaryDiffArgs,
    ) -> WindowsProjectFunctionBoundaryDiffResult:
        before_path = Path(args.before_project_path).expanduser()
        after_path = Path(args.after_project_path).expanduser()
        if not before_path.exists():
            raise ValueError(f"{before_path}: before .glaurung project does not exist")
        if not after_path.exists():
            raise ValueError(f"{after_path}: after .glaurung project does not exist")

        before = _load_project_facts(
            before_path,
            binary_id=args.before_binary_id,
            min_confidence=args.min_confidence,
        )
        after = _load_project_facts(
            after_path,
            binary_id=args.after_binary_id,
            min_confidence=args.min_confidence,
        )
        deltas_all = _deltas(
            before,
            after,
            include_unchanged=args.include_unchanged,
            function_name_contains=args.function_name_contains,
        )
        counts = _counts(deltas_all)
        deltas = deltas_all[: args.max_rows] if args.max_rows else []
        coverage = _coverage(before, after, deltas_all)
        missing = _missing(before, after, deltas_all)

        result = WindowsProjectFunctionBoundaryDiffResult(
            before_project_path=str(before_path),
            after_project_path=str(after_path),
            before_binary_id=before.binary_id,
            after_binary_id=after.binary_id,
            before_boundary_count=len(before.boundaries),
            after_boundary_count=len(after.boundaries),
            before_chunk_count=len(before.chunks),
            after_chunk_count=len(after.chunks),
            added_count=counts["added"],
            removed_count=counts["removed"],
            changed_count=counts["changed"],
            unchanged_count=counts["unchanged"],
            returned_count=len(deltas),
            deltas=deltas,
            coverage=coverage,
            missing_capabilities=missing,
            notes=[
                "project boundary diff is functionization triage metadata, not vulnerability evidence",
                "range, thunk, tailcall, and funclet deltas should feed decompile and sink review",
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_function_boundary_diff",
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


class _ProjectFacts(BaseModel):
    path: str
    binary_id: int | None = None
    tables: set[str] = Field(default_factory=set)
    boundaries: dict[str, ProjectFunctionBoundarySnapshot] = Field(default_factory=dict)
    chunks: dict[str, ProjectFunctionChunkSnapshot] = Field(default_factory=dict)


def _load_project_facts(
    path: Path,
    *,
    binary_id: int | None,
    min_confidence: float,
) -> _ProjectFacts:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = _present_tables(conn)
        selected_binary_id = (
            binary_id if binary_id is not None else _first_binary_id(conn, tables)
        )
        return _ProjectFacts(
            path=str(path),
            binary_id=selected_binary_id,
            tables=tables,
            boundaries=_load_boundaries(
                conn, tables, selected_binary_id, min_confidence
            ),
            chunks=_load_chunks(conn, tables, selected_binary_id, min_confidence),
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


def _load_boundaries(
    conn: sqlite3.Connection,
    tables: set[str],
    binary_id: int | None,
    min_confidence: float,
) -> dict[str, ProjectFunctionBoundarySnapshot]:
    if "function_boundaries" not in tables:
        return {}
    clauses = ["confidence >= ?"]
    params: list[object] = [min_confidence]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        f"""
SELECT binary_id, entry_va, end_va, size, source, confidence, name, detail_json
FROM function_boundaries
WHERE {" AND ".join(clauses)}
ORDER BY entry_va, confidence DESC
""",
        params,
    )
    out: dict[str, ProjectFunctionBoundarySnapshot] = {}
    for row in rows.fetchall():
        item = ProjectFunctionBoundarySnapshot(
            binary_id=_optional_int(row[0]),
            entry_va=int(row[1]),
            entry=_hex(int(row[1])),
            end_va=_optional_int(row[2]),
            end=_hex(int(row[2])) if row[2] is not None else None,
            size=_optional_int(row[3]),
            source=str(row[4]),
            confidence=float(row[5]),
            name=_optional_str(row[6]),
            detail=_json_dict(row[7]),
        )
        out[_boundary_key(item)] = item
    return out


def _load_chunks(
    conn: sqlite3.Connection,
    tables: set[str],
    binary_id: int | None,
    min_confidence: float,
) -> dict[str, ProjectFunctionChunkSnapshot]:
    if "function_chunk_facts" not in tables:
        return {}
    clauses = ["confidence >= ?"]
    params: list[object] = [min_confidence]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        f"""
SELECT binary_id, identity_key, owner_entry_va, chunk_start_va, chunk_end_va,
       chunk_size, chunk_kind, relation_kind, target_va, target_name, source,
       confidence, name, detail_json
FROM function_chunk_facts
WHERE {" AND ".join(clauses)}
ORDER BY chunk_start_va, confidence DESC
""",
        params,
    )
    out: dict[str, ProjectFunctionChunkSnapshot] = {}
    for row in rows.fetchall():
        owner = _optional_int(row[2])
        start = int(row[3])
        end = _optional_int(row[4])
        target = _optional_int(row[8])
        item = ProjectFunctionChunkSnapshot(
            binary_id=_optional_int(row[0]),
            identity_key=_optional_str(row[1]),
            owner_entry_va=owner,
            owner_entry=_hex(owner) if owner is not None else None,
            chunk_start_va=start,
            chunk_start=_hex(start),
            chunk_end_va=end,
            chunk_end=_hex(end) if end is not None else None,
            chunk_size=_optional_int(row[5]),
            chunk_kind=str(row[6]),
            relation_kind=str(row[7]),
            target_va=target,
            target=_hex(target) if target is not None else None,
            target_name=_optional_str(row[9]),
            source=str(row[10]),
            confidence=float(row[11]),
            name=_optional_str(row[12]),
            detail=_json_dict(row[13]),
        )
        out[_chunk_key(item)] = item
    return out


def _deltas(
    before: _ProjectFacts,
    after: _ProjectFacts,
    *,
    include_unchanged: bool,
    function_name_contains: str | None,
) -> list[ProjectFunctionBoundaryDelta]:
    needle = function_name_contains.lower() if function_name_contains else None
    deltas: list[ProjectFunctionBoundaryDelta] = []
    for key in sorted(set(before.boundaries) | set(after.boundaries)):
        old = before.boundaries.get(key)
        new = after.boundaries.get(key)
        delta = _boundary_delta(key, old, new, include_unchanged)
        if delta is not None and _matches(delta, needle):
            deltas.append(delta)
    for key in sorted(set(before.chunks) | set(after.chunks)):
        old = before.chunks.get(key)
        new = after.chunks.get(key)
        delta = _chunk_delta(key, old, new, include_unchanged)
        if delta is not None and _matches(delta, needle):
            deltas.append(delta)
    return sorted(deltas, key=_sort_key)


def _boundary_delta(
    key: str,
    before: ProjectFunctionBoundarySnapshot | None,
    after: ProjectFunctionBoundarySnapshot | None,
    include_unchanged: bool,
) -> ProjectFunctionBoundaryDelta | None:
    status, changed = _status_and_changes(before, after, _boundary_changed_fields)
    if status == "unchanged" and not include_unchanged:
        return None
    item = after or before
    if item is None:
        return None
    relevance = _boundary_relevance(status, changed, before, after)
    reason_codes = _reason_codes("boundary", status, changed, relevance)
    return ProjectFunctionBoundaryDelta(
        record_kind="function_boundary",
        identity_key=key,
        status=status,
        address_va=item.entry_va,
        address=item.entry,
        name=item.name,
        before_boundary=before,
        after_boundary=after,
        changed_fields=changed,
        reason_codes=reason_codes,
        security_relevance=relevance,
        review_priority=_priority(status, relevance, changed),
    )


def _chunk_delta(
    key: str,
    before: ProjectFunctionChunkSnapshot | None,
    after: ProjectFunctionChunkSnapshot | None,
    include_unchanged: bool,
) -> ProjectFunctionBoundaryDelta | None:
    status, changed = _status_and_changes(before, after, _chunk_changed_fields)
    if status == "unchanged" and not include_unchanged:
        return None
    item = after or before
    if item is None:
        return None
    relevance = _chunk_relevance(status, changed, before, after)
    reason_codes = _reason_codes("chunk", status, changed, relevance)
    return ProjectFunctionBoundaryDelta(
        record_kind="function_chunk",
        identity_key=key,
        status=status,
        address_va=item.chunk_start_va,
        address=item.chunk_start,
        name=item.name or item.target_name,
        before_chunk=before,
        after_chunk=after,
        changed_fields=changed,
        reason_codes=reason_codes,
        security_relevance=relevance,
        review_priority=_priority(status, relevance, changed),
    )


def _status_and_changes(
    before: T | None,
    after: T | None,
    changed_fn: Callable[[T, T], list[str]],
) -> tuple[ProjectBoundaryDeltaStatus, list[str]]:
    if before is None and after is not None:
        return "added", ["record"]
    if before is not None and after is None:
        return "removed", ["record"]
    if before is None or after is None:
        return "unchanged", []
    changed = changed_fn(before, after)
    return ("changed" if changed else "unchanged"), changed


def _boundary_changed_fields(
    before: ProjectFunctionBoundarySnapshot,
    after: ProjectFunctionBoundarySnapshot,
) -> list[str]:
    changed: list[str] = []
    for field in ("entry_va", "end_va", "size", "source", "name", "detail"):
        if getattr(before, field) != getattr(after, field):
            changed.append(field)
    if abs(before.confidence - after.confidence) >= 0.01:
        changed.append("confidence")
    return changed


def _chunk_changed_fields(
    before: ProjectFunctionChunkSnapshot,
    after: ProjectFunctionChunkSnapshot,
) -> list[str]:
    changed: list[str] = []
    fields = (
        "owner_entry_va",
        "chunk_start_va",
        "chunk_end_va",
        "chunk_size",
        "chunk_kind",
        "relation_kind",
        "target_va",
        "target_name",
        "source",
        "name",
        "detail",
    )
    for field in fields:
        if getattr(before, field) != getattr(after, field):
            changed.append(field)
    if abs(before.confidence - after.confidence) >= 0.01:
        changed.append("confidence")
    return changed


def _boundary_relevance(
    status: ProjectBoundaryDeltaStatus,
    changed: list[str],
    before: ProjectFunctionBoundarySnapshot | None,
    after: ProjectFunctionBoundarySnapshot | None,
) -> list[str]:
    relevance: list[str] = []
    if status in {"added", "removed"}:
        relevance.append(f"function_boundary_{status}")
    if {"entry_va", "end_va", "size"} & set(changed):
        relevance.append("function_range_delta")
    if "source" in changed:
        relevance.append("boundary_source_delta")
    if "name" in changed:
        relevance.append("symbol_binding_delta")
    if _confidence_dropped(before, after):
        relevance.append("boundary_confidence_drop")
    return _dedupe(relevance)


def _chunk_relevance(
    status: ProjectBoundaryDeltaStatus,
    changed: list[str],
    before: ProjectFunctionChunkSnapshot | None,
    after: ProjectFunctionChunkSnapshot | None,
) -> list[str]:
    relevance: list[str] = []
    item = after or before
    kind = (item.chunk_kind if item else "").lower()
    relation = (item.relation_kind if item else "").lower()
    if status in {"added", "removed"}:
        relevance.append(f"function_chunk_{status}")
    if "thunk" in kind or "thunk" in relation:
        relevance.append("thunk_delta")
    if "tail" in kind or "tail" in relation:
        relevance.append("tailcall_or_shared_tail_delta")
    if "funclet" in kind or "exception" in kind:
        relevance.append("exception_funclet_delta")
    if "unwind" in kind or "unwind" in relation:
        relevance.append("unwind_chunk_delta")
    if "split" in kind or "body" in kind:
        relevance.append("split_body_delta")
    if {"owner_entry_va", "target_va", "target_name", "chunk_kind"} & set(changed):
        relevance.append("chunk_relation_delta")
    if _confidence_dropped(before, after):
        relevance.append("chunk_confidence_drop")
    return _dedupe(relevance)


def _confidence_dropped(
    before: ProjectFunctionBoundarySnapshot | ProjectFunctionChunkSnapshot | None,
    after: ProjectFunctionBoundarySnapshot | ProjectFunctionChunkSnapshot | None,
) -> bool:
    return (
        before is not None
        and after is not None
        and after.confidence < before.confidence
    )


def _reason_codes(
    prefix: str,
    status: ProjectBoundaryDeltaStatus,
    changed: list[str],
    relevance: list[str],
) -> list[str]:
    return _dedupe(
        [
            f"{prefix}_{status}",
            *(f"changed_{field}" for field in changed if field != "record"),
            *relevance,
        ]
    )


def _priority(
    status: ProjectBoundaryDeltaStatus,
    relevance: list[str],
    changed: list[str],
) -> int:
    priority = 40
    if status == "changed":
        priority += 18
    if status in {"added", "removed"}:
        priority += 14
    if relevance:
        priority += 18
    if any(
        "thunk" in item or "tail" in item or "funclet" in item for item in relevance
    ):
        priority += 10
    if any(field in {"entry_va", "end_va", "size", "target_va"} for field in changed):
        priority += 8
    return priority


def _matches(delta: ProjectFunctionBoundaryDelta, needle: str | None) -> bool:
    if not needle:
        return True
    haystack = " ".join(
        value
        for value in (
            delta.identity_key,
            delta.name,
            delta.before_boundary.name if delta.before_boundary else None,
            delta.after_boundary.name if delta.after_boundary else None,
            delta.before_chunk.name if delta.before_chunk else None,
            delta.after_chunk.name if delta.after_chunk else None,
            delta.before_chunk.target_name if delta.before_chunk else None,
            delta.after_chunk.target_name if delta.after_chunk else None,
        )
        if value
    ).lower()
    return needle in haystack


def _counts(deltas: list[ProjectFunctionBoundaryDelta]) -> dict[str, int]:
    return {
        status: sum(1 for delta in deltas if delta.status == status)
        for status in ("added", "removed", "changed", "unchanged")
    }


def _coverage(
    before: _ProjectFacts,
    after: _ProjectFacts,
    deltas: list[ProjectFunctionBoundaryDelta],
) -> list[str]:
    coverage: list[str] = []
    if before.boundaries or after.boundaries:
        coverage.append("function_boundaries")
    if before.chunks or after.chunks:
        coverage.append("function_chunk_facts")
    if any(delta.record_kind == "function_boundary" for delta in deltas):
        coverage.append("boundary_deltas")
    if any(delta.record_kind == "function_chunk" for delta in deltas):
        coverage.append("chunk_deltas")
    if any(
        "thunk_delta" in delta.security_relevance
        or "tailcall_or_shared_tail_delta" in delta.security_relevance
        for delta in deltas
    ):
        coverage.append("thunk_tailcall_deltas")
    if any("exception_funclet_delta" in delta.security_relevance for delta in deltas):
        coverage.append("funclet_deltas")
    return coverage


def _missing(
    before: _ProjectFacts,
    after: _ProjectFacts,
    deltas: list[ProjectFunctionBoundaryDelta],
) -> list[str]:
    missing: list[str] = []
    if not before.boundaries:
        missing.append("before_function_boundaries")
    if not after.boundaries:
        missing.append("after_function_boundaries")
    if not before.chunks:
        missing.append("before_function_chunk_facts")
    if not after.chunks:
        missing.append("after_function_chunk_facts")
    if before.boundaries and after.boundaries and not deltas:
        missing.append("boundary_or_chunk_deltas")
    return missing


def _sort_key(delta: ProjectFunctionBoundaryDelta) -> tuple[int, str, str]:
    return (-delta.review_priority, delta.record_kind, delta.identity_key)


def _boundary_key(item: ProjectFunctionBoundarySnapshot) -> str:
    if item.name:
        return f"boundary:name:{item.name.lower()}"
    return f"boundary:va:{item.entry_va:x}"


def _chunk_key(item: ProjectFunctionChunkSnapshot) -> str:
    if item.identity_key:
        return f"chunk:id:{item.identity_key}"
    if item.name:
        return f"chunk:name:{item.name.lower()}:{item.chunk_kind}:{item.relation_kind}"
    return (
        f"chunk:va:{item.owner_entry_va or 0:x}:{item.chunk_start_va:x}:"
        f"{item.chunk_kind}:{item.relation_kind}:{item.target_va or 0:x}"
    )


def _json_dict(raw: Any) -> dict[str, Any]:
    if raw in (None, ""):
        return {}
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return {"raw": str(raw)}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


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


def build_tool() -> WindowsProjectFunctionBoundaryDiffTool:
    return WindowsProjectFunctionBoundaryDiffTool()
