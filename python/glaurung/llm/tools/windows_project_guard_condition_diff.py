from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


GuardConditionDeltaStatus = Literal["added", "removed", "changed", "unchanged"]
GuardConditionRecordKind = Literal["branch_condition", "callsite_path_condition"]
GuardConditionRecordKindFilter = Literal[
    "all", "branch_condition", "callsite_path_condition"
]


class ProjectGuardConditionSnapshot(BaseModel):
    guard_key: str
    record_kind: GuardConditionRecordKind
    function_va: int | None = None
    function: str | None = None
    function_name: str | None = None
    function_demangled: str | None = None
    callsite_vas: list[int] = Field(default_factory=list)
    callsites: list[str] = Field(default_factory=list)
    branch_vas: list[int] = Field(default_factory=list)
    branches: list[str] = Field(default_factory=list)
    block_ids: list[str] = Field(default_factory=list)
    branch_mnemonic: str
    branch_operands: list[str] = Field(default_factory=list)
    compare_mnemonic: str | None = None
    compare_operands: list[str] = Field(default_factory=list)
    condition_kind: str
    condition_role: str | None = None
    target_block_ids: list[str] = Field(default_factory=list)
    fallthrough_block_ids: list[str] = Field(default_factory=list)
    min_distance_bytes: int | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)
    count: int = 1


class ProjectGuardConditionDelta(BaseModel):
    guard_key: str
    status: GuardConditionDeltaStatus
    record_kind: GuardConditionRecordKind
    function_name: str | None = None
    condition_role: str | None = None
    condition_kind: str
    before: ProjectGuardConditionSnapshot | None = None
    after: ProjectGuardConditionSnapshot | None = None
    changed_fields: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)
    review_priority: int = Field(ge=0)


class WindowsProjectGuardConditionDiffArgs(BaseModel):
    before_project_path: str = Field(..., description="Pre-change .glaurung project.")
    after_project_path: str = Field(..., description="Post-change .glaurung project.")
    before_binary_id: int | None = Field(None, description="Optional before binary_id.")
    after_binary_id: int | None = Field(None, description="Optional after binary_id.")
    record_kind: GuardConditionRecordKindFilter = "all"
    function_name_contains: str | None = Field(
        None,
        description="Optional case-insensitive function name substring filter.",
    )
    condition_role_contains: str | None = Field(
        None,
        description="Optional case-insensitive callsite path-condition role substring.",
    )
    condition_kind: str | None = Field(
        None,
        description="Optional condition kind filter.",
    )
    include_unchanged: bool = False
    max_rows: int = Field(128, ge=0, le=4096)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact guard-condition-diff evidence node.",
    )


class WindowsProjectGuardConditionDiffResult(BaseModel):
    before_project_path: str
    after_project_path: str
    before_binary_id: int | None = None
    after_binary_id: int | None = None
    before_guard_count: int
    after_guard_count: int
    added_count: int
    removed_count: int
    changed_count: int
    unchanged_count: int
    returned_count: int
    deltas: list[ProjectGuardConditionDelta]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectGuardConditionDiffTool(
    MemoryTool[
        WindowsProjectGuardConditionDiffArgs,
        WindowsProjectGuardConditionDiffResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_guard_condition_diff",
                description=(
                    "Compare persisted branch and callsite path-condition guards "
                    "across two .glaurung projects for Patch Tuesday style "
                    "guard/path-condition review."
                ),
                tags=("windows", "pe", "project", "patch", "diff", "guards"),
            ),
            WindowsProjectGuardConditionDiffArgs,
            WindowsProjectGuardConditionDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectGuardConditionDiffArgs,
    ) -> WindowsProjectGuardConditionDiffResult:
        before_path = Path(args.before_project_path).expanduser()
        after_path = Path(args.after_project_path).expanduser()
        if not before_path.exists():
            raise ValueError(f"{before_path}: before .glaurung project does not exist")
        if not after_path.exists():
            raise ValueError(f"{after_path}: after .glaurung project does not exist")

        before = _load_project_guards(
            before_path,
            binary_id=args.before_binary_id,
            record_kind=args.record_kind,
        )
        after = _load_project_guards(
            after_path,
            binary_id=args.after_binary_id,
            record_kind=args.record_kind,
        )
        deltas_all = _deltas(
            before.guards,
            after.guards,
            include_unchanged=args.include_unchanged,
            function_name_contains=args.function_name_contains,
            condition_role_contains=args.condition_role_contains,
            condition_kind=args.condition_kind,
        )
        counts = _counts(deltas_all)
        deltas = deltas_all[: args.max_rows] if args.max_rows else []
        result = WindowsProjectGuardConditionDiffResult(
            before_project_path=str(before_path),
            after_project_path=str(after_path),
            before_binary_id=before.binary_id,
            after_binary_id=after.binary_id,
            before_guard_count=len(before.guards),
            after_guard_count=len(after.guards),
            added_count=counts["added"],
            removed_count=counts["removed"],
            changed_count=counts["changed"],
            unchanged_count=counts["unchanged"],
            returned_count=len(deltas),
            deltas=deltas,
            coverage=_coverage(before.tables, after.tables, deltas_all),
            missing_capabilities=_missing(before.tables, after.tables, deltas_all),
            notes=[
                "project guard-condition diff is patch-triage metadata, not vulnerability evidence",
                "added or removed guards must be validated against path feasibility, argument flow, and sink semantics",
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_guard_condition_diff",
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


class _ProjectGuards(BaseModel):
    path: str
    binary_id: int | None = None
    tables: set[str] = Field(default_factory=set)
    guards: dict[str, ProjectGuardConditionSnapshot] = Field(default_factory=dict)


def _load_project_guards(
    path: Path,
    *,
    binary_id: int | None,
    record_kind: GuardConditionRecordKindFilter,
) -> _ProjectGuards:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = _present_tables(conn)
        selected_binary_id = (
            binary_id if binary_id is not None else _first_binary_id(conn, tables)
        )
        guards: dict[str, ProjectGuardConditionSnapshot] = {}
        if record_kind in {"all", "branch_condition"}:
            guards.update(_load_branch_guards(conn, tables, selected_binary_id))
        if record_kind in {"all", "callsite_path_condition"}:
            guards.update(_load_callsite_path_guards(conn, tables, selected_binary_id))
        return _ProjectGuards(
            path=str(path),
            binary_id=selected_binary_id,
            tables=tables,
            guards=guards,
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


def _load_branch_guards(
    conn: sqlite3.Connection,
    tables: set[str],
    binary_id: int | None,
) -> dict[str, ProjectGuardConditionSnapshot]:
    if "cfg_branch_facts" not in tables:
        return {}
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("b.binary_id = ?")
        params.append(binary_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    if "function_names" in tables:
        join = """
LEFT JOIN function_names fn
  ON fn.binary_id = b.binary_id AND fn.entry_va = b.function_va
"""
        name_columns = "fn.canonical, fn.demangled"
    else:
        join = ""
        name_columns = "NULL, NULL"
    rows = conn.execute(
        f"""
SELECT b.function_va, {name_columns}, b.block_id, b.branch_va,
       b.branch_mnemonic, b.branch_operands_json, b.compare_mnemonic,
       b.compare_operands_json, b.condition_kind, b.target_block_id,
       b.fallthrough_block_id
FROM cfg_branch_facts b
{join}
{where}
ORDER BY b.function_va, b.branch_va
LIMIT 200000
""",
        params,
    ).fetchall()
    out: dict[str, ProjectGuardConditionSnapshot] = {}
    for row in rows:
        function_va = int(row[0])
        function_name = str(row[1]) if row[1] is not None else None
        function_demangled = str(row[2]) if row[2] is not None else None
        compare_operands = _json_list(row[8])
        condition_kind = str(row[9])
        key = _guard_key(
            record_kind="branch_condition",
            function_va=function_va,
            function_name=function_name,
            condition_kind=condition_kind,
            condition_role=None,
            compare_operands=compare_operands,
            branch_mnemonic=str(row[5]),
        )
        item = out.get(key)
        if item is None:
            item = ProjectGuardConditionSnapshot(
                guard_key=key,
                record_kind="branch_condition",
                function_va=function_va,
                function=hex(function_va),
                function_name=function_name,
                function_demangled=function_demangled,
                branch_mnemonic=str(row[5]),
                branch_operands=_json_list(row[6]),
                compare_mnemonic=str(row[7]) if row[7] is not None else None,
                compare_operands=compare_operands,
                condition_kind=condition_kind,
                confidence=0.68,
                provenance=["cfg_branch_facts"],
            )
            out[key] = item
        _append_unique(item.branch_vas, int(row[4]))
        _append_unique(item.branches, hex(int(row[4])))
        _append_unique(item.block_ids, str(row[3]))
        if row[10] is not None:
            _append_unique(item.target_block_ids, str(row[10]))
        if row[11] is not None:
            _append_unique(item.fallthrough_block_ids, str(row[11]))
        item.count = len(item.branch_vas)
    return out


def _load_callsite_path_guards(
    conn: sqlite3.Connection,
    tables: set[str],
    binary_id: int | None,
) -> dict[str, ProjectGuardConditionSnapshot]:
    if "callsite_path_conditions" not in tables:
        return {}
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("p.binary_id = ?")
        params.append(binary_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    if "function_names" in tables:
        join = """
LEFT JOIN function_names fn
  ON fn.binary_id = p.binary_id AND fn.entry_va = p.caller_va
"""
        name_columns = "fn.canonical, fn.demangled"
    else:
        join = ""
        name_columns = "NULL, NULL"
    rows = conn.execute(
        f"""
SELECT p.caller_va, {name_columns}, p.callsite_va, p.block_id, p.branch_va,
       p.branch_mnemonic, p.branch_operands_json, p.compare_mnemonic,
       p.compare_operands_json, p.condition_kind, p.condition_role,
       p.target_block_id, p.fallthrough_block_id, p.distance_bytes,
       p.confidence, p.provenance_json
FROM callsite_path_conditions p
{join}
{where}
ORDER BY p.caller_va, p.callsite_va, p.branch_va
LIMIT 200000
""",
        params,
    ).fetchall()
    out: dict[str, ProjectGuardConditionSnapshot] = {}
    for row in rows:
        function_va = int(row[0]) if row[0] is not None else None
        function_name = str(row[1]) if row[1] is not None else None
        function_demangled = str(row[2]) if row[2] is not None else None
        compare_operands = _json_list(row[9])
        condition_kind = str(row[10])
        condition_role = str(row[11])
        key = _guard_key(
            record_kind="callsite_path_condition",
            function_va=function_va,
            function_name=function_name,
            condition_kind=condition_kind,
            condition_role=condition_role,
            compare_operands=compare_operands,
            branch_mnemonic=str(row[6]),
        )
        item = out.get(key)
        if item is None:
            item = ProjectGuardConditionSnapshot(
                guard_key=key,
                record_kind="callsite_path_condition",
                function_va=function_va,
                function=hex(function_va) if function_va is not None else None,
                function_name=function_name,
                function_demangled=function_demangled,
                branch_mnemonic=str(row[6]),
                branch_operands=_json_list(row[7]),
                compare_mnemonic=str(row[8]) if row[8] is not None else None,
                compare_operands=compare_operands,
                condition_kind=condition_kind,
                condition_role=condition_role,
                confidence=float(row[15]),
                provenance=_json_list(row[16]),
            )
            out[key] = item
        if row[12] is not None:
            _append_unique(item.target_block_ids, str(row[12]))
        _append_unique(item.callsite_vas, int(row[3]))
        _append_unique(item.callsites, hex(int(row[3])))
        _append_unique(item.branch_vas, int(row[5]))
        _append_unique(item.branches, hex(int(row[5])))
        _append_unique(item.block_ids, str(row[4]))
        if row[13] is not None:
            _append_unique(item.fallthrough_block_ids, str(row[13]))
        distance = int(row[14]) if row[14] is not None else None
        if distance is not None:
            item.min_distance_bytes = (
                distance
                if item.min_distance_bytes is None
                else min(item.min_distance_bytes, distance)
            )
        item.confidence = max(item.confidence, float(row[15]))
        item.provenance = _dedupe([*item.provenance, *_json_list(row[16])])
        item.count = len(item.branch_vas)
    return out


def _guard_key(
    *,
    record_kind: GuardConditionRecordKind,
    function_va: int | None,
    function_name: str | None,
    condition_kind: str,
    condition_role: str | None,
    compare_operands: list[str],
    branch_mnemonic: str,
) -> str:
    function = (
        f"name:{function_name.lower()}"
        if function_name
        else f"va:{function_va:x}"
        if function_va is not None
        else "function:unknown"
    )
    operands = ",".join(item.lower() for item in compare_operands) or "no_compare"
    role = condition_role.lower() if condition_role else "branch"
    return (
        f"{record_kind}:{function}:{role}:{condition_kind}:{branch_mnemonic}:{operands}"
    )


def _deltas(
    before: dict[str, ProjectGuardConditionSnapshot],
    after: dict[str, ProjectGuardConditionSnapshot],
    *,
    include_unchanged: bool,
    function_name_contains: str | None,
    condition_role_contains: str | None,
    condition_kind: str | None,
) -> list[ProjectGuardConditionDelta]:
    function_needle = function_name_contains.lower() if function_name_contains else None
    role_needle = condition_role_contains.lower() if condition_role_contains else None
    kind_needle = condition_kind.lower() if condition_kind else None
    out: list[ProjectGuardConditionDelta] = []
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
        if role_needle and role_needle not in (item.condition_role or "").lower():
            continue
        if kind_needle and item.condition_kind.lower() != kind_needle:
            continue
        relevance = _security_relevance(status, changed, old, new)
        out.append(
            ProjectGuardConditionDelta(
                guard_key=key,
                status=status,
                record_kind=item.record_kind,
                function_name=item.function_name,
                condition_role=item.condition_role,
                condition_kind=item.condition_kind,
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
    before: ProjectGuardConditionSnapshot | None,
    after: ProjectGuardConditionSnapshot | None,
) -> tuple[GuardConditionDeltaStatus, list[str]]:
    if before is None and after is not None:
        return "added", ["guard"]
    if before is not None and after is None:
        return "removed", ["guard"]
    if before is None or after is None:
        return "unchanged", []
    changed: list[str] = []
    for field in (
        "record_kind",
        "function_va",
        "function_name",
        "branch_mnemonic",
        "branch_operands",
        "compare_mnemonic",
        "compare_operands",
        "condition_kind",
        "condition_role",
        "target_block_ids",
        "fallthrough_block_ids",
        "min_distance_bytes",
        "count",
    ):
        if getattr(before, field) != getattr(after, field):
            changed.append(field)
    if before.callsite_vas != after.callsite_vas:
        changed.append("callsites")
    if before.branch_vas != after.branch_vas:
        changed.append("branches")
    if before.block_ids != after.block_ids:
        changed.append("blocks")
    if abs(before.confidence - after.confidence) >= 0.01:
        changed.append("confidence")
    return ("changed" if changed else "unchanged"), changed


def _security_relevance(
    status: GuardConditionDeltaStatus,
    changed: list[str],
    before: ProjectGuardConditionSnapshot | None,
    after: ProjectGuardConditionSnapshot | None,
) -> list[str]:
    guard = after or before
    relevance: list[str] = []
    if status == "added":
        relevance.append("guard_added")
    if status == "removed":
        relevance.append("guard_removed")
    if guard is not None:
        relevance.append(guard.record_kind)
        role_text = " ".join(
            [
                guard.condition_role or "",
                guard.condition_kind,
                " ".join(guard.compare_operands),
                " ".join(guard.branch_operands),
            ]
        ).lower()
        if _contains_any(role_text, ("length", "size", "count", "bounds", "range")):
            relevance.append("bounds_guard_delta")
        if _contains_any(role_text, ("status", "ntstatus", "success", "failure")):
            relevance.append("status_guard_delta")
        if _contains_any(role_text, ("mode", "previousmode", "requestormode", "user")):
            relevance.append("mode_or_user_guard_delta")
        if _contains_any(role_text, ("privilege", "access", "token", "security")):
            relevance.append("privilege_guard_delta")
        if _contains_any(role_text, ("null", "zero")):
            relevance.append("null_or_zero_guard_delta")
        if _contains_any(role_text, ("probe", "pointer", "buffer", "user")):
            relevance.append("user_pointer_guard_delta")
    if {"callsites", "branches", "blocks", "min_distance_bytes"} & set(changed):
        relevance.append("guard_location_delta")
    return _dedupe(relevance)


def _reason_codes(
    status: GuardConditionDeltaStatus,
    changed: list[str],
    relevance: list[str],
    guard: ProjectGuardConditionSnapshot,
) -> list[str]:
    return _dedupe(
        [
            f"guard_{status}",
            f"record_kind:{guard.record_kind}",
            f"condition_kind:{guard.condition_kind}",
            *(
                [f"condition_role:{guard.condition_role}"]
                if guard.condition_role
                else []
            ),
            *(f"changed_{field}" for field in changed if field != "guard"),
            *relevance,
        ]
    )


def _priority(
    status: GuardConditionDeltaStatus,
    changed: list[str],
    relevance: list[str],
    guard: ProjectGuardConditionSnapshot,
) -> int:
    priority = 42
    if status == "removed":
        priority += 20
    if status == "added":
        priority += 12
    if status == "changed":
        priority += 8
    if guard.record_kind == "callsite_path_condition":
        priority += 8
    if any(
        item in relevance
        for item in {
            "bounds_guard_delta",
            "mode_or_user_guard_delta",
            "privilege_guard_delta",
            "status_guard_delta",
            "user_pointer_guard_delta",
        }
    ):
        priority += 16
    if "guard_location_delta" in relevance:
        priority += 8
    return priority


def _matches_function(guard: ProjectGuardConditionSnapshot, needle: str) -> bool:
    return (
        needle
        in " ".join(
            value
            for value in (guard.function_name, guard.function_demangled, guard.function)
            if value
        ).lower()
    )


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _counts(deltas: list[ProjectGuardConditionDelta]) -> dict[str, int]:
    return {
        status: sum(1 for delta in deltas if delta.status == status)
        for status in ("added", "removed", "changed", "unchanged")
    }


def _coverage(
    before_tables: set[str],
    after_tables: set[str],
    deltas: list[ProjectGuardConditionDelta],
) -> list[str]:
    coverage = _dedupe(
        [f"before:{table}" for table in sorted(before_tables)]
        + [f"after:{table}" for table in sorted(after_tables)]
    )
    if "cfg_branch_facts" in before_tables or "cfg_branch_facts" in after_tables:
        coverage.append("branch_conditions")
    if (
        "callsite_path_conditions" in before_tables
        or "callsite_path_conditions" in after_tables
    ):
        coverage.append("callsite_path_conditions")
    if deltas:
        coverage.append("guard_condition_deltas")
    if any("guard_removed" in delta.security_relevance for delta in deltas):
        coverage.append("removed_guard_deltas")
    return coverage


def _missing(
    before_tables: set[str],
    after_tables: set[str],
    deltas: list[ProjectGuardConditionDelta],
) -> list[str]:
    missing: list[str] = []
    if "cfg_branch_facts" not in before_tables:
        missing.append("before:cfg_branch_facts")
    if "cfg_branch_facts" not in after_tables:
        missing.append("after:cfg_branch_facts")
    if "callsite_path_conditions" not in before_tables:
        missing.append("before:callsite_path_conditions")
    if "callsite_path_conditions" not in after_tables:
        missing.append("after:callsite_path_conditions")
    if not deltas:
        missing.append("guard_condition_deltas")
    return missing


def _sort_key(delta: ProjectGuardConditionDelta) -> tuple[int, str, str, str]:
    return (
        -delta.review_priority,
        delta.record_kind,
        delta.function_name or "",
        delta.guard_key,
    )


def _json_list(value: Any) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsProjectGuardConditionDiffTool:
    return WindowsProjectGuardConditionDiffTool()
