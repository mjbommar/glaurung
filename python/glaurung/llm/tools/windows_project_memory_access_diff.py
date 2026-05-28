from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


MemoryAccessDeltaStatus = Literal["added", "removed", "changed", "unchanged"]
MemoryAccessDiffKind = Literal["all", "reads", "writes", "read_write"]


class ProjectMemoryAccessSnapshot(BaseModel):
    access_key: str
    function_va: int
    function: str
    function_name: str | None = None
    instruction_vas: list[int] = Field(default_factory=list)
    instructions: list[str] = Field(default_factory=list)
    instruction_texts: list[str] = Field(default_factory=list)
    mnemonics: list[str] = Field(default_factory=list)
    operand_texts: list[str] = Field(default_factory=list)
    access_kind: str
    width_bytes: int | None = None
    address_expressions: list[str] = Field(default_factory=list)
    role_hint: str
    base_object: str | None = None
    base_object_kind: str | None = None
    base_object_type: str | None = None
    base_object_role: str | None = None
    field_offset: int
    likely_field_name: str | None = None
    likely_type_name: str | None = None
    data_target_va: int | None = None
    data_target: str | None = None
    data_target_kind: str | None = None
    data_target_name: str | None = None
    data_target_type: str | None = None
    data_target_size: int | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    count: int = 1


class ProjectMemoryAccessDelta(BaseModel):
    access_key: str
    status: MemoryAccessDeltaStatus
    access_kind: str
    function_name: str | None = None
    base_object_kind: str | None = None
    likely_field_name: str | None = None
    likely_type_name: str | None = None
    data_target_name: str | None = None
    before: ProjectMemoryAccessSnapshot | None = None
    after: ProjectMemoryAccessSnapshot | None = None
    changed_fields: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)
    review_priority: int = Field(ge=0)


class WindowsProjectMemoryAccessDiffArgs(BaseModel):
    before_project_path: str = Field(..., description="Pre-change .glaurung project.")
    after_project_path: str = Field(..., description="Post-change .glaurung project.")
    before_binary_id: int | None = Field(None, description="Optional before binary_id.")
    after_binary_id: int | None = Field(None, description="Optional after binary_id.")
    query: MemoryAccessDiffKind = Field(
        "all",
        description="Compare all accesses, reads, writes, or read_write rows.",
    )
    function_name_contains: str | None = None
    base_object_kind: str | None = None
    base_object_contains: str | None = None
    role_hint: str | None = None
    likely_type_name: str | None = None
    likely_field_name: str | None = None
    field_offset: int | None = None
    data_target_name_contains: str | None = None
    include_unchanged: bool = False
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    max_rows: int = Field(128, ge=0, le=4096)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact memory-access-diff evidence node.",
    )


class WindowsProjectMemoryAccessDiffResult(BaseModel):
    before_project_path: str
    after_project_path: str
    before_binary_id: int | None = None
    after_binary_id: int | None = None
    before_access_count: int
    after_access_count: int
    added_count: int
    removed_count: int
    changed_count: int
    unchanged_count: int
    returned_count: int
    deltas: list[ProjectMemoryAccessDelta]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectMemoryAccessDiffTool(
    MemoryTool[WindowsProjectMemoryAccessDiffArgs, WindowsProjectMemoryAccessDiffResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_memory_access_diff",
                description=(
                    "Compare persisted Windows memory_operand_facts across two "
                    ".glaurung projects and report changed field/global/buffer "
                    "read/write facts for patch/build diff triage."
                ),
                tags=("windows", "pe", "project", "patch", "diff", "memory"),
            ),
            WindowsProjectMemoryAccessDiffArgs,
            WindowsProjectMemoryAccessDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectMemoryAccessDiffArgs,
    ) -> WindowsProjectMemoryAccessDiffResult:
        before_path = Path(args.before_project_path).expanduser()
        after_path = Path(args.after_project_path).expanduser()
        if not before_path.exists():
            raise ValueError(f"{before_path}: before .glaurung project does not exist")
        if not after_path.exists():
            raise ValueError(f"{after_path}: after .glaurung project does not exist")

        before = _load_project_accesses(
            before_path,
            binary_id=args.before_binary_id,
            args=args,
        )
        after = _load_project_accesses(
            after_path,
            binary_id=args.after_binary_id,
            args=args,
        )
        deltas_all = _deltas(
            before.accesses,
            after.accesses,
            include_unchanged=args.include_unchanged,
            args=args,
        )
        counts = _counts(deltas_all)
        deltas = deltas_all[: args.max_rows] if args.max_rows else []

        result = WindowsProjectMemoryAccessDiffResult(
            before_project_path=str(before_path),
            after_project_path=str(after_path),
            before_binary_id=before.binary_id,
            after_binary_id=after.binary_id,
            before_access_count=len(before.accesses),
            after_access_count=len(after.accesses),
            added_count=counts["added"],
            removed_count=counts["removed"],
            changed_count=counts["changed"],
            unchanged_count=counts["unchanged"],
            returned_count=len(deltas),
            deltas=deltas,
            coverage=_coverage(before.tables, after.tables, deltas_all),
            missing_capabilities=_missing(before.tables, after.tables, deltas_all),
            notes=[
                "project memory-access diff is patch-triage metadata, not vulnerability evidence",
                "memory deltas are instruction-level facts; aliasing, path feasibility, and source control still require separate review",
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_memory_access_diff",
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


class _ProjectMemoryAccesses(BaseModel):
    path: str
    binary_id: int | None = None
    tables: set[str] = Field(default_factory=set)
    accesses: dict[str, ProjectMemoryAccessSnapshot] = Field(default_factory=dict)


def _load_project_accesses(
    path: Path,
    *,
    binary_id: int | None,
    args: WindowsProjectMemoryAccessDiffArgs,
) -> _ProjectMemoryAccesses:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = _present_tables(conn)
        selected_binary_id = (
            binary_id if binary_id is not None else _first_binary_id(conn, tables)
        )
        return _ProjectMemoryAccesses(
            path=str(path),
            binary_id=selected_binary_id,
            tables=tables,
            accesses=_load_accesses(conn, tables, selected_binary_id, args),
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


def _load_accesses(
    conn: sqlite3.Connection,
    tables: set[str],
    binary_id: int | None,
    args: WindowsProjectMemoryAccessDiffArgs,
) -> dict[str, ProjectMemoryAccessSnapshot]:
    if "memory_operand_facts" not in tables:
        return {}
    join = ""
    function_name_expr = "m.function_name"
    if "function_names" in tables:
        join = """
LEFT JOIN function_names fn
  ON fn.binary_id = m.binary_id AND fn.entry_va = m.function_va
"""
        function_name_expr = "COALESCE(m.function_name, fn.canonical)"
    clauses = ["m.confidence >= ?"]
    params: list[object] = [args.min_confidence]
    if binary_id is not None:
        clauses.append("m.binary_id = ?")
        params.append(binary_id)
    if args.query == "reads":
        clauses.append("m.access_kind IN ('read', 'read_write')")
    elif args.query == "writes":
        clauses.append("m.access_kind IN ('write', 'read_write')")
    elif args.query == "read_write":
        clauses.append("m.access_kind = 'read_write'")
    if args.base_object_kind:
        clauses.append("m.base_object_kind = ?")
        params.append(args.base_object_kind)
    if args.role_hint:
        clauses.append("m.role_hint = ?")
        params.append(args.role_hint)
    if args.likely_type_name:
        clauses.append("m.likely_type_name = ?")
        params.append(args.likely_type_name)
    if args.likely_field_name:
        clauses.append("m.likely_field_name = ?")
        params.append(args.likely_field_name)
    if args.field_offset is not None:
        clauses.append("m.field_offset = ?")
        params.append(args.field_offset)
    if args.base_object_contains:
        clauses.append("LOWER(COALESCE(m.base_object, '')) LIKE ?")
        params.append(f"%{args.base_object_contains.lower()}%")
    if args.data_target_name_contains:
        clauses.append("LOWER(COALESCE(m.data_target_name, '')) LIKE ?")
        params.append(f"%{args.data_target_name_contains.lower()}%")
    if args.function_name_contains:
        clauses.append(f"LOWER(COALESCE({function_name_expr}, '')) LIKE ?")
        params.append(f"%{args.function_name_contains.lower()}%")
    rows = conn.execute(
        f"""
SELECT m.function_va, {function_name_expr} AS function_name, m.instruction_va,
       m.instruction_text, m.mnemonic, m.operand_index, m.operand_text,
       m.access_kind, m.width_bytes, m.address_expression, m.base_register,
       m.index_register, m.scale, m.displacement, m.role_hint, m.base_object,
       m.base_object_kind, m.base_object_type, m.base_object_role, m.field_offset,
       m.likely_field_name, m.likely_type_name, m.data_target_va,
       m.data_target_kind, m.data_target_name, m.data_target_type,
       m.data_target_size, m.confidence
FROM memory_operand_facts m
{join}
WHERE {" AND ".join(clauses)}
ORDER BY m.function_va, m.instruction_va, m.operand_index
LIMIT 1000000
""",
        params,
    ).fetchall()
    grouped: dict[str, ProjectMemoryAccessSnapshot] = {}
    for row in rows:
        function_va = int(row[0])
        function_name = _optional_str(row[1])
        access_kind = str(row[7])
        width_bytes = _optional_int(row[8])
        role_hint = str(row[14])
        base_object = _optional_str(row[15])
        base_object_kind = _optional_str(row[16])
        field_offset = int(row[19] or 0)
        likely_field_name = _optional_str(row[20])
        likely_type_name = _optional_str(row[21])
        data_target_va = _optional_int(row[22])
        data_target_name = _optional_str(row[24])
        key = _access_key(
            function_va=function_va,
            function_name=function_name,
            access_kind=access_kind,
            role_hint=role_hint,
            base_object=base_object,
            base_object_kind=base_object_kind,
            field_offset=field_offset,
            data_target_va=data_target_va,
            data_target_name=data_target_name,
        )
        item = grouped.get(key)
        if item is None:
            item = ProjectMemoryAccessSnapshot(
                access_key=key,
                function_va=function_va,
                function=hex(function_va),
                function_name=function_name,
                access_kind=access_kind,
                width_bytes=width_bytes,
                role_hint=role_hint,
                base_object=base_object,
                base_object_kind=base_object_kind,
                base_object_type=_optional_str(row[17]),
                base_object_role=_optional_str(row[18]),
                field_offset=field_offset,
                likely_field_name=likely_field_name,
                likely_type_name=likely_type_name,
                data_target_va=data_target_va,
                data_target=hex(data_target_va) if data_target_va is not None else None,
                data_target_kind=_optional_str(row[23]),
                data_target_name=data_target_name,
                data_target_type=_optional_str(row[25]),
                data_target_size=_optional_int(row[26]),
                confidence=float(row[27]),
            )
            grouped[key] = item
        _append_unique(item.instruction_vas, int(row[2]))
        _append_unique(item.instructions, hex(int(row[2])))
        _append_unique(item.instruction_texts, str(row[3]))
        _append_unique(item.mnemonics, str(row[4]))
        _append_unique(item.operand_texts, str(row[6]))
        _append_unique(item.address_expressions, str(row[9]))
        item.confidence = max(item.confidence, float(row[27]))
        item.count = len(item.instruction_vas)
    return grouped


def _access_key(
    *,
    function_va: int,
    function_name: str | None,
    access_kind: str,
    role_hint: str,
    base_object: str | None,
    base_object_kind: str | None,
    field_offset: int,
    data_target_va: int | None,
    data_target_name: str | None,
) -> str:
    function = (
        f"name:{function_name.lower()}" if function_name else f"va:{function_va:x}"
    )
    base = ":".join(
        [
            base_object_kind.lower() if base_object_kind else "base_unknown",
            _norm(base_object) or "object_unknown",
        ]
    )
    target = (
        f"name:{data_target_name.lower()}"
        if data_target_name
        else f"va:{data_target_va:x}"
        if data_target_va is not None
        else "target_unknown"
    )
    return (
        f"{function}:{access_kind}:{role_hint.lower()}:"
        f"{base}:off:{field_offset:x}:{target}"
    )


def _deltas(
    before: dict[str, ProjectMemoryAccessSnapshot],
    after: dict[str, ProjectMemoryAccessSnapshot],
    *,
    include_unchanged: bool,
    args: WindowsProjectMemoryAccessDiffArgs,
) -> list[ProjectMemoryAccessDelta]:
    out: list[ProjectMemoryAccessDelta] = []
    for key in sorted(set(before) | set(after)):
        old = before.get(key)
        new = after.get(key)
        status, changed = _status_and_changes(old, new)
        if status == "unchanged" and not include_unchanged:
            continue
        item = new or old
        if item is None:
            continue
        if not _matches_filters(item, args):
            continue
        relevance = _security_relevance(status, changed, old, new)
        out.append(
            ProjectMemoryAccessDelta(
                access_key=key,
                status=status,
                access_kind=item.access_kind,
                function_name=item.function_name,
                base_object_kind=item.base_object_kind,
                likely_field_name=item.likely_field_name,
                likely_type_name=item.likely_type_name,
                data_target_name=item.data_target_name,
                before=old,
                after=new,
                changed_fields=changed,
                reason_codes=_reason_codes(status, changed, relevance, item),
                security_relevance=relevance,
                review_priority=_priority(status, changed, relevance, item),
            )
        )
    return sorted(out, key=_sort_key)


def _matches_filters(
    item: ProjectMemoryAccessSnapshot,
    args: WindowsProjectMemoryAccessDiffArgs,
) -> bool:
    if args.function_name_contains:
        needle = args.function_name_contains.lower()
        if (
            needle
            not in " ".join(
                value for value in (item.function_name, item.function) if value
            ).lower()
        ):
            return False
    if args.base_object_contains:
        needle = args.base_object_contains.lower()
        if needle not in (item.base_object or "").lower():
            return False
    if args.data_target_name_contains:
        needle = args.data_target_name_contains.lower()
        if (
            needle
            not in " ".join(
                value for value in (item.data_target_name, item.data_target) if value
            ).lower()
        ):
            return False
    return True


def _status_and_changes(
    before: ProjectMemoryAccessSnapshot | None,
    after: ProjectMemoryAccessSnapshot | None,
) -> tuple[MemoryAccessDeltaStatus, list[str]]:
    if before is None and after is not None:
        return "added", ["access"]
    if before is not None and after is None:
        return "removed", ["access"]
    if before is None or after is None:
        return "unchanged", []
    changed: list[str] = []
    for field in (
        "function_va",
        "function_name",
        "access_kind",
        "width_bytes",
        "role_hint",
        "base_object",
        "base_object_kind",
        "base_object_type",
        "base_object_role",
        "field_offset",
        "likely_field_name",
        "likely_type_name",
        "data_target_va",
        "data_target_kind",
        "data_target_name",
        "data_target_type",
        "data_target_size",
        "count",
    ):
        if getattr(before, field) != getattr(after, field):
            changed.append(field)
    for field in (
        "instruction_vas",
        "instruction_texts",
        "mnemonics",
        "operand_texts",
        "address_expressions",
    ):
        if getattr(before, field) != getattr(after, field):
            changed.append(field.replace("_vas", "s"))
    if abs(before.confidence - after.confidence) >= 0.01:
        changed.append("confidence")
    return ("changed" if changed else "unchanged"), changed


def _security_relevance(
    status: MemoryAccessDeltaStatus,
    changed: list[str],
    before: ProjectMemoryAccessSnapshot | None,
    after: ProjectMemoryAccessSnapshot | None,
) -> list[str]:
    access = after or before
    relevance: list[str] = []
    if status == "added":
        relevance.append("memory_access_added")
    if status == "removed":
        relevance.append("memory_access_removed")
    if access is None:
        return relevance
    if access.access_kind in {"write", "read_write"}:
        relevance.append("memory_write_delta")
    if access.access_kind in {"read", "read_write"}:
        relevance.append("memory_read_delta")
    if access.base_object_kind:
        relevance.append(f"base_object:{access.base_object_kind}")
    if access.likely_field_name or access.field_offset:
        relevance.append("field_access_delta")
    if access.data_target_va is not None or access.data_target_name:
        relevance.append("data_target_delta")
    if "width_bytes" in changed:
        relevance.append("memory_width_delta")
    if "instructions" in changed or "instruction_texts" in changed:
        relevance.append("memory_location_delta")
    if {"base_object", "base_object_kind", "base_object_type"} & set(changed):
        relevance.append("base_object_delta")
    if {"likely_field_name", "likely_type_name", "field_offset"} & set(changed):
        relevance.append("field_identity_delta")
    if {"data_target_va", "data_target_name", "data_target_type"} & set(changed):
        relevance.append("data_target_identity_delta")
    text = " ".join(
        value
        for value in (
            access.role_hint,
            access.base_object or "",
            access.base_object_kind or "",
            access.base_object_type or "",
            access.base_object_role or "",
            access.likely_field_name or "",
            access.likely_type_name or "",
            access.data_target_name or "",
            access.data_target_type or "",
            " ".join(access.operand_texts),
        )
        if value
    ).lower()
    if _contains_any(text, ("user", "requestor", "probe", "buffer", "mdl", "irp")):
        relevance.append("user_or_request_memory_delta")
    if _contains_any(text, ("length", "size", "count", "bounds", "range")):
        relevance.append("length_or_bounds_memory_delta")
    if _contains_any(text, ("status", "ntstatus", "success", "failure")):
        relevance.append("status_memory_delta")
    if _contains_any(text, ("function", "callback", "dispatch", "vtable", "handler")):
        relevance.append("function_pointer_memory_delta")
    return _dedupe(relevance)


def _reason_codes(
    status: MemoryAccessDeltaStatus,
    changed: list[str],
    relevance: list[str],
    access: ProjectMemoryAccessSnapshot,
) -> list[str]:
    return _dedupe(
        [
            f"memory_access_{status}",
            f"access_kind:{access.access_kind}",
            f"role_hint:{access.role_hint}",
            *(
                [f"base_object_kind:{access.base_object_kind}"]
                if access.base_object_kind
                else []
            ),
            *(
                [f"field:{access.likely_type_name}.{access.likely_field_name}"]
                if access.likely_type_name and access.likely_field_name
                else []
            ),
            *(f"changed_{field}" for field in changed if field != "access"),
            *relevance,
        ]
    )


def _priority(
    status: MemoryAccessDeltaStatus,
    changed: list[str],
    relevance: list[str],
    access: ProjectMemoryAccessSnapshot,
) -> int:
    priority = 42
    if status == "added":
        priority += 12
    if status == "removed":
        priority += 14
    if status == "changed":
        priority += 8
    if access.access_kind in {"write", "read_write"}:
        priority += 12
    if any(
        item in relevance
        for item in {
            "user_or_request_memory_delta",
            "length_or_bounds_memory_delta",
            "function_pointer_memory_delta",
            "data_target_identity_delta",
            "memory_width_delta",
        }
    ):
        priority += 16
    if "memory_location_delta" in relevance:
        priority += 8
    if {"width_bytes", "field_offset", "data_target_va"} & set(changed):
        priority += 8
    return priority


def _counts(deltas: list[ProjectMemoryAccessDelta]) -> dict[str, int]:
    return {
        status: sum(1 for delta in deltas if delta.status == status)
        for status in ("added", "removed", "changed", "unchanged")
    }


def _coverage(
    before_tables: set[str],
    after_tables: set[str],
    deltas: list[ProjectMemoryAccessDelta],
) -> list[str]:
    coverage = _dedupe(
        [f"before:{table}" for table in sorted(before_tables)]
        + [f"after:{table}" for table in sorted(after_tables)]
    )
    if (
        "memory_operand_facts" in before_tables
        or "memory_operand_facts" in after_tables
    ):
        coverage.append("memory_operand_facts")
    if deltas:
        coverage.append("memory_access_deltas")
    if any("memory_write_delta" in delta.security_relevance for delta in deltas):
        coverage.append("memory_write_deltas")
    if any("field_access_delta" in delta.security_relevance for delta in deltas):
        coverage.append("field_access_deltas")
    if any("data_target_delta" in delta.security_relevance for delta in deltas):
        coverage.append("data_target_deltas")
    return coverage


def _missing(
    before_tables: set[str],
    after_tables: set[str],
    deltas: list[ProjectMemoryAccessDelta],
) -> list[str]:
    missing: list[str] = []
    if "memory_operand_facts" not in before_tables:
        missing.append("before:memory_operand_facts")
    if "memory_operand_facts" not in after_tables:
        missing.append("after:memory_operand_facts")
    if not deltas:
        missing.append("memory_access_deltas")
    missing.append("alias_analysis")
    missing.append("path_sensitive_memory_state")
    return missing


def _sort_key(delta: ProjectMemoryAccessDelta) -> tuple[int, str, str, str]:
    return (
        -delta.review_priority,
        delta.access_kind,
        delta.function_name or "",
        delta.access_key,
    )


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


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


def _norm(value: str | None) -> str:
    if not value:
        return ""
    return " ".join(value.lower().split())


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def build_tool() -> WindowsProjectMemoryAccessDiffTool:
    return WindowsProjectMemoryAccessDiffTool()
