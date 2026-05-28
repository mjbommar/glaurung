from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


MemoryAccessQueryKind = Literal["all", "reads", "writes", "read_write"]


class WindowsProjectMemoryAccessQueryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    query: MemoryAccessQueryKind = Field(
        "all",
        description="Access filter: all, reads, writes, or read_write.",
    )
    function_va: int | None = None
    function_name_contains: str | None = None
    base_object_kind: str | None = Field(
        None,
        description="Filter by base object kind, e.g. stack_local, user_pointer.",
    )
    base_object_contains: str | None = None
    role_hint: str | None = None
    likely_type_name: str | None = None
    likely_field_name: str | None = None
    field_offset: int | None = None
    data_target_va: int | None = None
    data_target_name_contains: str | None = None
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    max_rows: int = Field(128, ge=0, le=4096)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact memory-access-query evidence node.",
    )


class ProjectMemoryAccessRow(BaseModel):
    function_va: int
    function: str
    function_name: str | None = None
    instruction_va: int
    instruction: str
    instruction_text: str
    mnemonic: str
    operand_index: int
    operand_text: str
    access_kind: str
    width_bytes: int | None = None
    address_expression: str
    base_register: str | None = None
    index_register: str | None = None
    scale: int | None = None
    displacement: int
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


class WindowsProjectMemoryAccessQueryResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    query: MemoryAccessQueryKind
    total_count: int
    returned_count: int
    rows: list[ProjectMemoryAccessRow]
    summary_by_access_kind: dict[str, int] = Field(default_factory=dict)
    summary_by_base_object_kind: dict[str, int] = Field(default_factory=dict)
    summary_by_role_hint: dict[str, int] = Field(default_factory=dict)
    summary_by_field: dict[str, int] = Field(default_factory=dict)
    summary_by_data_target: dict[str, int] = Field(default_factory=dict)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectMemoryAccessQueryTool(
    MemoryTool[
        WindowsProjectMemoryAccessQueryArgs,
        WindowsProjectMemoryAccessQueryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_memory_access_query",
                description=(
                    "Query persisted Windows memory_operand_facts by access "
                    "direction, base object kind, data target, type/field, and "
                    "function to answer who reads/writes a memory object."
                ),
                tags=("windows", "pe", "project", "memory", "xrefs", "fields"),
            ),
            WindowsProjectMemoryAccessQueryArgs,
            WindowsProjectMemoryAccessQueryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectMemoryAccessQueryArgs,
    ) -> WindowsProjectMemoryAccessQueryResult:
        project_path = Path(args.project_path).expanduser()
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = (
                args.binary_id
                if args.binary_id is not None
                else _first_binary_id(conn, present)
            )
            total_count, rows = _query_memory_accesses(
                conn,
                present,
                binary_id,
                args,
            )
        finally:
            conn.close()

        facts = [_row_from_sql(row) for row in rows]
        result = WindowsProjectMemoryAccessQueryResult(
            project_path=str(project_path),
            binary_id=binary_id,
            query=args.query,
            total_count=total_count,
            returned_count=len(facts),
            rows=facts,
            summary_by_access_kind=_summary(facts, lambda item: item.access_kind),
            summary_by_base_object_kind=_summary(
                facts, lambda item: item.base_object_kind
            ),
            summary_by_role_hint=_summary(facts, lambda item: item.role_hint),
            summary_by_field=_summary(facts, _field_key),
            summary_by_data_target=_summary(facts, _data_target_key),
            coverage=_coverage(present, facts),
            missing_capabilities=_missing(present, facts),
            notes=[
                "memory access query uses persisted memory_operand_facts; run bootstrap with memory operands if empty",
                "these are instruction-level memory facts, not alias-aware or path-sensitive memory state",
            ],
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_memory_access_query",
                    props={
                        "project_path": result.project_path,
                        "binary_id": result.binary_id,
                        "query": result.query,
                        "total_count": result.total_count,
                        "returned_count": result.returned_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": evidence_node_id})

        return result


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


def _query_memory_accesses(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectMemoryAccessQueryArgs,
) -> tuple[int, list[dict[str, Any]]]:
    if "memory_operand_facts" not in present:
        return 0, []
    clauses, params = _where(binary_id, args)
    where = " AND ".join(clauses)
    total = conn.execute(
        f"SELECT COUNT(*) FROM memory_operand_facts WHERE {where}",
        params,
    ).fetchone()
    rows = conn.execute(
        f"""
SELECT function_va, function_name, instruction_va, instruction_text, mnemonic,
       operand_index, operand_text, access_kind, width_bytes, address_expression,
       base_register, index_register, scale, displacement, role_hint,
       base_object, base_object_kind, base_object_type, base_object_role,
       field_offset, likely_field_name, likely_type_name, data_target_va,
       data_target_kind, data_target_name, data_target_type, data_target_size,
       confidence
FROM memory_operand_facts
WHERE {where}
ORDER BY function_va, instruction_va, operand_index
LIMIT ?
""",
        (*params, int(args.max_rows)),
    )
    columns = [col[0] for col in rows.description or []]
    return int(total[0] if total else 0), [
        dict(zip(columns, row, strict=True)) for row in rows.fetchall()
    ]


def _where(
    binary_id: int | None,
    args: WindowsProjectMemoryAccessQueryArgs,
) -> tuple[list[str], list[object]]:
    clauses: list[str] = ["confidence >= ?"]
    params: list[object] = [args.min_confidence]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    if args.query == "reads":
        clauses.append("access_kind IN ('read', 'read_write')")
    elif args.query == "writes":
        clauses.append("access_kind IN ('write', 'read_write')")
    elif args.query == "read_write":
        clauses.append("access_kind = 'read_write'")
    if args.function_va is not None:
        clauses.append("function_va = ?")
        params.append(args.function_va)
    if args.function_name_contains:
        clauses.append("LOWER(COALESCE(function_name, '')) LIKE ?")
        params.append(f"%{args.function_name_contains.lower()}%")
    if args.base_object_kind:
        clauses.append("base_object_kind = ?")
        params.append(args.base_object_kind)
    if args.base_object_contains:
        clauses.append("LOWER(COALESCE(base_object, '')) LIKE ?")
        params.append(f"%{args.base_object_contains.lower()}%")
    if args.role_hint:
        clauses.append("role_hint = ?")
        params.append(args.role_hint)
    if args.likely_type_name:
        clauses.append("likely_type_name = ?")
        params.append(args.likely_type_name)
    if args.likely_field_name:
        clauses.append("likely_field_name = ?")
        params.append(args.likely_field_name)
    if args.field_offset is not None:
        clauses.append("field_offset = ?")
        params.append(args.field_offset)
    if args.data_target_va is not None:
        clauses.append("data_target_va = ?")
        params.append(args.data_target_va)
    if args.data_target_name_contains:
        clauses.append("LOWER(COALESCE(data_target_name, '')) LIKE ?")
        params.append(f"%{args.data_target_name_contains.lower()}%")
    return clauses, params


def _row_from_sql(row: dict[str, Any]) -> ProjectMemoryAccessRow:
    function_va = _required_int(row["function_va"])
    instruction_va = _required_int(row["instruction_va"])
    data_target_va = _optional_int(row.get("data_target_va"))
    return ProjectMemoryAccessRow(
        function_va=function_va,
        function=_hex(function_va),
        function_name=_optional_str(row.get("function_name")),
        instruction_va=instruction_va,
        instruction=_hex(instruction_va),
        instruction_text=str(row["instruction_text"]),
        mnemonic=str(row["mnemonic"]),
        operand_index=_required_int(row["operand_index"]),
        operand_text=str(row["operand_text"]),
        access_kind=str(row["access_kind"]),
        width_bytes=_optional_int(row.get("width_bytes")),
        address_expression=str(row["address_expression"]),
        base_register=_optional_str(row.get("base_register")),
        index_register=_optional_str(row.get("index_register")),
        scale=_optional_int(row.get("scale")),
        displacement=_required_int(row["displacement"]),
        role_hint=str(row["role_hint"]),
        base_object=_optional_str(row.get("base_object")),
        base_object_kind=_optional_str(row.get("base_object_kind")),
        base_object_type=_optional_str(row.get("base_object_type")),
        base_object_role=_optional_str(row.get("base_object_role")),
        field_offset=_required_int(row["field_offset"]),
        likely_field_name=_optional_str(row.get("likely_field_name")),
        likely_type_name=_optional_str(row.get("likely_type_name")),
        data_target_va=data_target_va,
        data_target=_hex(data_target_va) if data_target_va is not None else None,
        data_target_kind=_optional_str(row.get("data_target_kind")),
        data_target_name=_optional_str(row.get("data_target_name")),
        data_target_type=_optional_str(row.get("data_target_type")),
        data_target_size=_optional_int(row.get("data_target_size")),
        confidence=_required_float(row["confidence"]),
    )


def _summary(
    rows: list[ProjectMemoryAccessRow],
    key_fn: Callable[[ProjectMemoryAccessRow], str | None],
) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        key = key_fn(row)
        if not key:
            continue
        out[str(key)] = out.get(str(key), 0) + 1
    return dict(sorted(out.items()))


def _field_key(row: ProjectMemoryAccessRow) -> str | None:
    if row.likely_type_name and row.likely_field_name:
        return f"{row.likely_type_name}.{row.likely_field_name}"
    if row.field_offset:
        return f"offset_{row.field_offset:#x}"
    return None


def _data_target_key(row: ProjectMemoryAccessRow) -> str | None:
    if row.data_target_name:
        return row.data_target_name
    return row.data_target


def _coverage(
    present: set[str],
    rows: list[ProjectMemoryAccessRow],
) -> list[str]:
    coverage: list[str] = []
    if "memory_operand_facts" in present:
        coverage.append("memory_operand_facts")
    if rows:
        coverage.append("memory_access_rows")
    if any(row.access_kind in {"read", "read_write"} for row in rows):
        coverage.append("memory_reads")
    if any(row.access_kind in {"write", "read_write"} for row in rows):
        coverage.append("memory_writes")
    if any(row.base_object_kind for row in rows):
        coverage.append("base_object_classification")
    if any(row.likely_field_name or row.field_offset for row in rows):
        coverage.append("field_or_offset_facts")
    if any(row.data_target_va is not None for row in rows):
        coverage.append("data_target_facts")
    return coverage


def _missing(
    present: set[str],
    rows: list[ProjectMemoryAccessRow],
) -> list[str]:
    missing: list[str] = []
    if "memory_operand_facts" not in present:
        missing.append("memory_operand_facts")
    if not rows:
        missing.append("memory_access_rows")
    if rows and not any(row.base_object_kind for row in rows):
        missing.append("base_object_classification")
    if rows and not any(row.likely_field_name for row in rows):
        missing.append("type_layout_field_names")
    missing.append("alias_analysis")
    missing.append("path_sensitive_memory_state")
    return missing


def _required_int(value: Any) -> int:
    return int(value)


def _required_float(value: Any) -> float:
    return float(value)


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _hex(va: int) -> str:
    return f"0x{va:x}"


def build_tool() -> WindowsProjectMemoryAccessQueryTool:
    return WindowsProjectMemoryAccessQueryTool()
