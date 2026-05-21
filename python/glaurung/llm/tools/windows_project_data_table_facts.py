from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from glaurung import windows_analysis

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


DataTableKind = Literal[
    "dispatch_table",
    "callback_array",
    "vtable",
    "jump_table",
    "selector_table",
    "import_thunk_table",
    "code_pointer_table",
    "global_array",
    "unknown_table",
]
DataTableQueryKind = Literal[
    "all",
    "dispatch_table",
    "callback_array",
    "vtable",
    "jump_table",
    "selector_table",
    "import_thunk_table",
    "code_pointer_table",
    "global_array",
    "unknown_table",
]


class WindowsProjectDataTableFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    binary_path: str | None = Field(
        None,
        description=(
            "Optional PE path. When present, native code-pointer tables are added "
            "to persisted project label/xref/chunk candidates."
        ),
    )
    table_kind: DataTableQueryKind = Field(
        "all",
        description="Optional table-kind filter.",
    )
    name_contains: str | None = Field(
        None,
        description="Optional case-insensitive table name/type substring filter.",
    )
    min_entries: int = Field(2, ge=1, le=4096)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    include_native_code_pointers: bool = Field(
        True,
        description="If true and binary_path is set, run the native PE code-pointer scan.",
    )
    max_tables: int = Field(64, ge=0, le=4096)
    max_entries_per_table: int = Field(32, ge=0, le=512)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact data-table evidence node to the KB.",
    )


class ProjectDataTableEntry(BaseModel):
    index: int | None = None
    slot_va: int | None = None
    slot: str | None = None
    target_va: int | None = None
    target: str | None = None
    target_name: str | None = None
    target_kind: str = "unknown"
    xref_kind: str | None = None
    src_va: int | None = None
    src: str | None = None
    src_function_va: int | None = None
    src_function: str | None = None
    src_function_name: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str


class ProjectDataTableFact(BaseModel):
    table_va: int | None = None
    table: str | None = None
    table_kind: DataTableKind
    name: str | None = None
    c_type: str | None = None
    section: str | None = None
    size_bytes: int | None = None
    slot_size: int | None = None
    entry_count: int
    entry_count_source: str
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    read_xref_count: int = 0
    write_xref_count: int = 0
    source_function_count: int = 0
    source_function_names: list[str] = Field(default_factory=list)
    entries: list[ProjectDataTableEntry] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)


class WindowsProjectDataTableFactsResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    binary_path: str | None = None
    total_candidate_count: int
    returned_count: int
    tables: list[ProjectDataTableFact]
    summary_by_kind: dict[str, int] = Field(default_factory=dict)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectDataTableFactsTool(
    MemoryTool[WindowsProjectDataTableFactsArgs, WindowsProjectDataTableFactsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_data_table_facts",
                description=(
                    "Recover first-class Windows data/table candidates from "
                    "persisted data labels, data xrefs, function chunk facts, and "
                    "optional native PE code-pointer tables."
                ),
                tags=("windows", "pe", "project", "data", "tables", "xrefs"),
            ),
            WindowsProjectDataTableFactsArgs,
            WindowsProjectDataTableFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectDataTableFactsArgs,
    ) -> WindowsProjectDataTableFactsResult:
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
            function_names = _function_names(conn, present, binary_id)
            candidates = [
                *_label_table_candidates(conn, present, binary_id, args),
                *_chunk_table_candidates(conn, present, binary_id, args),
            ]
        finally:
            conn.close()

        if args.binary_path and args.include_native_code_pointers:
            candidates.extend(_native_code_pointer_tables(args, function_names))

        filtered = [table for table in candidates if _include_table(table, args)]
        filtered.sort(key=_sort_key)
        returned = filtered[: args.max_tables] if args.max_tables else []

        result = WindowsProjectDataTableFactsResult(
            project_path=str(project_path),
            binary_id=binary_id,
            binary_path=str(Path(args.binary_path)) if args.binary_path else None,
            total_candidate_count=len(filtered),
            returned_count=len(returned),
            tables=returned,
            summary_by_kind=_summary_by_kind(filtered),
            coverage=_coverage(present, returned, args),
            missing_capabilities=_missing(present, returned, args),
            notes=[
                "data-table facts are recovery and navigation evidence, not vulnerability evidence",
                "native code-pointer rows require binary_path; project rows use persisted labels, xrefs, and chunk facts",
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_data_table_facts",
                    props={
                        "project_path": result.project_path,
                        "binary_id": result.binary_id,
                        "table_kind": args.table_kind,
                        "total_candidate_count": result.total_candidate_count,
                        "returned_count": result.returned_count,
                    },
                )
            )
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": node.id})

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


def _function_names(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
) -> dict[int, str]:
    if "function_names" not in present:
        return {}
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT entry_va, canonical FROM function_names {where}",
        params,
    ).fetchall()
    return {int(row[0]): str(row[1]) for row in rows}


def _label_table_candidates(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataTableFactsArgs,
) -> list[ProjectDataTableFact]:
    if "data_labels" not in present:
        return []
    clauses: list[str] = []
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
SELECT va, name, c_type, size, set_by
FROM data_labels
{where}
ORDER BY va
LIMIT 8192
""",
        params,
    ).fetchall()
    candidates: list[ProjectDataTableFact] = []
    for row in rows:
        table_va = int(row[0])
        name = str(row[1])
        c_type = _optional_str(row[2])
        size = _optional_int(row[3])
        slot_size = _slot_size(c_type)
        entry_count = _entry_count_from_size(size, slot_size)
        kind, reasons = _classify_label_table(name, c_type)
        entries = _data_xref_entries(
            conn,
            present,
            binary_id,
            table_va,
            size,
            slot_size,
            args.max_entries_per_table,
        )
        xref_slots = {entry.index for entry in entries if entry.index is not None}
        inferred_count = max(
            entry_count,
            (max(xref_slots) + 1) if xref_slots else 0,
            len(xref_slots),
        )
        if inferred_count < args.min_entries and kind == "unknown_table":
            continue
        read_count = sum(1 for entry in entries if entry.xref_kind == "data_read")
        write_count = sum(1 for entry in entries if entry.xref_kind == "data_write")
        source_names = sorted(
            {
                entry.src_function_name
                for entry in entries
                if entry.src_function_name is not None
            }
        )
        confidence = _label_confidence(
            kind,
            entry_count=entry_count,
            xref_entry_count=len(entries),
            reason_codes=reasons,
        )
        candidates.append(
            ProjectDataTableFact(
                table_va=table_va,
                table=_hex(table_va),
                table_kind=kind,
                name=name,
                c_type=c_type,
                size_bytes=size,
                slot_size=slot_size,
                entry_count=inferred_count,
                entry_count_source="declared_size" if entry_count else "xref_slots",
                source="data_labels",
                confidence=confidence,
                read_xref_count=read_count,
                write_xref_count=write_count,
                source_function_count=len(source_names),
                source_function_names=source_names,
                entries=entries,
                reason_codes=reasons,
                security_relevance=_security_relevance(kind, reasons),
            )
        )
    return candidates


def _data_xref_entries(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    table_va: int,
    size: int | None,
    slot_size: int,
    limit: int,
) -> list[ProjectDataTableEntry]:
    if "xrefs" not in present or limit == 0:
        return []
    clauses = ["x.kind IN ('data_read', 'data_write')"]
    params: list[object] = []
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if size is not None and size > 0:
        clauses.append("x.dst_va >= ?")
        clauses.append("x.dst_va < ?")
        params.extend([table_va, table_va + size])
    else:
        clauses.append("x.dst_va = ?")
        params.append(table_va)
    name_select = "fn.canonical" if "function_names" in present else "NULL"
    function_join = ""
    if "function_names" in present:
        function_join = """
LEFT JOIN function_names fn ON
    fn.binary_id = x.binary_id AND fn.entry_va = x.src_function_va
"""
    rows = conn.execute(
        f"""
SELECT x.src_va, x.dst_va, x.kind, x.src_function_va, {name_select}
FROM xrefs x
{function_join}
WHERE {" AND ".join(clauses)}
ORDER BY x.dst_va, x.src_va
LIMIT ?
""",
        [*params, limit],
    ).fetchall()
    entries: list[ProjectDataTableEntry] = []
    for row in rows:
        src_va = int(row[0])
        slot_va = int(row[1])
        offset = max(0, slot_va - table_va)
        index = offset // slot_size if slot_size else None
        src_function_va = _optional_int(row[3])
        entries.append(
            ProjectDataTableEntry(
                index=index,
                slot_va=slot_va,
                slot=_hex(slot_va),
                target_kind="table_slot",
                xref_kind=str(row[2]),
                src_va=src_va,
                src=_hex(src_va),
                src_function_va=src_function_va,
                src_function=_hex(src_function_va)
                if src_function_va is not None
                else None,
                src_function_name=_optional_str(row[4]),
                confidence=0.72,
                evidence="project_data_xref_to_table_range",
            )
        )
    return entries


def _chunk_table_candidates(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataTableFactsArgs,
) -> list[ProjectDataTableFact]:
    if "function_chunk_facts" not in present:
        return []
    clauses = [
        "(LOWER(chunk_kind) LIKE '%thunk%' OR LOWER(relation_kind) LIKE '%thunk%')"
    ]
    params: list[object] = []
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    rows = conn.execute(
        f"""
SELECT owner_entry_va, chunk_start_va, chunk_end_va, chunk_size, chunk_kind,
       relation_kind, target_va, target_name, source, confidence, name
FROM function_chunk_facts
WHERE {" AND ".join(clauses)}
ORDER BY chunk_start_va
""",
        params,
    ).fetchall()
    chunks = [_chunk_row(row) for row in rows]
    groups: list[list[_ChunkRow]] = []
    for chunk in chunks:
        if not groups or not _same_chunk_run(groups[-1][-1], chunk):
            groups.append([chunk])
        else:
            groups[-1].append(chunk)
    candidates: list[ProjectDataTableFact] = []
    for group in groups:
        if len(group) < args.min_entries:
            continue
        first = group[0]
        kind = _chunk_table_kind(group)
        entries = [
            ProjectDataTableEntry(
                index=idx,
                slot_va=chunk.chunk_start_va,
                slot=_hex(chunk.chunk_start_va),
                target_va=chunk.target_va,
                target=_hex(chunk.target_va) if chunk.target_va is not None else None,
                target_name=chunk.target_name,
                target_kind="function",
                confidence=chunk.confidence,
                evidence=f"function_chunk_facts:{chunk.chunk_kind}",
            )
            for idx, chunk in enumerate(group[: args.max_entries_per_table])
        ]
        reason_codes = _dedupe(
            [
                "function_chunk_table",
                *[f"chunk_kind:{chunk.chunk_kind}" for chunk in group],
                *[f"relation:{chunk.relation_kind}" for chunk in group],
            ]
        )
        candidates.append(
            ProjectDataTableFact(
                table_va=first.chunk_start_va,
                table=_hex(first.chunk_start_va),
                table_kind=kind,
                name=first.name,
                size_bytes=max(
                    chunk.chunk_end_va or chunk.chunk_start_va for chunk in group
                )
                - first.chunk_start_va,
                slot_size=None,
                entry_count=len(group),
                entry_count_source="function_chunk_run",
                source="function_chunk_facts",
                confidence=round(
                    sum(chunk.confidence for chunk in group) / max(1, len(group)),
                    3,
                ),
                entries=entries,
                reason_codes=reason_codes,
                security_relevance=_security_relevance(kind, reason_codes),
            )
        )
    return candidates


class _ChunkRow(BaseModel):
    owner_entry_va: int | None = None
    chunk_start_va: int
    chunk_end_va: int | None = None
    chunk_size: int | None = None
    chunk_kind: str
    relation_kind: str
    target_va: int | None = None
    target_name: str | None = None
    source: str
    confidence: float
    name: str | None = None


def _chunk_row(row: tuple[Any, ...]) -> _ChunkRow:
    return _ChunkRow(
        owner_entry_va=_optional_int(row[0]),
        chunk_start_va=int(row[1]),
        chunk_end_va=_optional_int(row[2]),
        chunk_size=_optional_int(row[3]),
        chunk_kind=str(row[4]),
        relation_kind=str(row[5]),
        target_va=_optional_int(row[6]),
        target_name=_optional_str(row[7]),
        source=str(row[8]),
        confidence=float(row[9]),
        name=_optional_str(row[10]),
    )


def _same_chunk_run(left: _ChunkRow, right: _ChunkRow) -> bool:
    gap = right.chunk_start_va - left.chunk_start_va
    return 0 < gap <= 16 and _chunk_table_kind([left]) == _chunk_table_kind([right])


def _chunk_table_kind(group: list[_ChunkRow]) -> DataTableKind:
    text = " ".join(
        f"{chunk.chunk_kind} {chunk.relation_kind} {chunk.name or ''}"
        for chunk in group
    ).lower()
    if "import" in text:
        return "import_thunk_table"
    if "jump" in text:
        return "jump_table"
    return "code_pointer_table"


def _native_code_pointer_tables(
    args: WindowsProjectDataTableFactsArgs,
    function_names: dict[int, str],
) -> list[ProjectDataTableFact]:
    if not args.binary_path:
        return []
    binary_path = Path(args.binary_path).expanduser()
    if not binary_path.exists():
        raise ValueError(f"{binary_path}: binary_path does not exist")
    pointers = windows_analysis.find_code_pointers(binary_path)
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for pointer in pointers:
        key = (str(pointer["section"]), int(pointer["table_index"]))
        grouped.setdefault(key, []).append(pointer)
    candidates: list[ProjectDataTableFact] = []
    for (section, table_index), group in grouped.items():
        group.sort(key=lambda item: int(item["pointer_va"]))
        if len(group) < args.min_entries:
            continue
        table_va = int(group[0]["pointer_va"])
        slot_size = int(group[0]["slot_size"])
        entries = [
            ProjectDataTableEntry(
                index=int(item.get("table_index", table_index))
                if len(group) == 1
                else idx,
                slot_va=int(item["pointer_va"]),
                slot=str(item["pointer"]),
                target_va=int(item["target_va"]),
                target=str(item["target"]),
                target_name=function_names.get(int(item["target_va"])),
                target_kind="function",
                confidence=0.82 if item.get("confidence") == "boundary" else 0.68,
                evidence=f"native_pe_code_pointer:{item.get('confidence')}",
            )
            for idx, item in enumerate(group[: args.max_entries_per_table])
        ]
        reason_codes = [
            "native_pe_code_pointer_table",
            f"section:{section}",
            f"table_index:{table_index}",
        ]
        candidates.append(
            ProjectDataTableFact(
                table_va=table_va,
                table=_hex(table_va),
                table_kind="code_pointer_table",
                section=section,
                slot_size=slot_size,
                entry_count=max(int(item["table_length"]) for item in group),
                entry_count_source="native_table_length",
                source="native_pe_code_pointer_scan",
                confidence=round(
                    sum(entry.confidence for entry in entries) / max(1, len(entries)),
                    3,
                ),
                entries=entries,
                reason_codes=reason_codes,
                security_relevance=_security_relevance(
                    "code_pointer_table", reason_codes
                ),
            )
        )
    return candidates


def _include_table(
    table: ProjectDataTableFact,
    args: WindowsProjectDataTableFactsArgs,
) -> bool:
    if table.table_kind != args.table_kind and args.table_kind != "all":
        return False
    if table.confidence < args.min_confidence:
        return False
    if table.entry_count < args.min_entries:
        return False
    if args.name_contains:
        needle = args.name_contains.lower()
        haystack = " ".join(
            value
            for value in (
                table.name,
                table.c_type,
                table.section,
                table.source,
                table.table_kind,
            )
            if value
        ).lower()
        if needle not in haystack:
            return False
    return True


def _sort_key(table: ProjectDataTableFact) -> tuple[int, int, int, str]:
    priority = {
        "dispatch_table": 0,
        "callback_array": 1,
        "vtable": 2,
        "import_thunk_table": 3,
        "jump_table": 4,
        "selector_table": 5,
        "code_pointer_table": 6,
        "global_array": 7,
        "unknown_table": 8,
    }[table.table_kind]
    xrefs = table.read_xref_count + table.write_xref_count
    return (priority, -table.entry_count, -xrefs, table.name or table.table or "")


def _classify_label_table(
    name: str, c_type: str | None
) -> tuple[DataTableKind, list[str]]:
    haystack = f"{name} {c_type or ''}".lower()
    reasons: list[str] = []
    if "majorfunction" in haystack or "dispatch" in haystack:
        reasons.append("name_or_type_dispatch")
        return "dispatch_table", reasons
    if "callback" in haystack or "notify" in haystack or "routine" in haystack:
        reasons.append("name_or_type_callback")
        return "callback_array", reasons
    if "vftable" in haystack or "vtable" in haystack or "??_7" in name:
        reasons.append("name_or_type_vtable")
        return "vtable", reasons
    if "jump" in haystack or "switch" in haystack or "case" in haystack:
        reasons.append("name_or_type_jump_table")
        return "jump_table", reasons
    if "__imp" in haystack or "iat" in haystack or "import" in haystack:
        reasons.append("name_or_type_import_thunk")
        return "import_thunk_table", reasons
    if "selector" in haystack or "index" in haystack or "opcode" in haystack:
        reasons.append("name_or_type_selector")
        return "selector_table", reasons
    if _looks_pointer_array(c_type):
        reasons.append("type_pointer_array")
        return "code_pointer_table", reasons
    if "[" in (c_type or "") or (c_type and c_type.endswith("[]")):
        reasons.append("type_array")
        return "global_array", reasons
    return "unknown_table", ["unclassified_data_label"]


def _looks_pointer_array(c_type: str | None) -> bool:
    if not c_type:
        return False
    lowered = c_type.lower()
    return any(token in lowered for token in ("pfn", "callback", "dispatch")) or (
        ("*" in c_type or "pvoid" in lowered or "ptr" in lowered)
        and ("[" in c_type or lowered.endswith("[]"))
    )


def _slot_size(c_type: str | None) -> int:
    if c_type and _looks_pointer_array(c_type):
        return 8
    if c_type and any(token in c_type.lower() for token in ("uint64", "ulong64")):
        return 8
    return 4


def _entry_count_from_size(size: int | None, slot_size: int) -> int:
    if size is None or size <= 0 or slot_size <= 0:
        return 0
    return max(1, size // slot_size)


def _label_confidence(
    kind: DataTableKind,
    *,
    entry_count: int,
    xref_entry_count: int,
    reason_codes: list[str],
) -> float:
    confidence = 0.35
    if kind != "unknown_table":
        confidence += 0.25
    if entry_count >= 2:
        confidence += 0.18
    if xref_entry_count:
        confidence += 0.12
    if "type_pointer_array" in reason_codes:
        confidence += 0.08
    return round(min(0.95, confidence), 3)


def _security_relevance(kind: DataTableKind, reason_codes: list[str]) -> list[str]:
    relevance: list[str] = []
    if kind == "dispatch_table":
        relevance.append("dispatch_table")
    if kind == "callback_array":
        relevance.append("callback_table")
    if kind == "vtable":
        relevance.append("virtual_dispatch_table")
    if kind == "jump_table":
        relevance.append("selector_indexed_control_flow")
    if kind == "selector_table":
        relevance.append("selector_indexed_global")
    if kind == "import_thunk_table":
        relevance.append("import_thunk_table")
    if kind == "code_pointer_table":
        relevance.append("code_pointer_table")
    if any("function_chunk" in code for code in reason_codes):
        relevance.append("functionization_table")
    return _dedupe(relevance)


def _summary_by_kind(tables: list[ProjectDataTableFact]) -> dict[str, int]:
    out: dict[str, int] = {}
    for table in tables:
        out[table.table_kind] = out.get(table.table_kind, 0) + 1
    return dict(sorted(out.items()))


def _coverage(
    present: set[str],
    tables: list[ProjectDataTableFact],
    args: WindowsProjectDataTableFactsArgs,
) -> list[str]:
    coverage: list[str] = []
    if "data_labels" in present:
        coverage.append("data_labels")
    if "xrefs" in present:
        coverage.append("project_xrefs")
    if "function_chunk_facts" in present:
        coverage.append("function_chunk_facts")
    if args.binary_path and args.include_native_code_pointers:
        coverage.append("native_code_pointer_scan")
    if tables:
        coverage.append("data_table_candidates")
    if any(table.table_kind == "dispatch_table" for table in tables):
        coverage.append("dispatch_table_candidates")
    if any(table.table_kind == "callback_array" for table in tables):
        coverage.append("callback_array_candidates")
    if any(table.table_kind == "vtable" for table in tables):
        coverage.append("vtable_candidates")
    if any(table.table_kind == "import_thunk_table" for table in tables):
        coverage.append("import_thunk_table_candidates")
    return coverage


def _missing(
    present: set[str],
    tables: list[ProjectDataTableFact],
    args: WindowsProjectDataTableFactsArgs,
) -> list[str]:
    missing: list[str] = []
    if "data_labels" not in present:
        missing.append("data_labels")
    if "xrefs" not in present:
        missing.append("project_xrefs")
    if "function_chunk_facts" not in present:
        missing.append("function_chunk_facts")
    if not args.binary_path:
        missing.append("binary_path_for_native_code_pointer_tables")
    if not tables:
        missing.append("data_table_candidates")
    missing.extend(["typed_table_layouts", "table_entry_target_resolution"])
    return missing


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


def build_tool() -> WindowsProjectDataTableFactsTool:
    return WindowsProjectDataTableFactsTool()
