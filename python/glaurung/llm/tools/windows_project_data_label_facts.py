from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_operation_metadata import (
    OperationRecord,
    _load_yaml_list,
    _operation_record,
)
from .windows_surface_metadata import _resolve_metadata_path


class WindowsProjectDataLabelFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional source function VA used to filter data xrefs.",
    )
    target_va: int | None = Field(
        None,
        description="Optional data target VA used to filter labels and xrefs.",
    )
    labeled_only: bool = Field(
        False,
        description="If true, omit unlabeled data xref targets from samples.",
    )
    attach_sink_context: bool = Field(
        False,
        description=(
            "If true, join ASB sink metadata to callsites in functions that "
            "also reference each data target."
        ),
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    max_labels: int = Field(64, ge=0, le=1024, description="Maximum labels to return.")
    max_unlabeled_targets: int = Field(
        64,
        ge=0,
        le=1024,
        description="Maximum unlabeled target summaries to return.",
    )
    max_xrefs: int = Field(
        128,
        ge=0,
        le=4096,
        description="Maximum data xref samples to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact data-label coverage evidence node to the KB.",
    )


class WindowsProjectDataXrefFact(BaseModel):
    src_va: int
    dst_va: int
    kind: str
    src_function_va: int | None = None
    src_function_name: str | None = None
    data_label_name: str | None = None
    data_label_type: str | None = None
    data_label_size: int | None = None


class WindowsProjectDataLabelFact(BaseModel):
    va: int
    name: str
    c_type: str | None = None
    size: int | None = None
    set_by: str | None = None
    xref_count: int = 0
    read_xref_count: int = 0
    write_xref_count: int = 0
    source_function_count: int = 0
    source_function_sink_count: int = 0
    source_function_sink_kinds: list[str] = Field(default_factory=list)
    source_function_sink_symbols: list[str] = Field(default_factory=list)


class WindowsProjectUnlabeledDataTarget(BaseModel):
    va: int
    xref_count: int = 0
    read_xref_count: int = 0
    write_xref_count: int = 0
    source_function_count: int = 0
    source_function_sink_count: int = 0
    source_function_sink_kinds: list[str] = Field(default_factory=list)
    source_function_sink_symbols: list[str] = Field(default_factory=list)
    sample_source_vas: list[int] = Field(default_factory=list)


class WindowsProjectDataLabelFactsResult(BaseModel):
    project_path: str
    binary_id: int | None = None
    function_va: int | None = None
    target_va: int | None = None
    data_label_count: int
    data_xref_count: int
    labeled_xref_count: int
    unlabeled_xref_count: int
    data_targets_with_sink_context_count: int = 0
    labels: list[WindowsProjectDataLabelFact]
    unlabeled_targets: list[WindowsProjectUnlabeledDataTarget]
    xrefs: list[WindowsProjectDataXrefFact]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectDataLabelFactsTool(
    MemoryTool[
        WindowsProjectDataLabelFactsArgs,
        WindowsProjectDataLabelFactsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_data_label_facts",
                description=(
                    "Report labeled and unlabeled global data targets referenced by "
                    "persisted Windows PE project data xrefs."
                ),
                tags=("windows", "pe", "project", "data", "xrefs", "labels"),
            ),
            WindowsProjectDataLabelFactsArgs,
            WindowsProjectDataLabelFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectDataLabelFactsArgs,
    ) -> WindowsProjectDataLabelFactsResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            operations = _operations(args) if args.attach_sink_context else []
            sink_context = _sink_context_by_target(
                conn,
                present,
                binary_id,
                args,
                operations,
            )
            labels = _labels(conn, present, binary_id, args, sink_context)
            xrefs = _xrefs(conn, present, binary_id, args)
            unlabeled_targets = _unlabeled_targets(
                conn,
                present,
                binary_id,
                args,
                sink_context,
            )
            data_label_count = _count_labels(conn, present, binary_id, args)
            data_xref_count = _count_data_xrefs(conn, present, binary_id, args)
            labeled_xref_count = _count_labeled_xrefs(conn, present, binary_id, args)
        finally:
            conn.close()

        unlabeled_xref_count = max(0, data_xref_count - labeled_xref_count)
        coverage = _coverage(present, data_label_count, data_xref_count)
        missing = _missing_capabilities(present, data_label_count, data_xref_count)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_data_label_facts",
                    props={
                        "project_path": str(project_path),
                        "binary_id": binary_id,
                        "function_va": args.function_va,
                        "target_va": args.target_va,
                        "data_label_count": data_label_count,
                        "data_xref_count": data_xref_count,
                        "unlabeled_xref_count": unlabeled_xref_count,
                        "data_targets_with_sink_context_count": len(sink_context),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectDataLabelFactsResult(
            project_path=str(project_path),
            binary_id=binary_id,
            function_va=args.function_va,
            target_va=args.target_va,
            data_label_count=data_label_count,
            data_xref_count=data_xref_count,
            labeled_xref_count=labeled_xref_count,
            unlabeled_xref_count=unlabeled_xref_count,
            data_targets_with_sink_context_count=len(sink_context),
            labels=labels,
            unlabeled_targets=unlabeled_targets,
            xrefs=xrefs,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "data-label facts expose project global-reference coverage; "
                "they do not recover missing names or type layouts by themselves"
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


def _labels(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
    sink_context: dict[int, "_TargetSinkContext"],
) -> list[WindowsProjectDataLabelFact]:
    if "data_labels" not in present or args.max_labels == 0:
        return []
    clauses, params = _label_clauses(binary_id, args)
    if "xrefs" not in present:
        query = f"""
SELECT dl.va, dl.name, dl.c_type, dl.size, dl.set_by
FROM data_labels dl
WHERE {' AND '.join(clauses)}
ORDER BY dl.va
LIMIT ?
"""
        params.append(args.max_labels)
        rows = conn.execute(query, params).fetchall()
        return [
            WindowsProjectDataLabelFact(
                va=int(row[0]),
                name=str(row[1]),
                c_type=str(row[2]) if row[2] is not None else None,
                size=int(row[3]) if row[3] is not None else None,
                set_by=str(row[4]) if row[4] is not None else None,
                **_sink_context_fields(sink_context, int(row[0])),
            )
            for row in rows
        ]
    query = f"""
SELECT
    dl.va,
    dl.name,
    dl.c_type,
    dl.size,
    dl.set_by,
    COUNT(x.xref_id) AS xref_count,
    SUM(CASE WHEN x.kind = 'data_read' THEN 1 ELSE 0 END) AS read_xref_count,
    SUM(CASE WHEN x.kind = 'data_write' THEN 1 ELSE 0 END) AS write_xref_count,
    COUNT(DISTINCT x.src_function_va) AS source_function_count
FROM data_labels dl
LEFT JOIN xrefs x ON
    x.binary_id = dl.binary_id
    AND x.dst_va = dl.va
    AND x.kind IN ('data_read', 'data_write')
WHERE {' AND '.join(clauses)}
GROUP BY dl.va, dl.name, dl.c_type, dl.size, dl.set_by
ORDER BY xref_count DESC, dl.va
LIMIT ?
"""
    params.append(args.max_labels)
    rows = conn.execute(query, params).fetchall()
    return [
        WindowsProjectDataLabelFact(
            va=int(row[0]),
            name=str(row[1]),
            c_type=str(row[2]) if row[2] is not None else None,
            size=int(row[3]) if row[3] is not None else None,
            set_by=str(row[4]) if row[4] is not None else None,
            xref_count=int(row[5] or 0),
            read_xref_count=int(row[6] or 0),
            write_xref_count=int(row[7] or 0),
            source_function_count=int(row[8] or 0),
            **_sink_context_fields(sink_context, int(row[0])),
        )
        for row in rows
    ]


def _xrefs(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
) -> list[WindowsProjectDataXrefFact]:
    if "xrefs" not in present or args.max_xrefs == 0:
        return []
    fn_join = "function_names" in present
    label_join = "data_labels" in present
    if args.labeled_only and not label_join:
        return []
    name_select = "fn.canonical" if fn_join else "NULL"
    label_select = "dl.name, dl.c_type, dl.size" if label_join else "NULL, NULL, NULL"
    joins = ""
    if fn_join:
        joins += """
LEFT JOIN function_names fn ON
    fn.binary_id = x.binary_id AND fn.entry_va = x.src_function_va
"""
    if label_join:
        joins += """
LEFT JOIN data_labels dl ON dl.binary_id = x.binary_id AND dl.va = x.dst_va
"""
    clauses, params = _xref_clauses(binary_id, args)
    if args.labeled_only:
        clauses.append("dl.va IS NOT NULL")
    query = f"""
SELECT
    x.src_va,
    x.dst_va,
    x.kind,
    x.src_function_va,
    {name_select} AS src_function_name,
    {label_select}
FROM xrefs x
{joins}
WHERE {' AND '.join(clauses)}
ORDER BY x.src_va, x.xref_id
LIMIT ?
"""
    params.append(args.max_xrefs)
    rows = conn.execute(query, params).fetchall()
    return [
        WindowsProjectDataXrefFact(
            src_va=int(row[0]),
            dst_va=int(row[1]),
            kind=str(row[2]),
            src_function_va=int(row[3]) if row[3] is not None else None,
            src_function_name=str(row[4]) if row[4] is not None else None,
            data_label_name=str(row[5]) if row[5] is not None else None,
            data_label_type=str(row[6]) if row[6] is not None else None,
            data_label_size=int(row[7]) if row[7] is not None else None,
        )
        for row in rows
    ]


def _unlabeled_targets(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
    sink_context: dict[int, "_TargetSinkContext"],
) -> list[WindowsProjectUnlabeledDataTarget]:
    if (
        "xrefs" not in present
        or "data_labels" not in present
        or args.max_unlabeled_targets == 0
        or args.labeled_only
    ):
        return []
    clauses, params = _xref_clauses(binary_id, args)
    clauses.append("dl.va IS NULL")
    query = f"""
SELECT
    x.dst_va,
    COUNT(*) AS xref_count,
    SUM(CASE WHEN x.kind = 'data_read' THEN 1 ELSE 0 END) AS read_xref_count,
    SUM(CASE WHEN x.kind = 'data_write' THEN 1 ELSE 0 END) AS write_xref_count,
    COUNT(DISTINCT x.src_function_va) AS source_function_count,
    GROUP_CONCAT(x.src_va, ',') AS sample_source_vas
FROM xrefs x
LEFT JOIN data_labels dl ON dl.binary_id = x.binary_id AND dl.va = x.dst_va
WHERE {' AND '.join(clauses)}
GROUP BY x.dst_va
ORDER BY xref_count DESC, x.dst_va
LIMIT ?
"""
    params.append(args.max_unlabeled_targets)
    rows = conn.execute(query, params).fetchall()
    return [
        WindowsProjectUnlabeledDataTarget(
            va=int(row[0]),
            xref_count=int(row[1] or 0),
            read_xref_count=int(row[2] or 0),
            write_xref_count=int(row[3] or 0),
            source_function_count=int(row[4] or 0),
            **_sink_context_fields(sink_context, int(row[0])),
            sample_source_vas=_sample_vas(row[5]),
        )
        for row in rows
    ]


def _count_labels(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
) -> int:
    if "data_labels" not in present:
        return 0
    clauses, params = _label_clauses(binary_id, args)
    row = conn.execute(
        f"SELECT COUNT(*) FROM data_labels dl WHERE {' AND '.join(clauses)}",
        params,
    ).fetchone()
    return int(row[0] or 0) if row else 0


def _count_data_xrefs(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
) -> int:
    if "xrefs" not in present:
        return 0
    clauses, params = _xref_clauses(binary_id, args)
    row = conn.execute(
        f"SELECT COUNT(*) FROM xrefs x WHERE {' AND '.join(clauses)}",
        params,
    ).fetchone()
    return int(row[0] or 0) if row else 0


def _count_labeled_xrefs(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
) -> int:
    if "xrefs" not in present or "data_labels" not in present:
        return 0
    clauses, params = _xref_clauses(binary_id, args)
    query = f"""
SELECT COUNT(*)
FROM xrefs x
JOIN data_labels dl ON dl.binary_id = x.binary_id AND dl.va = x.dst_va
WHERE {' AND '.join(clauses)}
"""
    row = conn.execute(query, params).fetchone()
    return int(row[0] or 0) if row else 0


def _label_clauses(
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
) -> tuple[list[str], list[Any]]:
    clauses = ["1 = 1"]
    params: list[Any] = []
    if binary_id is not None:
        clauses.append("dl.binary_id = ?")
        params.append(binary_id)
    if args.target_va is not None:
        clauses.append("dl.va = ?")
        params.append(args.target_va)
    return clauses, params


def _xref_clauses(
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
) -> tuple[list[str], list[Any]]:
    clauses = ["x.kind IN ('data_read', 'data_write')"]
    params: list[Any] = []
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if args.function_va is not None:
        clauses.append("x.src_function_va = ?")
        params.append(args.function_va)
    if args.target_va is not None:
        clauses.append("x.dst_va = ?")
        params.append(args.target_va)
    return clauses, params


def _coverage(
    present: set[str],
    data_label_count: int,
    data_xref_count: int,
) -> list[str]:
    coverage: list[str] = []
    if "xrefs" in present and data_xref_count:
        coverage.append("project_data_xrefs")
    if "data_labels" in present:
        coverage.append("project_data_label_table")
    if data_label_count:
        coverage.append("project_data_labels")
    return coverage


def _missing_capabilities(
    present: set[str],
    data_label_count: int,
    data_xref_count: int,
) -> list[str]:
    missing: list[str] = []
    if "xrefs" not in present or not data_xref_count:
        missing.append("project_data_xrefs")
    if "data_labels" not in present:
        missing.append("project_data_label_table")
    elif data_label_count == 0:
        missing.append("project_data_labels")
    missing.extend(["pdb_type_layouts", "field_sensitive_global_types"])
    return missing


class _TargetSinkContext(BaseModel):
    sink_count: int = 0
    sink_kinds: list[str] = Field(default_factory=list)
    sink_symbols: list[str] = Field(default_factory=list)


def _operations(args: WindowsProjectDataLabelFactsArgs) -> list[OperationRecord]:
    path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
    return [_operation_record(entry, path) for entry in _load_yaml_list(path)]


def _sink_context_by_target(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    args: WindowsProjectDataLabelFactsArgs,
    operations: list[OperationRecord],
) -> dict[int, _TargetSinkContext]:
    if not operations or "xrefs" not in present or "function_names" not in present:
        return {}
    by_symbol = _operations_by_symbol(operations)
    clauses, params = _xref_clauses(binary_id, args)
    clauses = [clause.replace("x.", "dx.") for clause in clauses]
    query = f"""
SELECT
    dx.dst_va,
    cx.src_va,
    callee.canonical
FROM xrefs dx
JOIN xrefs cx ON
    cx.binary_id = dx.binary_id
    AND cx.src_function_va = dx.src_function_va
    AND cx.kind = 'call'
JOIN function_names callee ON
    callee.binary_id = cx.binary_id
    AND callee.entry_va = cx.dst_va
WHERE {' AND '.join(clauses)}
ORDER BY dx.dst_va, cx.src_va
"""
    rows = conn.execute(query, params).fetchall()
    target_symbols: dict[int, set[str]] = {}
    target_kinds: dict[int, set[str]] = {}
    target_calls: dict[int, set[tuple[int, str]]] = {}
    for dst_va, callsite_va, callee_name in rows:
        if callee_name is None:
            continue
        operation = by_symbol.get(str(callee_name))
        if operation is None:
            continue
        target = int(dst_va)
        symbol = str(callee_name)
        target_symbols.setdefault(target, set()).add(symbol)
        target_kinds.setdefault(target, set()).add(operation.sink_kind)
        target_calls.setdefault(target, set()).add((int(callsite_va), symbol))
    return {
        target: _TargetSinkContext(
            sink_count=len(target_calls.get(target, set())),
            sink_kinds=sorted(target_kinds.get(target, set())),
            sink_symbols=sorted(target_symbols.get(target, set())),
        )
        for target in target_calls
    }


def _operations_by_symbol(
    operations: list[OperationRecord],
) -> dict[str, OperationRecord]:
    out: dict[str, OperationRecord] = {}
    for operation in operations:
        for symbol in operation.symbols:
            out.setdefault(symbol, operation)
    return out


def _sink_context_fields(
    sink_context: dict[int, _TargetSinkContext],
    target_va: int,
) -> dict[str, object]:
    context = sink_context.get(target_va)
    if context is None:
        return {}
    return {
        "source_function_sink_count": context.sink_count,
        "source_function_sink_kinds": context.sink_kinds,
        "source_function_sink_symbols": context.sink_symbols,
    }


def _sample_vas(value: object) -> list[int]:
    if not value:
        return []
    out: list[int] = []
    for item in str(value).split(","):
        if not item:
            continue
        out.append(int(item))
        if len(out) >= 8:
            break
    return out


def build_tool() -> WindowsProjectDataLabelFactsTool:
    return WindowsProjectDataLabelFactsTool()
