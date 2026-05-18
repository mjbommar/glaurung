from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_callsite_operand_facts import (
    _first_operation,
    _load_yaml_list,
    _operations_by_symbol,
    _operation_record,
    _symbol_matches,
)
from .windows_operation_metadata import OperationRecord
from .windows_surface_metadata import _resolve_metadata_path


class WindowsProjectCallsiteFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter callsites.",
    )
    call_symbol: str | None = Field(
        None,
        description="Optional callee symbol filter, e.g. RtlCopyMemory or nt!RtlCopyMemory.",
    )
    operation_only: bool = Field(
        False,
        description="If true, return only callsites whose callee matches ASB sink metadata.",
    )
    max_calls: int = Field(64, ge=0, description="Maximum callsites to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact project callsite evidence node to the KB.",
    )


class ProjectCallsiteFact(BaseModel):
    binary_id: int
    callsite_va: int
    caller_va: int | None = None
    caller_name: str | None = None
    caller_demangled: str | None = None
    callee_va: int
    callee_name: str | None = None
    callee_demangled: str | None = None
    callee_prototype: str | None = None
    operation: OperationRecord | None = None
    evidence_kind: str = "project_call_xref"
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectCallsiteFactsResult(BaseModel):
    project_path: str
    sinks_path: str
    binary_id: int | None = None
    callsites: list[ProjectCallsiteFact]
    scanned_call_count: int
    operation_count_total: int
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectCallsiteFactsTool(
    MemoryTool[WindowsProjectCallsiteFactsArgs, WindowsProjectCallsiteFactsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_callsite_facts",
                description=(
                    "Enumerate exact callsite VAs and caller/callee identity "
                    "from persisted .glaurung PE call xrefs."
                ),
                tags=("windows", "pe", "project", "callsites", "xrefs"),
            ),
            WindowsProjectCallsiteFactsArgs,
            WindowsProjectCallsiteFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectCallsiteFactsArgs,
    ) -> WindowsProjectCallsiteFactsResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        operations = [_operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)]
        operations_by_symbol = _operations_by_symbol(operations)

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            rows = _query_callsite_rows(conn, present, binary_id, args.function_va)
        finally:
            conn.close()

        facts: list[ProjectCallsiteFact] = []
        for row in rows:
            callee_name = _best_name(row["callee_name"], row["callee_demangled"])
            if args.call_symbol and not _call_symbol_matches(row, args.call_symbol):
                continue
            operation = _first_operation(callee_name or "", operations_by_symbol)
            if args.operation_only and operation is None:
                continue
            facts.append(_fact_from_row(row, operation))
            if len(facts) >= args.max_calls:
                break

        coverage = _coverage(present, len(rows), facts)
        missing = _missing_capabilities(present, len(rows), facts)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_callsite_facts",
                    props={
                        "project_path": str(project_path),
                        "binary_id": binary_id,
                        "function_va": args.function_va,
                        "call_symbol": args.call_symbol,
                        "callsite_count": len(facts),
                        "scanned_call_count": len(rows),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectCallsiteFactsResult(
            project_path=str(project_path),
            sinks_path=str(sinks_path),
            binary_id=binary_id,
            callsites=facts,
            scanned_call_count=len(rows),
            operation_count_total=len(operations),
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "project callsite facts come from persisted xrefs; argument operands require IR or decompiler callsite facts"
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
    row = conn.execute("SELECT binary_id FROM binaries ORDER BY binary_id LIMIT 1").fetchone()
    return int(row[0]) if row else None


def _query_callsite_rows(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_va: int | None,
) -> list[dict[str, Any]]:
    if "xrefs" not in present:
        return []
    clauses = ["x.kind = 'call'"]
    params: list[object] = []
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if function_va is not None:
        clauses.append("x.src_function_va = ?")
        params.append(function_va)
    where = " AND ".join(clauses)
    fn_join = "function_names" in present
    proto_join = "function_prototypes" in present
    query = _callsite_query(fn_join=fn_join, proto_join=proto_join, where=where)
    cur = conn.execute(query, params)
    columns = [col[0] for col in cur.description or []]
    rows = cur.fetchall()
    return [dict(zip(columns, row, strict=True)) for row in rows]


def _callsite_query(*, fn_join: bool, proto_join: bool, where: str) -> str:
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
    proto_select = (
        "proto.return_type AS return_type, proto.params_json AS params_json"
        if proto_join and fn_join
        else "NULL AS return_type, NULL AS params_json"
    )
    joins = []
    if fn_join:
        joins.extend(
            [
                "LEFT JOIN function_names caller ON "
                "caller.binary_id = x.binary_id AND caller.entry_va = x.src_function_va",
                "LEFT JOIN function_names callee ON "
                "callee.binary_id = x.binary_id AND callee.entry_va = x.dst_va",
            ]
        )
    if proto_join and fn_join:
        joins.append(
            "LEFT JOIN function_prototypes proto ON "
            "proto.binary_id = x.binary_id AND proto.function_name = callee.canonical"
        )
    join_sql = "\n".join(joins)
    return f"""
SELECT
    x.binary_id AS binary_id,
    x.src_va AS callsite_va,
    x.src_function_va AS caller_va,
    x.dst_va AS callee_va,
    {caller_select},
    {callee_select},
    {proto_select}
FROM xrefs x
{join_sql}
WHERE {where}
ORDER BY x.src_va
"""


def _best_name(canonical: Any, demangled: Any) -> str | None:
    for value in (demangled, canonical):
        if isinstance(value, str) and value:
            return value
    return None


def _call_symbol_matches(row: dict[str, Any], symbol: str) -> bool:
    for key in ("callee_name", "callee_demangled"):
        value = row.get(key)
        if isinstance(value, str) and _symbol_matches(value, symbol):
            return True
    return False


def _fact_from_row(
    row: dict[str, Any],
    operation: OperationRecord | None,
) -> ProjectCallsiteFact:
    provenance = ["glaurung_project_xrefs"]
    if row.get("callee_name") or row.get("callee_demangled"):
        provenance.append("glaurung_function_names")
    if row.get("return_type") is not None or row.get("params_json") is not None:
        provenance.append("glaurung_function_prototypes")
    if operation:
        provenance.append("asb_pe_sink_metadata")
    return ProjectCallsiteFact(
        binary_id=int(row["binary_id"]),
        callsite_va=int(row["callsite_va"]),
        caller_va=int(row["caller_va"]) if row["caller_va"] is not None else None,
        caller_name=row.get("caller_name"),
        caller_demangled=row.get("caller_demangled"),
        callee_va=int(row["callee_va"]),
        callee_name=row.get("callee_name"),
        callee_demangled=row.get("callee_demangled"),
        callee_prototype=_format_prototype(row),
        operation=operation,
        confidence=0.84 if row.get("callee_name") else 0.68,
        provenance=provenance,
    )


def _format_prototype(row: dict[str, Any]) -> str | None:
    return_type = row.get("return_type")
    params_json = row.get("params_json")
    name = _best_name(row.get("callee_name"), row.get("callee_demangled"))
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(return_type, str) or not return_type:
        return None
    if not isinstance(params_json, str) or not params_json:
        return f"{return_type} {name}(...)"
    try:
        params = json.loads(params_json)
    except json.JSONDecodeError:
        params = None
    if isinstance(params, list):
        rendered_params = ", ".join(str(param) for param in params)
    else:
        rendered_params = params_json
    return f"{return_type} {name}({rendered_params})"


def _coverage(
    present: set[str],
    scanned_call_count: int,
    facts: list[ProjectCallsiteFact],
) -> list[str]:
    coverage: list[str] = []
    if "xrefs" in present and scanned_call_count:
        coverage.append("project_call_xrefs")
    if "function_names" in present and any(f.callee_name for f in facts):
        coverage.append("callee_names")
    if "function_prototypes" in present and any(f.callee_prototype for f in facts):
        coverage.append("callee_prototypes")
    if any(f.operation for f in facts):
        coverage.append("operation_metadata")
    return coverage


def _missing_capabilities(
    present: set[str],
    scanned_call_count: int,
    facts: list[ProjectCallsiteFact],
) -> list[str]:
    missing: list[str] = []
    if "xrefs" not in present or not scanned_call_count:
        missing.append("project_call_xrefs")
    if "function_names" not in present or not any(f.callee_name for f in facts):
        missing.append("callee_names")
    if "function_prototypes" not in present or not any(f.callee_prototype for f in facts):
        missing.append("callee_prototypes")
    missing.append("call_argument_operands")
    missing.append("native_ir_memory_references")
    return missing


def build_tool() -> MemoryTool[
    WindowsProjectCallsiteFactsArgs, WindowsProjectCallsiteFactsResult
]:
    return WindowsProjectCallsiteFactsTool()
