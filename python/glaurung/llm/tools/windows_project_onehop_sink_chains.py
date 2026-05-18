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


class WindowsProjectOnehopSinkChainsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    caller_function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter chain starts.",
    )
    caller_function_name: str | None = Field(
        None,
        description="Optional caller function name used when caller_function_va is absent.",
    )
    helper_function_va: int | None = Field(
        None,
        description="Optional helper function VA used to filter one-hop callees.",
    )
    helper_function_name: str | None = Field(
        None,
        description="Optional helper function name used when helper_function_va is absent.",
    )
    sink_symbol: str | None = Field(
        None,
        description="Optional helper-local sink symbol filter, e.g. RtlCopyMemory.",
    )
    sink_kind: str | None = Field(
        None,
        description="Optional ASB sink kind filter, e.g. copy, free, completion.",
    )
    max_chains: int = Field(64, ge=0, le=4096, description="Maximum chains to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact one-hop sink-chain evidence node to the KB.",
    )


class WindowsProjectOnehopSinkChain(BaseModel):
    binary_id: int
    caller_va: int | None = None
    caller_name: str | None = None
    caller_demangled: str | None = None
    helper_callsite_va: int
    helper_va: int
    helper_name: str | None = None
    helper_demangled: str | None = None
    sink_callsite_va: int
    sink_va: int
    sink_symbol: str
    sink_kind: str
    sink_effects: list[str] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectOnehopSinkChainsResult(BaseModel):
    project_path: str
    sinks_path: str
    binary_id: int | None = None
    scanned_helper_call_count: int
    scanned_helper_sink_call_count: int
    chain_count: int
    chains: list[WindowsProjectOnehopSinkChain]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOnehopSinkChainsTool(
    MemoryTool[
        WindowsProjectOnehopSinkChainsArgs,
        WindowsProjectOnehopSinkChainsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_onehop_sink_chains",
                description=(
                    "Find caller -> helper -> ASB sink call chains from persisted "
                    ".glaurung Windows PE call xrefs."
                ),
                tags=("windows", "pe", "project", "callgraph", "onehop", "sinks"),
            ),
            WindowsProjectOnehopSinkChainsArgs,
            WindowsProjectOnehopSinkChainsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOnehopSinkChainsArgs,
    ) -> WindowsProjectOnehopSinkChainsResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        operations = [
            _operation_record(entry, sinks_path)
            for entry in _load_yaml_list(sinks_path)
        ]
        operations_by_symbol = _operations_by_symbol(operations)

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            caller_va = args.caller_function_va or _function_va_by_name(
                conn,
                present,
                binary_id,
                args.caller_function_name,
            )
            helper_va = args.helper_function_va or _function_va_by_name(
                conn,
                present,
                binary_id,
                args.helper_function_name,
            )
            helper_rows = _helper_call_rows(conn, present, binary_id, caller_va, helper_va)
            sink_rows = _helper_sink_rows(conn, present, binary_id, helper_va)
        finally:
            conn.close()

        sink_rows_by_helper = _sink_rows_by_helper(sink_rows)
        chains: list[WindowsProjectOnehopSinkChain] = []
        scanned_helper_sink_call_count = 0
        for helper_row in helper_rows:
            helper_sink_rows = sink_rows_by_helper.get(int(helper_row["helper_va"]), [])
            scanned_helper_sink_call_count += len(helper_sink_rows)
            for sink_row in helper_sink_rows:
                operation = _operation_for_row(sink_row, operations_by_symbol)
                if operation is None:
                    continue
                if args.sink_kind and operation.sink_kind != args.sink_kind:
                    continue
                if args.sink_symbol and not _symbol_matches(
                    sink_row.get("sink_name"),
                    sink_row.get("sink_demangled"),
                    args.sink_symbol,
                ):
                    continue
                chains.append(_chain_from_rows(helper_row, sink_row, operation))
                if len(chains) >= args.max_chains:
                    break
            if len(chains) >= args.max_chains:
                break

        coverage = _coverage(present, helper_rows, chains)
        missing = _missing_capabilities(present, helper_rows, chains)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_onehop_sink_chains",
                    props={
                        "project_path": str(project_path),
                        "binary_id": binary_id,
                        "caller_function_va": caller_va,
                        "helper_function_va": helper_va,
                        "chain_count": len(chains),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOnehopSinkChainsResult(
            project_path=str(project_path),
            sinks_path=str(sinks_path),
            binary_id=binary_id,
            scanned_helper_call_count=len(helper_rows),
            scanned_helper_sink_call_count=scanned_helper_sink_call_count,
            chain_count=len(chains),
            chains=chains,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "one-hop sink chains are callgraph topology only; argument propagation "
                "and helper side-effect equivalence require separate value-flow facts"
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


def _function_va_by_name(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    name: str | None,
) -> int | None:
    if not name or "function_names" not in present:
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
    row = conn.execute(
        "SELECT entry_va FROM function_names "
        f"WHERE {' AND '.join(clauses)} ORDER BY entry_va LIMIT 1",
        params,
    ).fetchone()
    return int(row[0]) if row else None


def _helper_call_rows(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    caller_va: int | None,
    helper_va: int | None,
) -> list[dict[str, Any]]:
    if "xrefs" not in present:
        return []
    clauses = ["x.kind = 'call'", "x.src_function_va IS NOT NULL"]
    params: list[object] = []
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if caller_va is not None:
        clauses.append("x.src_function_va = ?")
        params.append(caller_va)
    if helper_va is not None:
        clauses.append("x.dst_va = ?")
        params.append(helper_va)
    fn_join = "function_names" in present
    caller_select = (
        "caller.canonical AS caller_name, caller.demangled AS caller_demangled"
        if fn_join
        else "NULL AS caller_name, NULL AS caller_demangled"
    )
    helper_select = (
        "helper.canonical AS helper_name, helper.demangled AS helper_demangled"
        if fn_join
        else "NULL AS helper_name, NULL AS helper_demangled"
    )
    joins = ""
    if fn_join:
        joins = """
LEFT JOIN function_names caller ON
    caller.binary_id = x.binary_id AND caller.entry_va = x.src_function_va
LEFT JOIN function_names helper ON
    helper.binary_id = x.binary_id AND helper.entry_va = x.dst_va
"""
    query = f"""
SELECT
    x.binary_id,
    x.src_function_va AS caller_va,
    {caller_select},
    x.src_va AS helper_callsite_va,
    x.dst_va AS helper_va,
    {helper_select}
FROM xrefs x
{joins}
WHERE {' AND '.join(clauses)}
ORDER BY x.src_va
"""
    return _rows(conn, query, params)


def _helper_sink_rows(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    helper_va: int | None,
) -> list[dict[str, Any]]:
    if "xrefs" not in present:
        return []
    clauses = ["x.kind = 'call'", "x.src_function_va IS NOT NULL"]
    params: list[object] = []
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if helper_va is not None:
        clauses.append("x.src_function_va = ?")
        params.append(helper_va)
    fn_join = "function_names" in present
    sink_select = (
        "sink.canonical AS sink_name, sink.demangled AS sink_demangled"
        if fn_join
        else "NULL AS sink_name, NULL AS sink_demangled"
    )
    joins = ""
    if fn_join:
        joins = """
LEFT JOIN function_names sink ON
    sink.binary_id = x.binary_id AND sink.entry_va = x.dst_va
"""
    query = f"""
SELECT
    x.binary_id,
    x.src_function_va AS helper_va,
    x.src_va AS sink_callsite_va,
    x.dst_va AS sink_va,
    {sink_select}
FROM xrefs x
{joins}
WHERE {' AND '.join(clauses)}
ORDER BY x.src_va
"""
    return _rows(conn, query, params)


def _rows(
    conn: sqlite3.Connection,
    query: str,
    params: list[object],
) -> list[dict[str, Any]]:
    cur = conn.execute(query, params)
    columns = [col[0] for col in cur.description or []]
    return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]


def _sink_rows_by_helper(rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    out: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        out.setdefault(int(row["helper_va"]), []).append(row)
    return out


def _operation_for_row(
    row: dict[str, Any],
    operations_by_symbol: dict[str, OperationRecord],
) -> OperationRecord | None:
    for value in (row.get("sink_name"), row.get("sink_demangled")):
        operation = _operation_for_symbol(value, operations_by_symbol)
        if operation is not None:
            return operation
    return None


def _operation_for_symbol(
    symbol: Any,
    operations_by_symbol: dict[str, OperationRecord],
) -> OperationRecord | None:
    if not isinstance(symbol, str) or not symbol:
        return None
    for key in _symbol_keys(symbol):
        operation = operations_by_symbol.get(key)
        if operation is not None:
            return operation
    return None


def _operations_by_symbol(
    operations: list[OperationRecord],
) -> dict[str, OperationRecord]:
    out: dict[str, OperationRecord] = {}
    for operation in operations:
        for symbol in operation.symbols:
            for key in _symbol_keys(symbol):
                out.setdefault(key, operation)
    return out


def _symbol_matches(name: Any, demangled: Any, expected: str) -> bool:
    expected_keys = set(_symbol_keys(expected))
    for value in (name, demangled):
        if isinstance(value, str) and expected_keys.intersection(_symbol_keys(value)):
            return True
    return False


def _symbol_keys(symbol: str) -> list[str]:
    stripped = symbol.strip()
    short = _short_symbol(stripped)
    return list(dict.fromkeys([stripped, short, stripped.lower(), short.lower()]))


def _short_symbol(symbol: str) -> str:
    return symbol.rsplit("!", 1)[-1]


def _chain_from_rows(
    helper_row: dict[str, Any],
    sink_row: dict[str, Any],
    operation: OperationRecord,
) -> WindowsProjectOnehopSinkChain:
    sink_symbol = (
        sink_row.get("sink_name")
        or sink_row.get("sink_demangled")
        or operation.symbols[0]
    )
    return WindowsProjectOnehopSinkChain(
        binary_id=int(helper_row["binary_id"]),
        caller_va=_int_or_none(helper_row.get("caller_va")),
        caller_name=_str_or_none(helper_row.get("caller_name")),
        caller_demangled=_str_or_none(helper_row.get("caller_demangled")),
        helper_callsite_va=int(helper_row["helper_callsite_va"]),
        helper_va=int(helper_row["helper_va"]),
        helper_name=_str_or_none(helper_row.get("helper_name")),
        helper_demangled=_str_or_none(helper_row.get("helper_demangled")),
        sink_callsite_va=int(sink_row["sink_callsite_va"]),
        sink_va=int(sink_row["sink_va"]),
        sink_symbol=str(sink_symbol),
        sink_kind=operation.sink_kind,
        sink_effects=list(operation.effects),
        required_gates=list(operation.required_gates),
        provenance=[
            "persisted_project_call_xrefs",
            "asb_pe_sink_metadata",
            "onehop_callgraph_topology",
        ],
    )


def _coverage(
    present: set[str],
    helper_rows: list[dict[str, Any]],
    chains: list[WindowsProjectOnehopSinkChain],
) -> list[str]:
    coverage: list[str] = []
    if "xrefs" in present and helper_rows:
        coverage.append("project_call_xrefs")
    if "function_names" in present:
        coverage.append("project_function_names")
    if chains:
        coverage.append("project_onehop_sink_chains")
    return coverage


def _missing_capabilities(
    present: set[str],
    helper_rows: list[dict[str, Any]],
    chains: list[WindowsProjectOnehopSinkChain],
) -> list[str]:
    missing: list[str] = []
    if "xrefs" not in present or not helper_rows:
        missing.append("project_call_xrefs")
    if "function_names" not in present:
        missing.append("project_function_names")
    if not chains:
        missing.append("project_onehop_sink_chains")
    missing.extend(["helper_argument_propagation", "interprocedural_value_equivalence"])
    return missing


def _int_or_none(value: Any) -> int | None:
    return int(value) if value is not None else None


def _str_or_none(value: Any) -> str | None:
    return str(value) if value is not None else None


def build_tool() -> WindowsProjectOnehopSinkChainsTool:
    return WindowsProjectOnehopSinkChainsTool()
