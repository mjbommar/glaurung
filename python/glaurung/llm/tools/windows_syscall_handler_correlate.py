from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_syscall_stub_atlas import (
    ServiceTableKind,
    SyscallDispatchKind,
    WindowsSyscallStubAtlasArgs,
    WindowsSyscallStubAtlasTool,
)


HandlerSource = Literal[
    "kernel_project_function_names",
    "external_handler_map",
    "missing",
]


class SyscallHandlerCorrelationRow(BaseModel):
    user_stub_symbol: str
    syscall_number: int
    syscall_hex: str
    user_stub_module: str | None = None
    service_table: ServiceTableKind
    dispatch_kind: SyscallDispatchKind = "unknown"
    stub_shape: str = "unknown"
    has_kuser_shared_data_gate: bool = False
    has_int2e_fallback: bool = False
    handler_name: str | None = None
    handler_va: int | None = None
    handler_module: str | None = None
    handler_source: HandlerSource
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class WindowsSyscallHandlerCorrelateArgs(BaseModel):
    binary_path: str | None = Field(
        None,
        description="Optional user-mode PE path, for example ntdll.dll or win32u.dll.",
    )
    pseudocode: str = Field(
        "",
        description="Optional lifted/text syscall stubs.",
    )
    raw_bytes_hex: str | None = Field(
        None,
        description="Optional raw x64 syscall-stub bytes as hex.",
    )
    user_stub_module: str | None = Field(
        None,
        description="Optional user-mode module name.",
    )
    service_table: ServiceTableKind = Field(
        "unknown",
        description="Optional expected service-table family.",
    )
    kernel_project_path: str | None = Field(
        None,
        description=(
            "Optional .glaurung project for ntoskrnl/win32k PDB function-name "
            "correlation."
        ),
    )
    kernel_binary_id: int | None = Field(
        None,
        description="Optional binary_id filter for the kernel project function_names table.",
    )
    handler_map_json: str | None = Field(
        None,
        description=(
            "Optional precomputed handler map JSON. Accepts a list of rows or a "
            "dict keyed by stub symbol or syscall number."
        ),
    )
    max_stubs: int = Field(4096, ge=1, description="Maximum syscall stubs to inspect.")
    max_rows: int = Field(
        64,
        ge=0,
        description="Maximum correlation rows to return. Use 0 for summary only.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact syscall-handler-correlation evidence node.",
    )


class WindowsSyscallHandlerCorrelateResult(BaseModel):
    syscall_count: int
    correlated_count: int
    project_correlated_count: int
    external_correlated_count: int
    missing_handler_count: int
    filtered_row_count: int
    rows: list[SyscallHandlerCorrelationRow]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSyscallHandlerCorrelateTool(
    MemoryTool[
        WindowsSyscallHandlerCorrelateArgs,
        WindowsSyscallHandlerCorrelateResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_syscall_handler_correlate",
                description=(
                    "Correlate user-mode Windows syscall stubs to kernel handler "
                    "symbols using a .glaurung PDB-backed function_names table or "
                    "an externally materialized handler map."
                ),
                tags=("windows", "pe", "syscall", "ssdt", "pdb", "correlation"),
            ),
            WindowsSyscallHandlerCorrelateArgs,
            WindowsSyscallHandlerCorrelateResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSyscallHandlerCorrelateArgs,
    ) -> WindowsSyscallHandlerCorrelateResult:
        atlas = WindowsSyscallStubAtlasTool().run(
            ctx,
            kb,
            WindowsSyscallStubAtlasArgs(
                binary_path=args.binary_path,
                pseudocode=args.pseudocode,
                raw_bytes_hex=args.raw_bytes_hex,
                user_stub_module=args.user_stub_module,
                service_table=args.service_table,
                max_stubs=args.max_stubs,
            ),
        )
        project_handlers = _project_handlers(
            args.kernel_project_path, args.kernel_binary_id
        )
        external_handlers = _external_handlers(args.handler_map_json)
        rows = [
            _correlate_stub(stub, project_handlers, external_handlers)
            for stub in atlas.stubs
        ]
        correlated = [row for row in rows if row.handler_source != "missing"]
        project_correlated = [
            row for row in rows if row.handler_source == "kernel_project_function_names"
        ]
        external_correlated = [
            row for row in rows if row.handler_source == "external_handler_map"
        ]
        missing = [row for row in rows if row.handler_source == "missing"]
        result_rows = rows[: args.max_rows] if args.max_rows else []

        coverage = list(atlas.coverage)
        if project_handlers:
            coverage.append("kernel_project_function_names")
        if external_handlers.by_symbol or external_handlers.by_number:
            coverage.append("external_handler_map")
        if correlated:
            coverage.append("syscall_handler_correlation")
        missing_capabilities = []
        if not atlas.stubs:
            missing_capabilities.append("syscall_stubs")
        if not (
            project_handlers
            or external_handlers.by_symbol
            or external_handlers.by_number
        ):
            missing_capabilities.append("kernel_handler_map")
        if atlas.stubs and not correlated:
            missing_capabilities.append("syscall_handler_correlation")

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_syscall_handler_correlate",
                    props={
                        "binary_path": args.binary_path,
                        "kernel_project_path": args.kernel_project_path,
                        "syscall_count": atlas.syscall_count,
                        "correlated_count": len(correlated),
                        "missing_handler_count": len(missing),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSyscallHandlerCorrelateResult(
            syscall_count=atlas.syscall_count,
            correlated_count=len(correlated),
            project_correlated_count=len(project_correlated),
            external_correlated_count=len(external_correlated),
            missing_handler_count=len(missing),
            filtered_row_count=len(rows),
            rows=result_rows,
            coverage=coverage,
            missing_capabilities=missing_capabilities,
            evidence_node_id=evidence_node_id,
            notes=[
                "name/map correlation links user stubs to likely kernel handlers; "
                "it does not prove live SSDT contents or hook state"
            ],
        )


class _HandlerRecord(BaseModel):
    handler_name: str
    handler_va: int | None = None
    handler_module: str | None = None
    source: HandlerSource
    evidence: list[str] = Field(default_factory=list)


class _ExternalHandlerMaps(BaseModel):
    by_symbol: dict[str, _HandlerRecord] = Field(default_factory=dict)
    by_number: dict[int, _HandlerRecord] = Field(default_factory=dict)


def _project_handlers(
    project_path: str | None,
    binary_id: int | None,
) -> dict[str, _HandlerRecord]:
    if not project_path:
        return {}
    path = Path(project_path)
    if not path.exists():
        raise ValueError(f"{path}: .glaurung project does not exist")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        present = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if "function_names" not in present:
            return {}
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(function_names)")
        }
        if not {"canonical", "entry_va"}.issubset(columns):
            return {}
        query = "SELECT canonical, entry_va FROM function_names"
        params: list[object] = []
        if binary_id is not None and "binary_id" in columns:
            query += " WHERE binary_id = ?"
            params.append(binary_id)
        query += " ORDER BY entry_va"
        handlers: dict[str, _HandlerRecord] = {}
        for name, va in conn.execute(query, params).fetchall():
            symbol = str(name)
            if not symbol or symbol in handlers:
                continue
            handlers[symbol] = _HandlerRecord(
                handler_name=symbol,
                handler_va=int(va),
                source="kernel_project_function_names",
                evidence=[f"function_names:{symbol}@0x{int(va):x}"],
            )
        return handlers
    finally:
        conn.close()


def _external_handlers(raw_json: str | None) -> _ExternalHandlerMaps:
    maps = _ExternalHandlerMaps()
    if not raw_json:
        return maps
    raw = json.loads(raw_json)
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                _add_external_record(maps, item)
    elif isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict):
                item = dict(value)
                item.setdefault("symbol", key)
                item.setdefault("syscall_number", key)
                _add_external_record(maps, item)
    return maps


def _add_external_record(
    maps: _ExternalHandlerMaps,
    item: dict,
) -> None:
    handler_name = str(
        item.get("handler_name") or item.get("handler") or item.get("symbol") or ""
    )
    if not handler_name:
        return
    record = _HandlerRecord(
        handler_name=handler_name,
        handler_va=_int_or_none(item.get("handler_va") or item.get("va")),
        handler_module=None
        if item.get("handler_module") is None
        else str(item.get("handler_module")),
        source="external_handler_map",
        evidence=["external_handler_map"],
    )
    symbol = item.get("symbol") or item.get("user_stub_symbol")
    if symbol is not None:
        maps.by_symbol[str(symbol)] = record
    number = _int_or_none(item.get("syscall_number") or item.get("number"))
    if number is not None:
        maps.by_number[number] = record


def _correlate_stub(
    stub,
    project_handlers: dict[str, _HandlerRecord],
    external_handlers: _ExternalHandlerMaps,
) -> SyscallHandlerCorrelationRow:
    handler = project_handlers.get(stub.user_stub_symbol)
    if handler is None:
        handler = external_handlers.by_symbol.get(stub.user_stub_symbol)
    if handler is None:
        handler = external_handlers.by_number.get(stub.syscall_number)
    if handler is None:
        return SyscallHandlerCorrelationRow(
            user_stub_symbol=stub.user_stub_symbol,
            syscall_number=stub.syscall_number,
            syscall_hex=stub.syscall_hex,
            user_stub_module=stub.user_stub_module,
            service_table=stub.service_table,
            dispatch_kind=stub.dispatch_kind,
            stub_shape=stub.stub_shape,
            has_kuser_shared_data_gate=stub.has_kuser_shared_data_gate,
            has_int2e_fallback=stub.has_int2e_fallback,
            handler_source="missing",
            confidence=0.0,
            evidence=["no project function-name or external handler-map match"],
        )
    confidence = 0.86 if handler.source == "kernel_project_function_names" else 0.78
    return SyscallHandlerCorrelationRow(
        user_stub_symbol=stub.user_stub_symbol,
        syscall_number=stub.syscall_number,
        syscall_hex=stub.syscall_hex,
        user_stub_module=stub.user_stub_module,
        service_table=stub.service_table,
        dispatch_kind=stub.dispatch_kind,
        stub_shape=stub.stub_shape,
        has_kuser_shared_data_gate=stub.has_kuser_shared_data_gate,
        has_int2e_fallback=stub.has_int2e_fallback,
        handler_name=handler.handler_name,
        handler_va=handler.handler_va,
        handler_module=handler.handler_module,
        handler_source=handler.source,
        confidence=confidence,
        evidence=[
            *stub.evidence[:3],
            *handler.evidence[:3],
        ],
    )


def _int_or_none(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def build_tool() -> WindowsSyscallHandlerCorrelateTool:
    return WindowsSyscallHandlerCorrelateTool()
