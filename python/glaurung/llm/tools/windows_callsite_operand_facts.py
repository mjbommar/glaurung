from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_operation_metadata import OperationRecord
from .windows_source_sink_operand_match import (
    _normalize_expression,
    _split_args,
    _symbol_keys,
)
from .windows_surface_metadata import _resolve_metadata_path
from .windows_trace_arg_flow import _arg_roles, _required_str, _required_str_list


_CONTROL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "catch",
    "__try",
    "__except",
}


class WindowsCallsiteOperandFactsArgs(BaseModel):
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    function_va: int | None = Field(
        None,
        description="Optional function VA. When supplied, the tool decompiles and scans it.",
    )
    pseudocode: str | None = Field(
        None,
        description="Optional pseudocode or source-like text to scan for call arguments.",
    )
    call_symbol: str | None = Field(
        None,
        description="Optional call symbol filter, e.g. RtlCopyMemory or nt!RtlCopyMemory.",
    )
    operation_only: bool = Field(
        False,
        description="If true, return only calls that match ASB operation/sink metadata.",
    )
    max_calls: int = Field(64, description="Maximum callsites to return.")
    timeout_ms: int = Field(500, description="Decompile timeout when function_va is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact callsite operand evidence node to the KB.",
    )


class CallsiteArgumentFact(BaseModel):
    index: int
    expression: str
    normalized_expression: str
    role: str | None = None
    provenance: list[str] = Field(default_factory=list)


class CallsiteOperandFact(BaseModel):
    symbol: str
    matched_symbol: str | None = None
    callsite_va: int | None = None
    line: int | None = None
    snippet: str | None = None
    arguments: list[CallsiteArgumentFact]
    operation: OperationRecord | None = None
    evidence_kind: str
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsCallsiteOperandFactsResult(BaseModel):
    sinks_path: str
    function_va: int | None = None
    callsites: list[CallsiteOperandFact]
    scanned_call_count: int
    operation_count_total: int
    pseudocode_source: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsCallsiteOperandFactsTool(
    MemoryTool[WindowsCallsiteOperandFactsArgs, WindowsCallsiteOperandFactsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_callsite_operand_facts",
                description=(
                    "Enumerate structured callsite argument facts and attach "
                    "Windows operation/sink argument roles when metadata matches."
                ),
                tags=("windows", "pe", "callsites", "operands", "sinks"),
            ),
            WindowsCallsiteOperandFactsArgs,
            WindowsCallsiteOperandFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsCallsiteOperandFactsArgs,
    ) -> WindowsCallsiteOperandFactsResult:
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        operations = [_operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)]
        operations_by_symbol = _operations_by_symbol(operations)
        text, source, notes = _scan_text(ctx, args)
        calls = _extract_calls(text)

        facts: list[CallsiteOperandFact] = []
        for call in calls:
            if args.call_symbol and not _symbol_matches(call.name, args.call_symbol):
                continue
            operation = _first_operation(call.name, operations_by_symbol)
            if args.operation_only and operation is None:
                continue
            facts.append(_callsite_fact(call, operation, source))
            if len(facts) >= args.max_calls:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_callsite_operand_facts",
                    props={
                        "function_va": args.function_va,
                        "callsite_count": len(facts),
                        "scanned_call_count": len(calls),
                        "call_symbol": args.call_symbol,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsCallsiteOperandFactsResult(
            sinks_path=str(sinks_path),
            function_va=args.function_va,
            callsites=facts,
            scanned_call_count=len(calls),
            operation_count_total=len(operations),
            pseudocode_source=source,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


class _Call(BaseModel):
    name: str
    args: list[str]
    line: int
    snippet: str
    callsite_va: int | None = None


def _scan_text(
    ctx: MemoryContext,
    args: WindowsCallsiteOperandFactsArgs,
) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if args.pseudocode:
        return args.pseudocode, "supplied_pseudocode", notes
    if args.function_va is None:
        notes.append("no pseudocode or function_va supplied")
        return "", "none", notes
    try:
        text = g.ir.decompile_at(
            str(ctx.file_path),
            int(args.function_va),
            timeout_ms=max(200, int(args.timeout_ms)),
            style="c",
            pdb_cache=args.pdb_cache,
        )
        return text, "glaurung_decompiler", notes
    except Exception as exc:
        notes.append(f"decompile failed: {exc}")
        return "", "glaurung_decompiler_failed", notes


def _extract_calls(text: str) -> list[_Call]:
    calls: list[_Call] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in re.finditer(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_!:.$@]*)\s*\((?P<args>[^;]*)\)\s*;",
            line,
        ):
            name = match.group("name")
            if name.lower() in _CONTROL_WORDS:
                continue
            calls.append(
                _Call(
                    name=name,
                    args=_split_args(match.group("args")),
                    line=line_no,
                    snippet=line.strip(),
                    callsite_va=_extract_callsite_va(line),
                )
            )
    return calls


def _extract_callsite_va(line: str) -> int | None:
    for pattern in (
        r"callsite(?:_va)?\s*[:=]\s*(0x[0-9a-fA-F]+)",
        r"@\s*(0x[0-9a-fA-F]+)",
        r"/\*\s*(0x[0-9a-fA-F]+)\s*\*/",
    ):
        match = re.search(pattern, line)
        if match:
            return int(match.group(1), 16)
    return None


def _callsite_fact(
    call: _Call,
    operation: OperationRecord | None,
    source: str,
) -> CallsiteOperandFact:
    matched_symbol = _matched_symbol(call.name, operation) if operation else None
    provenance = [source]
    if operation:
        provenance.append("asb_pe_sink_metadata")
    return CallsiteOperandFact(
        symbol=call.name,
        matched_symbol=matched_symbol,
        callsite_va=call.callsite_va,
        line=call.line,
        snippet=call.snippet,
        arguments=[
            CallsiteArgumentFact(
                index=idx,
                expression=arg.strip(),
                normalized_expression=_normalize_expression(arg),
                role=_arg_role(operation, idx),
                provenance=provenance.copy(),
            )
            for idx, arg in enumerate(call.args)
        ],
        operation=operation,
        evidence_kind="pseudocode_callsite_operands",
        confidence=0.74 if operation else 0.55,
        provenance=provenance,
    )


def _arg_role(operation: OperationRecord | None, index: int) -> str | None:
    if operation is None:
        return None
    for role in operation.arg_roles:
        if role.index == index:
            return role.role
    return None


def _operations_by_symbol(
    operations: list[OperationRecord],
) -> dict[str, list[OperationRecord]]:
    out: dict[str, list[OperationRecord]] = {}
    for operation in operations:
        for symbol in operation.symbols:
            for key in _symbol_keys(symbol):
                out.setdefault(key, []).append(operation)
    return out


def _first_operation(
    call_name: str,
    operations_by_symbol: dict[str, list[OperationRecord]],
) -> OperationRecord | None:
    for key in _symbol_keys(call_name):
        matches = operations_by_symbol.get(key)
        if matches:
            return matches[0]
    return None


def _matched_symbol(call_name: str, operation: OperationRecord | None) -> str | None:
    if operation is None:
        return None
    call_keys = set(_symbol_keys(call_name))
    for symbol in operation.symbols:
        if call_keys & set(_symbol_keys(symbol)):
            return symbol
    return None


def _symbol_matches(left: str, right: str) -> bool:
    return bool(set(_symbol_keys(left)) & set(_symbol_keys(right)))


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: operation entry {idx} is not a mapping")
        out.append(entry)
    return out


def _operation_record(entry: dict[str, Any], path: Path) -> OperationRecord:
    return OperationRecord(
        id=_required_str(entry, "id", path),
        symbols=_required_str_list(entry, "symbols", path),
        sink_kind=_required_str(entry, "sink_kind", path),
        effects=[str(x) for x in entry.get("effects") or []],
        arg_roles=_arg_roles(entry.get("arg_roles"), path, entry.get("id")),
        required_gates=[str(x) for x in entry.get("required_gates") or []],
        notes=entry.get("notes"),
    )


def build_tool() -> MemoryTool[
    WindowsCallsiteOperandFactsArgs, WindowsCallsiteOperandFactsResult
]:
    return WindowsCallsiteOperandFactsTool()
