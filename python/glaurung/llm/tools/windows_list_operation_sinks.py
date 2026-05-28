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
from .windows_operation_metadata import OperationArgRole, OperationRecord
from .windows_surface_metadata import _resolve_metadata_path


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


class WindowsListOperationSinksArgs(BaseModel):
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
        description="Optional pseudocode or source-like text to scan for operation calls.",
    )
    sink_kind: str | None = Field(
        None,
        description="Optional operation kind filter, e.g. copy, free, completion, lock.",
    )
    max_sinks: int = Field(64, description="Maximum operation hits to return.")
    timeout_ms: int = Field(500, description="Decompile timeout when function_va is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-sink evidence node to the KB.",
    )


class OperationSinkHit(BaseModel):
    symbol: str
    matched_text: str
    operation: OperationRecord
    line: int | None = None
    snippet: str | None = None
    evidence_kind: str
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsListOperationSinksResult(BaseModel):
    sinks_path: str
    function_va: int | None = None
    sinks: list[OperationSinkHit]
    scanned_call_count: int
    operation_count_total: int
    pseudocode_source: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsListOperationSinksTool(
    MemoryTool[WindowsListOperationSinksArgs, WindowsListOperationSinksResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_list_operation_sinks",
                description=(
                    "List Windows security-relevant operation calls in "
                    "pseudocode by joining call names to ASB pe-sinks metadata."
                ),
                tags=("windows", "pe", "sinks", "operations", "pseudocode"),
            ),
            WindowsListOperationSinksArgs,
            WindowsListOperationSinksResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsListOperationSinksArgs,
    ) -> WindowsListOperationSinksResult:
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        operations = [_operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)]
        operations_by_symbol = _operations_by_symbol(operations)
        text, source, notes = _scan_text(ctx, args)
        calls = _extract_calls(text)

        hits: list[OperationSinkHit] = []
        for call in calls:
            for op in _matching_operations(call.name, operations_by_symbol):
                if args.sink_kind and op.sink_kind != args.sink_kind:
                    continue
                hits.append(
                    OperationSinkHit(
                        symbol=_matched_symbol(call.name, op) or call.name,
                        matched_text=call.name,
                        operation=op,
                        line=call.line,
                        snippet=call.snippet,
                        evidence_kind="pseudocode_call",
                        confidence=0.7,
                        provenance=["asb_pe_sink_metadata", source],
                    )
                )
                if len(hits) >= args.max_sinks:
                    break
            if len(hits) >= args.max_sinks:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_list_operation_sinks",
                    props={
                        "function_va": args.function_va,
                        "sink_matches": len(hits),
                        "scanned_call_count": len(calls),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsListOperationSinksResult(
            sinks_path=str(sinks_path),
            function_va=args.function_va,
            sinks=hits,
            scanned_call_count=len(calls),
            operation_count_total=len(operations),
            pseudocode_source=source,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


class _Call(BaseModel):
    name: str
    line: int
    snippet: str


def _scan_text(
    ctx: MemoryContext,
    args: WindowsListOperationSinksArgs,
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
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_!:.$@]*)\s*\(",
            line,
        ):
            name = match.group("name")
            if name.lower() in _CONTROL_WORDS:
                continue
            calls.append(_Call(name=name, line=line_no, snippet=line.strip()))
    return calls


def _operations_by_symbol(
    operations: list[OperationRecord],
) -> dict[str, list[OperationRecord]]:
    out: dict[str, list[OperationRecord]] = {}
    for operation in operations:
        for symbol in operation.symbols:
            for key in _symbol_keys(symbol):
                out.setdefault(key, []).append(operation)
    return out


def _matching_operations(
    call_name: str,
    operations_by_symbol: dict[str, list[OperationRecord]],
) -> list[OperationRecord]:
    matches: list[OperationRecord] = []
    seen: set[str] = set()
    for key in _symbol_keys(call_name):
        for operation in operations_by_symbol.get(key, []):
            if operation.id not in seen:
                seen.add(operation.id)
                matches.append(operation)
    return matches


def _matched_symbol(call_name: str, operation: OperationRecord) -> str | None:
    call_keys = set(_symbol_keys(call_name))
    for symbol in operation.symbols:
        if call_keys & set(_symbol_keys(symbol)):
            return symbol
    return None


def _symbol_keys(symbol: str) -> list[str]:
    raw = symbol.strip()
    if not raw:
        return []
    suffix = raw.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
    return [raw.lower(), suffix.lower()]


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


def _arg_roles(raw: Any, path: Path, owner: Any) -> list[OperationArgRole]:
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path}: operation {owner!r} missing non-empty arg_roles")
    roles = []
    for key, value in raw.items():
        roles.append(OperationArgRole(index=int(key), role=str(value)))
    return sorted(roles, key=lambda role: role.index)


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty list field {key!r}")
    return [str(v) for v in values if str(v)]


def build_tool() -> MemoryTool[
    WindowsListOperationSinksArgs, WindowsListOperationSinksResult
]:
    return WindowsListOperationSinksTool()
