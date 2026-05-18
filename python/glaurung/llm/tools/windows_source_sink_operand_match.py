from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_operation_metadata import OperationRecord
from .windows_surface_metadata import _resolve_metadata_path
from .windows_trace_arg_flow import AliasStep


OperandMatchStatus = Literal[
    "exact",
    "alias",
    "transformed",
    "mismatch",
    "sink_not_found",
    "source_unknown",
]


class WindowsSourceSinkOperandMatchArgs(BaseModel):
    source_arg_index: int | None = Field(
        None,
        description="Zero-based source argument index to derive from the function signature.",
    )
    source_name: str | None = Field(
        None,
        description="Source variable name to trace. Used directly or derived from source_arg_index.",
    )
    sink_symbol: str = Field(..., description="Sink call symbol to inspect.")
    sink_arg_index: int = Field(..., description="Zero-based sink argument index to compare.")
    pseudocode: str | None = Field(
        None,
        description="Optional pseudocode or source-like text to inspect.",
    )
    function_va: int | None = Field(
        None,
        description="Optional function VA. When supplied, the tool decompiles and inspects it.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    max_depth: int = Field(2, description="Maximum simple alias depth.")
    timeout_ms: int = Field(500, description="Decompile timeout when function_va is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact source/sink operand evidence node to the KB.",
    )


class SinkOperandSite(BaseModel):
    symbol: str
    arg_index: int
    expression: str
    line: int
    snippet: str
    operation: OperationRecord | None = None
    arg_role: str | None = None


class WindowsSourceSinkOperandMatchResult(BaseModel):
    function_va: int | None = None
    source_name: str | None = None
    sink: SinkOperandSite | None = None
    aliases: list[AliasStep] = Field(default_factory=list)
    matched_name: str | None = None
    status: OperandMatchStatus
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    pseudocode_source: str
    provenance: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSourceSinkOperandMatchTool(
    MemoryTool[
        WindowsSourceSinkOperandMatchArgs,
        WindowsSourceSinkOperandMatchResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_source_sink_operand_match",
                description=(
                    "Check whether a traced source value is the same value "
                    "consumed by a selected sink argument."
                ),
                tags=("windows", "pe", "flow", "operands", "sinks"),
            ),
            WindowsSourceSinkOperandMatchArgs,
            WindowsSourceSinkOperandMatchResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSourceSinkOperandMatchArgs,
    ) -> WindowsSourceSinkOperandMatchResult:
        text, source, notes = _scan_text(ctx, args)
        source_name = args.source_name or _source_name_from_signature(
            text,
            args.source_arg_index,
        )
        if not source_name:
            result = _result(
                args,
                source,
                notes,
                None,
                [],
                None,
                None,
                "source_unknown",
                0.0,
                "source_name could not be resolved",
            )
            return _maybe_add_evidence(ctx, kb, args, result)

        aliases = _trace_aliases(text, source_name, max_depth=args.max_depth)
        tracked = {source_name} | {alias.name for alias in aliases}
        operations = _load_operations(args.sinks_path)
        operation = _first_operation(args.sink_symbol, _operations_by_symbol(operations))
        sink = _find_sink(text, args, operation)
        if sink is None:
            result = _result(
                args,
                source,
                notes,
                source_name,
                aliases,
                None,
                None,
                "sink_not_found",
                0.1,
                f"sink {args.sink_symbol} arg{args.sink_arg_index} was not found",
            )
            return _maybe_add_evidence(ctx, kb, args, result)

        status, matched_name, confidence, reason = _match_operand(
            source_name,
            aliases,
            tracked,
            sink.expression,
        )
        result = _result(
            args,
            source,
            notes,
            source_name,
            aliases,
            sink,
            matched_name,
            status,
            confidence,
            reason,
        )
        return _maybe_add_evidence(ctx, kb, args, result)


class _Call(BaseModel):
    name: str
    args: list[str]
    line: int
    snippet: str


def _scan_text(
    ctx: MemoryContext,
    args: WindowsSourceSinkOperandMatchArgs,
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


def _source_name_from_signature(text: str, index: int | None) -> str | None:
    if index is None:
        return None
    match = re.search(r"\((?P<params>[^)]*)\)", text, flags=re.S)
    if not match:
        return None
    params = _split_args(match.group("params"))
    if index < 0 or index >= len(params):
        return None
    param = params[index].strip()
    name_match = re.search(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*$", param)
    return name_match.group("name") if name_match else None


def _trace_aliases(text: str, source_name: str, *, max_depth: int) -> list[AliasStep]:
    aliases: list[AliasStep] = []
    known_depth: dict[str, int] = {source_name: 0}
    assignment_re = re.compile(
        r"\b(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[^;]+);"
    )
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in assignment_re.finditer(line):
            lhs = match.group("lhs")
            rhs = match.group("rhs")
            source = _rhs_known_name(rhs, known_depth)
            if source is None:
                continue
            depth = known_depth[source] + 1
            if depth > max_depth or lhs in known_depth:
                continue
            known_depth[lhs] = depth
            aliases.append(
                AliasStep(
                    name=lhs,
                    source=source,
                    line=line_no,
                    snippet=line.strip(),
                    depth=depth,
                )
            )
    return aliases


def _rhs_known_name(rhs: str, known_depth: dict[str, int]) -> str | None:
    for name in known_depth:
        if re.search(rf"\b{re.escape(name)}\b", rhs):
            return name
    return None


def _find_sink(
    text: str,
    args: WindowsSourceSinkOperandMatchArgs,
    operation: OperationRecord | None,
) -> SinkOperandSite | None:
    for call in _extract_calls(text):
        if not _symbol_matches(call.name, args.sink_symbol):
            continue
        if args.sink_arg_index < 0 or args.sink_arg_index >= len(call.args):
            continue
        return SinkOperandSite(
            symbol=call.name,
            arg_index=args.sink_arg_index,
            expression=call.args[args.sink_arg_index].strip(),
            line=call.line,
            snippet=call.snippet,
            operation=operation,
            arg_role=_arg_role(operation, args.sink_arg_index),
        )
    return None


def _extract_calls(text: str) -> list[_Call]:
    calls: list[_Call] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in re.finditer(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_!:.$@]*)\s*\((?P<args>[^;]*)\)\s*;",
            line,
        ):
            calls.append(
                _Call(
                    name=match.group("name"),
                    args=_split_args(match.group("args")),
                    line=line_no,
                    snippet=line.strip(),
                )
            )
    return calls


def _match_operand(
    source_name: str,
    aliases: list[AliasStep],
    tracked: set[str],
    expression: str,
) -> tuple[OperandMatchStatus, str | None, float, str]:
    normalized = _normalize_expression(expression)
    if normalized == source_name:
        return "exact", source_name, 0.9, f"sink argument is exactly {source_name}"
    alias_names = {alias.name for alias in aliases}
    if normalized in alias_names:
        return "alias", normalized, 0.82, f"sink argument is alias {normalized}"
    for name in tracked:
        if re.search(rf"\b{re.escape(name)}\b", expression):
            return (
                "transformed",
                name,
                0.6,
                f"sink argument expression contains traced value {name}",
            )
    return (
        "mismatch",
        None,
        0.75,
        f"sink argument expression {expression!r} does not reference traced source",
    )


def _normalize_expression(expression: str) -> str:
    value = expression.strip()
    changed = True
    while changed:
        changed = False
        new = re.sub(r"^\((?:const\s+)?[A-Za-z_][A-Za-z0-9_\s\*]*\)\s*", "", value).strip()
        if new != value:
            value = new
            changed = True
        for prefix in ("&", "*"):
            if value.startswith(prefix):
                value = value[1:].strip()
                changed = True
        if value.startswith("(") and value.endswith(")") and _balanced(value[1:-1]):
            value = value[1:-1].strip()
            changed = True
    return value


def _balanced(value: str) -> bool:
    depth = 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _arg_role(operation: OperationRecord | None, index: int) -> str | None:
    if operation is None:
        return None
    for role in operation.arg_roles:
        if role.index == index:
            return role.role
    return None


def _load_operations(sinks_path: str | None) -> list[OperationRecord]:
    path = _resolve_metadata_path(sinks_path, "data/kg/pe-sinks.yaml")
    return [_operation_record(entry, path) for entry in _load_yaml_list(path)]


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
    from .windows_trace_arg_flow import _arg_roles, _required_str, _required_str_list

    return OperationRecord(
        id=_required_str(entry, "id", path),
        symbols=_required_str_list(entry, "symbols", path),
        sink_kind=_required_str(entry, "sink_kind", path),
        effects=[str(x) for x in entry.get("effects") or []],
        arg_roles=_arg_roles(entry.get("arg_roles"), path, entry.get("id")),
        required_gates=[str(x) for x in entry.get("required_gates") or []],
        notes=entry.get("notes"),
    )


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


def _symbol_matches(left: str, right: str) -> bool:
    return bool(set(_symbol_keys(left)) & set(_symbol_keys(right)))


def _symbol_keys(symbol: str) -> list[str]:
    raw = symbol.strip()
    if not raw:
        return []
    suffix = raw.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
    return [raw.lower(), suffix.lower()]


def _split_args(raw: str) -> list[str]:
    args: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(raw):
        if ch in "([":
            depth += 1
        elif ch in ")]" and depth:
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(raw[start:idx].strip())
            start = idx + 1
    tail = raw[start:].strip()
    if tail:
        args.append(tail)
    return args


def _result(
    args: WindowsSourceSinkOperandMatchArgs,
    pseudocode_source: str,
    notes: list[str],
    source_name: str | None,
    aliases: list[AliasStep],
    sink: SinkOperandSite | None,
    matched_name: str | None,
    status: OperandMatchStatus,
    confidence: float,
    reason: str,
) -> WindowsSourceSinkOperandMatchResult:
    provenance = [pseudocode_source]
    if sink and sink.operation:
        provenance.append("asb_pe_sink_metadata")
    if aliases:
        provenance.append("simple_alias_trace")
    return WindowsSourceSinkOperandMatchResult(
        function_va=args.function_va,
        source_name=source_name,
        sink=sink,
        aliases=aliases,
        matched_name=matched_name,
        status=status,
        confidence=confidence,
        reason=reason,
        pseudocode_source=pseudocode_source,
        provenance=provenance,
        notes=notes,
    )


def _maybe_add_evidence(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsSourceSinkOperandMatchArgs,
    result: WindowsSourceSinkOperandMatchResult,
) -> WindowsSourceSinkOperandMatchResult:
    if not args.add_to_kb:
        return result
    node = kb.add_node(
        Node(
            kind=NodeKind.evidence,
            label="windows_source_sink_operand_match",
            props={
                "function_va": args.function_va,
                "source_name": result.source_name,
                "sink_symbol": args.sink_symbol,
                "sink_arg_index": args.sink_arg_index,
                "status": result.status,
                "confidence": result.confidence,
            },
        )
    )
    result.evidence_node_id = node.id
    file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
    if file_node:
        kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
    return result


def build_tool() -> WindowsSourceSinkOperandMatchTool:
    return WindowsSourceSinkOperandMatchTool()
