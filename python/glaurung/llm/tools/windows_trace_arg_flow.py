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
from .windows_surface_metadata import _resolve_metadata_path


class WindowsTraceArgFlowArgs(BaseModel):
    source_arg_index: int | None = Field(
        None,
        description="Zero-based source argument index to trace from the function signature.",
    )
    source_name: str | None = Field(
        None,
        description="Source variable name to trace. Used directly or derived from source_arg_index.",
    )
    pseudocode: str | None = Field(
        None,
        description="Optional pseudocode or source-like text to trace.",
    )
    function_va: int | None = Field(
        None,
        description="Optional function VA. When supplied, the tool decompiles and traces it.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    max_depth: int = Field(2, description="Maximum simple alias depth.")
    max_flows: int = Field(64, description="Maximum call-argument flow hits.")
    timeout_ms: int = Field(500, description="Decompile timeout when function_va is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact argument-flow evidence node to the KB.",
    )


class AliasStep(BaseModel):
    name: str
    source: str
    line: int
    snippet: str
    depth: int


class ArgFlowHit(BaseModel):
    callee: str
    callee_arg_index: int
    expression: str
    line: int
    snippet: str
    matched_name: str
    operation: OperationRecord | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsTraceArgFlowResult(BaseModel):
    function_va: int | None = None
    source_name: str | None = None
    aliases: list[AliasStep]
    flows: list[ArgFlowHit]
    scanned_call_count: int
    pseudocode_source: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsTraceArgFlowTool(
    MemoryTool[WindowsTraceArgFlowArgs, WindowsTraceArgFlowResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_trace_arg_flow",
                description=(
                    "Trace one Windows function argument through simple aliases "
                    "into helper-call arguments using pseudocode evidence."
                ),
                tags=("windows", "pe", "flow", "arguments", "pseudocode"),
            ),
            WindowsTraceArgFlowArgs,
            WindowsTraceArgFlowResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsTraceArgFlowArgs,
    ) -> WindowsTraceArgFlowResult:
        text, source, notes = _scan_text(ctx, args)
        source_name = args.source_name or _source_name_from_signature(
            text, args.source_arg_index
        )
        if not source_name:
            notes.append("source_name could not be resolved")
            return _result(args, source, notes, source_name, [], [], 0, None)

        aliases = _trace_aliases(text, source_name, max_depth=args.max_depth)
        tracked_names = {source_name} | {alias.name for alias in aliases}
        operations = _load_operations(args.sinks_path)
        operations_by_symbol = _operations_by_symbol(operations)
        calls = _extract_calls(text)
        flows = _flow_hits(
            calls,
            tracked_names,
            operations_by_symbol,
            max_flows=args.max_flows,
            provenance_source=source,
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_trace_arg_flow",
                    props={
                        "function_va": args.function_va,
                        "source_name": source_name,
                        "flow_matches": len(flows),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return _result(
            args,
            source,
            notes,
            source_name,
            aliases,
            flows,
            len(calls),
            evidence_node_id,
        )


class _Call(BaseModel):
    name: str
    args: list[str]
    line: int
    snippet: str


def _scan_text(
    ctx: MemoryContext,
    args: WindowsTraceArgFlowArgs,
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


def _flow_hits(
    calls: list[_Call],
    tracked_names: set[str],
    operations_by_symbol: dict[str, list[OperationRecord]],
    *,
    max_flows: int,
    provenance_source: str,
) -> list[ArgFlowHit]:
    hits: list[ArgFlowHit] = []
    for call in calls:
        operation = _first_operation(call.name, operations_by_symbol)
        for index, expression in enumerate(call.args):
            matched_name = _expr_tracked_name(expression, tracked_names)
            if matched_name is None:
                continue
            hits.append(
                ArgFlowHit(
                    callee=call.name,
                    callee_arg_index=index,
                    expression=expression.strip(),
                    line=call.line,
                    snippet=call.snippet,
                    matched_name=matched_name,
                    operation=operation,
                    confidence=0.65 if operation else 0.55,
                    provenance=[provenance_source, "simple_alias_trace"],
                )
            )
            if len(hits) >= max_flows:
                return hits
    return hits


def _expr_tracked_name(expression: str, tracked_names: set[str]) -> str | None:
    for name in tracked_names:
        if re.search(rf"\b{re.escape(name)}\b", expression):
            return name
    return None


def _load_operations(sinks_path: str | None) -> list[OperationRecord]:
    path = _resolve_metadata_path(sinks_path, "data/kg/pe-sinks.yaml")
    operations = []
    for entry in _load_yaml_list(path):
        operations.append(_operation_record(entry, path))
    return operations


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


def _arg_roles(raw: Any, path: Path, owner: Any):
    from .windows_operation_metadata import OperationArgRole

    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path}: operation {owner!r} missing non-empty arg_roles")
    roles = []
    for key, value in raw.items():
        roles.append(OperationArgRole(index=int(key), role=str(value)))
    return sorted(roles, key=lambda role: role.index)


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


def _result(
    args: WindowsTraceArgFlowArgs,
    source: str,
    notes: list[str],
    source_name: str | None,
    aliases: list[AliasStep],
    flows: list[ArgFlowHit],
    scanned_call_count: int,
    evidence_node_id: str | None,
) -> WindowsTraceArgFlowResult:
    return WindowsTraceArgFlowResult(
        function_va=args.function_va,
        source_name=source_name,
        aliases=aliases,
        flows=flows,
        scanned_call_count=scanned_call_count,
        pseudocode_source=source,
        evidence_node_id=evidence_node_id,
        notes=notes,
    )


def build_tool() -> MemoryTool[WindowsTraceArgFlowArgs, WindowsTraceArgFlowResult]:
    return WindowsTraceArgFlowTool()
