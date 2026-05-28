from __future__ import annotations

import re

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_operation_metadata import OperationRecord
from .windows_trace_arg_flow import (
    _expr_tracked_name,
    _extract_calls,
    _first_operation,
    _load_operations,
    _operations_by_symbol,
    _split_args,
    _trace_aliases,
)


class HelperParameter(BaseModel):
    index: int
    name: str
    declaration: str


class HelperParameterImpact(BaseModel):
    parameter: HelperParameter
    call_arg_index: int
    call_arg_role: str | None = None
    expression: str
    effects: list[str] = Field(default_factory=list)


class HelperSideEffect(BaseModel):
    call_symbol: str
    operation: OperationRecord
    line: int
    snippet: str
    parameter_impacts: list[HelperParameterImpact]
    summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsSummarizeHelperSideEffectsArgs(BaseModel):
    helper_name: str | None = Field(
        None,
        description="Optional helper name override. Otherwise parsed from pseudocode.",
    )
    pseudocode: str | None = Field(
        None,
        description="Optional helper pseudocode or source-like text.",
    )
    function_va: int | None = Field(
        None,
        description="Optional helper function VA. Used only when pseudocode is omitted.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sink_kind: str | None = Field(None, description="Optional operation kind filter.")
    max_effects: int = Field(64, description="Maximum side-effect calls to return.")
    max_depth: int = Field(2, description="Maximum simple alias depth from parameters.")
    timeout_ms: int = Field(500, description="Decompile timeout when function_va is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact helper-side-effect evidence node to the KB.",
    )


class WindowsSummarizeHelperSideEffectsResult(BaseModel):
    helper_name: str | None
    function_va: int | None = None
    parameters: list[HelperParameter]
    side_effects: list[HelperSideEffect]
    scanned_call_count: int
    pseudocode_source: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSummarizeHelperSideEffectsTool(
    MemoryTool[
        WindowsSummarizeHelperSideEffectsArgs,
        WindowsSummarizeHelperSideEffectsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_summarize_helper_side_effects",
                description=(
                    "Summarize Windows helper side effects by mapping operation "
                    "sink arguments back to helper parameters."
                ),
                tags=("windows", "pe", "helpers", "side-effects", "pseudocode"),
            ),
            WindowsSummarizeHelperSideEffectsArgs,
            WindowsSummarizeHelperSideEffectsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSummarizeHelperSideEffectsArgs,
    ) -> WindowsSummarizeHelperSideEffectsResult:
        text, source, notes = _scan_text(ctx, args)
        helper_name = args.helper_name or _helper_name(text)
        parameters = _parameters(text)
        operations = _load_operations(args.sinks_path)
        operations_by_symbol = _operations_by_symbol(operations)
        tracked_by_param = _tracked_names_by_param(text, parameters, max_depth=args.max_depth)
        calls = _extract_calls(text)
        side_effects: list[HelperSideEffect] = []

        for call in calls:
            operation = _first_operation(call.name, operations_by_symbol)
            if operation is None:
                continue
            if args.sink_kind and operation.sink_kind != args.sink_kind:
                continue
            impacts = _parameter_impacts(call.args, operation, parameters, tracked_by_param)
            if not impacts:
                continue
            side_effects.append(
                HelperSideEffect(
                    call_symbol=call.name,
                    operation=operation,
                    line=call.line,
                    snippet=call.snippet,
                    parameter_impacts=impacts,
                    summary=_summary(call.name, operation, impacts),
                    confidence=0.65,
                    provenance=["asb_pe_sink_metadata", source, "simple_parameter_alias_trace"],
                )
            )
            if len(side_effects) >= args.max_effects:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_summarize_helper_side_effects",
                    props={
                        "helper_name": helper_name,
                        "function_va": args.function_va,
                        "side_effect_count": len(side_effects),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        notes.append(
            "side-effect summary uses pseudocode/simple-alias evidence; it is not IR proof"
        )
        return WindowsSummarizeHelperSideEffectsResult(
            helper_name=helper_name,
            function_va=args.function_va,
            parameters=parameters,
            side_effects=side_effects,
            scanned_call_count=len(calls),
            pseudocode_source=source,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _scan_text(
    ctx: MemoryContext,
    args: WindowsSummarizeHelperSideEffectsArgs,
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


def _helper_name(text: str) -> str | None:
    match = re.search(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_!:.$@]*)\s*\([^;{}]*\)\s*\{",
        text,
        flags=re.S,
    )
    if match:
        return match.group("name")
    return None


def _parameters(text: str) -> list[HelperParameter]:
    match = re.search(r"\((?P<params>[^)]*)\)", text, flags=re.S)
    if not match:
        return []
    params = _split_args(match.group("params"))
    out: list[HelperParameter] = []
    for index, declaration in enumerate(params):
        name_match = re.search(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*$", declaration)
        if not name_match:
            continue
        name = name_match.group("name")
        if name.lower() == "void":
            continue
        out.append(HelperParameter(index=index, name=name, declaration=declaration.strip()))
    return out


def _tracked_names_by_param(
    text: str,
    parameters: list[HelperParameter],
    *,
    max_depth: int,
) -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    for parameter in parameters:
        aliases = _trace_aliases(text, parameter.name, max_depth=max_depth)
        out[parameter.index] = {parameter.name, *(alias.name for alias in aliases)}
    return out


def _parameter_impacts(
    call_args: list[str],
    operation: OperationRecord,
    parameters: list[HelperParameter],
    tracked_by_param: dict[int, set[str]],
) -> list[HelperParameterImpact]:
    impacts: list[HelperParameterImpact] = []
    for call_arg_index, expression in enumerate(call_args):
        parameter = _matched_parameter(expression, parameters, tracked_by_param)
        if parameter is None:
            continue
        impacts.append(
            HelperParameterImpact(
                parameter=parameter,
                call_arg_index=call_arg_index,
                call_arg_role=_operation_role(operation, call_arg_index),
                expression=expression.strip(),
                effects=operation.effects,
            )
        )
    return impacts


def _matched_parameter(
    expression: str,
    parameters: list[HelperParameter],
    tracked_by_param: dict[int, set[str]],
) -> HelperParameter | None:
    for parameter in parameters:
        if _expr_tracked_name(expression, tracked_by_param.get(parameter.index, set())):
            return parameter
    return None


def _operation_role(operation: OperationRecord, index: int) -> str | None:
    for role in operation.arg_roles:
        if role.index == index:
            return role.role
    return None


def _summary(
    call_symbol: str,
    operation: OperationRecord,
    impacts: list[HelperParameterImpact],
) -> str:
    pieces = []
    for impact in impacts:
        role = impact.call_arg_role or f"arg{impact.call_arg_index}"
        pieces.append(f"{role}=helper_arg{impact.parameter.index}:{impact.parameter.name}")
    return f"{operation.sink_kind} via {call_symbol} ({', '.join(pieces)})"


def build_tool() -> MemoryTool[
    WindowsSummarizeHelperSideEffectsArgs,
    WindowsSummarizeHelperSideEffectsResult,
]:
    return WindowsSummarizeHelperSideEffectsTool()
