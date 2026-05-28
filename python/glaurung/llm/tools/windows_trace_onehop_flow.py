from __future__ import annotations

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_trace_arg_flow import (
    AliasStep,
    ArgFlowHit,
    _extract_calls,
    _expr_tracked_name,
    _flow_hits,
    _load_operations,
    _operations_by_symbol,
    _source_name_from_signature,
    _symbol_keys,
    _trace_aliases,
)


class HelperPseudocode(BaseModel):
    name: str
    pseudocode: str


class OneHopFlowHit(BaseModel):
    helper: str
    caller_arg_index: int
    caller_expression: str
    caller_line: int
    caller_snippet: str
    helper_source_name: str
    helper_aliases: list[AliasStep]
    sink_flow: ArgFlowHit
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsTraceOnehopFlowArgs(BaseModel):
    source_arg_index: int | None = Field(
        None,
        description="Zero-based source argument index to trace from caller signature.",
    )
    source_name: str | None = Field(
        None,
        description="Caller source variable name. Used directly or derived from source_arg_index.",
    )
    caller_pseudocode: str | None = Field(
        None,
        description="Caller pseudocode or source-like text.",
    )
    caller_function_va: int | None = Field(
        None,
        description="Optional caller function VA. Used only when caller_pseudocode is omitted.",
    )
    helpers: list[HelperPseudocode] = Field(
        default_factory=list,
        description="Helper pseudocode entries keyed by helper name.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    max_depth: int = Field(2, description="Maximum simple alias depth in each function.")
    max_flows: int = Field(64, description="Maximum one-hop flow hits to return.")
    timeout_ms: int = Field(
        500,
        description="Decompile timeout when caller_function_va is used.",
    )
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact one-hop-flow evidence node to the KB.",
    )


class WindowsTraceOnehopFlowResult(BaseModel):
    caller_function_va: int | None = None
    source_name: str | None = None
    caller_aliases: list[AliasStep]
    flows: list[OneHopFlowHit]
    scanned_caller_call_count: int
    caller_pseudocode_source: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsTraceOnehopFlowTool(
    MemoryTool[WindowsTraceOnehopFlowArgs, WindowsTraceOnehopFlowResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_trace_onehop_flow",
                description=(
                    "Trace one Windows source argument through a caller into "
                    "one supplied helper and then to helper-local sink calls."
                ),
                tags=("windows", "pe", "flow", "arguments", "onehop"),
            ),
            WindowsTraceOnehopFlowArgs,
            WindowsTraceOnehopFlowResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsTraceOnehopFlowArgs,
    ) -> WindowsTraceOnehopFlowResult:
        caller_text, caller_source, notes = _caller_text(ctx, args)
        source_name = args.source_name or _source_name_from_signature(
            caller_text, args.source_arg_index
        )
        if not source_name:
            notes.append("source_name could not be resolved in caller")
            return _result(args, source_name, [], [], 0, caller_source, notes, None)

        caller_aliases = _trace_aliases(caller_text, source_name, max_depth=args.max_depth)
        tracked_names = {source_name} | {alias.name for alias in caller_aliases}
        helper_by_key = _helpers_by_key(args.helpers)
        operations = _load_operations(args.sinks_path)
        operations_by_symbol = _operations_by_symbol(operations)
        caller_calls = _extract_calls(caller_text)
        flows: list[OneHopFlowHit] = []

        for caller_call in caller_calls:
            helper = _helper_for_name(caller_call.name, helper_by_key)
            if helper is None:
                continue
            for caller_arg_index, caller_expression in enumerate(caller_call.args):
                matched_name = _expr_tracked_name(caller_expression, tracked_names)
                if matched_name is None:
                    continue
                helper_source_name = _source_name_from_signature(
                    helper.pseudocode, caller_arg_index
                )
                if not helper_source_name:
                    notes.append(
                        f"could not resolve helper arg {caller_arg_index} for {helper.name}"
                    )
                    continue
                helper_aliases = _trace_aliases(
                    helper.pseudocode,
                    helper_source_name,
                    max_depth=args.max_depth,
                )
                helper_tracked_names = {
                    helper_source_name,
                    *(alias.name for alias in helper_aliases),
                }
                helper_flows = _flow_hits(
                    _extract_calls(helper.pseudocode),
                    helper_tracked_names,
                    operations_by_symbol,
                    max_flows=args.max_flows,
                    provenance_source="helper_pseudocode",
                )
                for sink_flow in helper_flows:
                    flows.append(
                        OneHopFlowHit(
                            helper=helper.name,
                            caller_arg_index=caller_arg_index,
                            caller_expression=caller_expression.strip(),
                            caller_line=caller_call.line,
                            caller_snippet=caller_call.snippet,
                            helper_source_name=helper_source_name,
                            helper_aliases=helper_aliases,
                            sink_flow=sink_flow,
                            confidence=0.55
                            + (0.1 if sink_flow.operation is not None else 0.0),
                            provenance=[
                                caller_source,
                                "caller_simple_alias_trace",
                                "helper_simple_alias_trace",
                            ],
                        )
                    )
                    if len(flows) >= args.max_flows:
                        break
                if len(flows) >= args.max_flows:
                    break
            if len(flows) >= args.max_flows:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_trace_onehop_flow",
                    props={
                        "caller_function_va": args.caller_function_va,
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
            source_name,
            caller_aliases,
            flows,
            len(caller_calls),
            caller_source,
            notes,
            evidence_node_id,
        )


def _caller_text(
    ctx: MemoryContext,
    args: WindowsTraceOnehopFlowArgs,
) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if args.caller_pseudocode:
        return args.caller_pseudocode, "supplied_caller_pseudocode", notes
    if args.caller_function_va is None:
        notes.append("no caller_pseudocode or caller_function_va supplied")
        return "", "none", notes
    try:
        text = g.ir.decompile_at(
            str(ctx.file_path),
            int(args.caller_function_va),
            timeout_ms=max(200, int(args.timeout_ms)),
            style="c",
            pdb_cache=args.pdb_cache,
        )
        return text, "glaurung_decompiler", notes
    except Exception as exc:
        notes.append(f"caller decompile failed: {exc}")
        return "", "glaurung_decompiler_failed", notes


def _helpers_by_key(helpers: list[HelperPseudocode]) -> dict[str, HelperPseudocode]:
    out: dict[str, HelperPseudocode] = {}
    for helper in helpers:
        for key in _symbol_keys(helper.name):
            out[key] = helper
    return out


def _helper_for_name(
    name: str,
    helper_by_key: dict[str, HelperPseudocode],
) -> HelperPseudocode | None:
    for key in _symbol_keys(name):
        helper = helper_by_key.get(key)
        if helper is not None:
            return helper
    return None


def _result(
    args: WindowsTraceOnehopFlowArgs,
    source_name: str | None,
    caller_aliases: list[AliasStep],
    flows: list[OneHopFlowHit],
    scanned_caller_call_count: int,
    caller_pseudocode_source: str,
    notes: list[str],
    evidence_node_id: str | None,
) -> WindowsTraceOnehopFlowResult:
    return WindowsTraceOnehopFlowResult(
        caller_function_va=args.caller_function_va,
        source_name=source_name,
        caller_aliases=caller_aliases,
        flows=flows,
        scanned_caller_call_count=scanned_caller_call_count,
        caller_pseudocode_source=caller_pseudocode_source,
        evidence_node_id=evidence_node_id,
        notes=notes,
    )


def build_tool() -> MemoryTool[
    WindowsTraceOnehopFlowArgs, WindowsTraceOnehopFlowResult
]:
    return WindowsTraceOnehopFlowTool()
