from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_project_onehop_argument_flow import (
    WindowsProjectOnehopArgumentFlow,
    WindowsProjectOnehopArgumentFlowArgs,
    WindowsProjectOnehopArgumentFlowTool,
)


class WindowsProjectHelperArgumentSummaryArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary backing the project.")
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    caller_function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter helper callers.",
    )
    caller_function_name: str | None = Field(
        None,
        description="Optional caller function name used when caller_function_va is absent.",
    )
    helper_function_va: int | None = Field(
        None,
        description="Optional helper function VA used to filter helper summaries.",
    )
    helper_function_name: str | None = Field(
        None,
        description="Optional helper function name used when helper_function_va is absent.",
    )
    source_arg_index: int | None = Field(
        None,
        description="Optional caller-to-helper argument index to summarize.",
    )
    sink_symbol: str | None = Field(None, description="Optional helper-local sink symbol.")
    sink_kind: str | None = Field(None, description="Optional ASB sink kind filter.")
    max_flows: int = Field(
        256,
        ge=0,
        le=4096,
        description="Maximum one-hop argument-flow facts to scan before aggregation.",
    )
    max_summaries: int = Field(
        64,
        ge=0,
        le=1024,
        description="Maximum helper argument summaries to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact helper-argument-summary evidence node.",
    )


class WindowsProjectHelperArgumentUse(BaseModel):
    caller_va: int | None = None
    caller_name: str | None = None
    helper_va: int
    helper_name: str | None = None
    helper_arg_index: int
    helper_arg_register: str
    caller_arg_expression: str | None = None
    matched_sink_count: int
    sink_symbols: list[str] = Field(default_factory=list)
    sink_kinds: list[str] = Field(default_factory=list)
    sink_arg_roles: list[str] = Field(default_factory=list)
    sink_callsite_vas: list[int] = Field(default_factory=list)
    sink_effects: list[str] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectHelperArgumentSummaryResult(BaseModel):
    binary_path: str
    project_path: str
    binary_id: int | None = None
    scanned_flow_count: int
    summary_count: int
    summaries: list[WindowsProjectHelperArgumentUse]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectHelperArgumentSummaryTool(
    MemoryTool[
        WindowsProjectHelperArgumentSummaryArgs,
        WindowsProjectHelperArgumentSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_helper_argument_summary",
                description=(
                    "Aggregate conservative caller -> helper -> sink argument-flow "
                    "facts into per-helper-argument summaries with sink roles, "
                    "effects, and required gates."
                ),
                tags=("windows", "pe", "project", "helper", "arguments", "summary"),
            ),
            WindowsProjectHelperArgumentSummaryArgs,
            WindowsProjectHelperArgumentSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectHelperArgumentSummaryArgs,
    ) -> WindowsProjectHelperArgumentSummaryResult:
        binary_path = Path(args.binary_path)
        project_path = Path(args.project_path)
        flow_tool = WindowsProjectOnehopArgumentFlowTool()
        flows = flow_tool.run(
            ctx,
            kb,
            WindowsProjectOnehopArgumentFlowArgs(
                binary_path=args.binary_path,
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                caller_function_va=args.caller_function_va,
                caller_function_name=args.caller_function_name,
                helper_function_va=args.helper_function_va,
                helper_function_name=args.helper_function_name,
                sink_symbol=args.sink_symbol,
                sink_kind=args.sink_kind,
                source_arg_index=args.source_arg_index,
                max_flows=args.max_flows,
                add_to_kb=False,
            ),
        )

        summaries = _summaries(flows.flows, args.max_summaries)
        coverage = _coverage(flows.coverage, summaries)
        missing = _missing_capabilities(summaries)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_helper_argument_summary",
                    props={
                        "project_path": str(project_path),
                        "binary_path": str(binary_path),
                        "scanned_flow_count": flows.flow_count,
                        "summary_count": len(summaries),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectHelperArgumentSummaryResult(
            binary_path=str(binary_path),
            project_path=str(project_path),
            binary_id=flows.binary_id,
            scanned_flow_count=flows.flow_count,
            summary_count=len(summaries),
            summaries=summaries,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "helper argument summaries aggregate matched one-hop sink uses only; "
                "they do not prove arbitrary helper side effects, aliases, returns, "
                "or path-sensitive value constraints"
            ],
        )


def _summaries(
    flows: list[WindowsProjectOnehopArgumentFlow],
    max_summaries: int,
) -> list[WindowsProjectHelperArgumentUse]:
    groups: dict[
        tuple[int | None, str | None, int, str | None, int, str, str | None],
        list[WindowsProjectOnehopArgumentFlow],
    ] = defaultdict(list)
    for flow in flows:
        groups[
            (
                flow.caller_va,
                flow.caller_name,
                flow.helper_va,
                flow.helper_name,
                flow.caller_arg_index,
                flow.caller_arg_register,
                flow.caller_arg_expression,
            )
        ].append(flow)

    out: list[WindowsProjectHelperArgumentUse] = []
    for key, grouped in groups.items():
        (
            caller_va,
            caller_name,
            helper_va,
            helper_name,
            helper_arg_index,
            helper_arg_register,
            caller_arg_expression,
        ) = key
        out.append(
            WindowsProjectHelperArgumentUse(
                caller_va=caller_va,
                caller_name=caller_name,
                helper_va=helper_va,
                helper_name=helper_name,
                helper_arg_index=helper_arg_index,
                helper_arg_register=helper_arg_register,
                caller_arg_expression=caller_arg_expression,
                matched_sink_count=len(grouped),
                sink_symbols=_uniq(flow.sink_symbol for flow in grouped),
                sink_kinds=_uniq(flow.sink_kind for flow in grouped),
                sink_arg_roles=_uniq(flow.helper_sink_arg_role for flow in grouped),
                sink_callsite_vas=sorted({flow.sink_callsite_va for flow in grouped}),
                sink_effects=_uniq(
                    effect for flow in grouped for effect in flow.sink_effects
                ),
                required_gates=_uniq(
                    gate for flow in grouped for gate in flow.required_gates
                ),
                confidence=round(min(flow.confidence for flow in grouped), 2),
                provenance=[
                    "windows_project_onehop_argument_flow",
                    "windows_project_onehop_sink_chains",
                    "windows_project_call_argument_snapshot",
                    "asb_pe_sink_metadata",
                    "helper_argument_sink_use_summary",
                ],
            )
        )
        if len(out) >= max_summaries:
            break
    return out


def _coverage(
    flow_coverage: list[str],
    summaries: list[WindowsProjectHelperArgumentUse],
) -> list[str]:
    coverage = list(dict.fromkeys(flow_coverage))
    if summaries:
        coverage.extend(
            [
                "helper_argument_sink_use_summary",
                "helper_arg_to_sink_role_summary",
                "helper_arg_required_gate_summary",
            ]
        )
    return list(dict.fromkeys(coverage))


def _missing_capabilities(
    summaries: list[WindowsProjectHelperArgumentUse],
) -> list[str]:
    missing = []
    if not summaries:
        missing.append("helper_argument_sink_use_summary")
    missing.extend(
        [
            "general_helper_side_effect_summaries",
            "helper_return_value_summaries",
            "alias_aware_interprocedural_propagation",
            "path_sensitive_argument_values",
        ]
    )
    return missing


def _uniq(values) -> list:
    out = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def build_tool() -> WindowsProjectHelperArgumentSummaryTool:
    return WindowsProjectHelperArgumentSummaryTool()
