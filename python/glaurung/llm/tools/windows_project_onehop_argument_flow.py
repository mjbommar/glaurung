from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_project_call_argument_snapshot import (
    ProjectCallArgumentFact,
    WindowsProjectCallArgumentSnapshotArgs,
    WindowsProjectCallArgumentSnapshotTool,
)
from .windows_project_onehop_sink_chains import (
    WindowsProjectOnehopSinkChain,
    WindowsProjectOnehopSinkChainsArgs,
    WindowsProjectOnehopSinkChainsTool,
)


class WindowsProjectOnehopArgumentFlowArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary backing the project.")
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
    sink_symbol: str | None = Field(None, description="Optional helper-local sink symbol.")
    sink_kind: str | None = Field(None, description="Optional ASB sink kind filter.")
    source_arg: str | None = Field(
        None,
        description="Optional caller-side source expression/register to match.",
    )
    source_arg_index: int | None = Field(
        None,
        description="Optional caller-to-helper argument index to match.",
    )
    sink_arg_index: int | None = Field(
        None,
        description="Optional helper-local sink argument index to match.",
    )
    max_flows: int = Field(64, ge=0, le=1024, description="Maximum flows to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact one-hop argument-flow evidence node to the KB.",
    )


class WindowsProjectOnehopArgumentFlow(BaseModel):
    caller_va: int | None = None
    caller_name: str | None = None
    helper_callsite_va: int
    helper_va: int
    helper_name: str | None = None
    sink_callsite_va: int
    sink_symbol: str
    sink_kind: str
    caller_arg_index: int
    caller_arg_expression: str | None = None
    caller_arg_register: str
    helper_sink_arg_index: int
    helper_sink_arg_role: str
    helper_sink_arg_expression: str | None = None
    sink_effects: list[str] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectOnehopArgumentFlowResult(BaseModel):
    binary_path: str
    project_path: str
    binary_id: int | None = None
    scanned_chain_count: int
    helper_argument_snapshot_count: int
    sink_argument_snapshot_count: int
    flow_count: int
    flows: list[WindowsProjectOnehopArgumentFlow]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOnehopArgumentFlowTool(
    MemoryTool[
        WindowsProjectOnehopArgumentFlowArgs,
        WindowsProjectOnehopArgumentFlowResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_onehop_argument_flow",
                description=(
                    "Compose project one-hop sink topology with local call-argument "
                    "snapshots to match caller helper arguments to helper-local sink "
                    "arguments."
                ),
                tags=("windows", "pe", "project", "onehop", "arguments", "flow"),
            ),
            WindowsProjectOnehopArgumentFlowArgs,
            WindowsProjectOnehopArgumentFlowResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOnehopArgumentFlowArgs,
    ) -> WindowsProjectOnehopArgumentFlowResult:
        binary_path = Path(args.binary_path)
        project_path = Path(args.project_path)
        if not binary_path.exists():
            raise ValueError(f"{binary_path}: PE binary does not exist")
        chains = WindowsProjectOnehopSinkChainsTool().run(
            ctx,
            kb,
            WindowsProjectOnehopSinkChainsArgs(
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                caller_function_va=args.caller_function_va,
                caller_function_name=args.caller_function_name,
                helper_function_va=args.helper_function_va,
                helper_function_name=args.helper_function_name,
                sink_symbol=args.sink_symbol,
                sink_kind=args.sink_kind,
                max_chains=args.max_flows,
                add_to_kb=False,
            ),
        )

        flows: list[WindowsProjectOnehopArgumentFlow] = []
        helper_argument_snapshot_count = 0
        sink_argument_snapshot_count = 0
        snapshot_tool = WindowsProjectCallArgumentSnapshotTool()
        for chain in chains.chains:
            helper_args = snapshot_tool.run(
                ctx,
                kb,
                WindowsProjectCallArgumentSnapshotArgs(
                    binary_path=args.binary_path,
                    project_path=args.project_path,
                    callsite_va=chain.helper_callsite_va,
                    binary_id=args.binary_id,
                    add_to_kb=False,
                ),
            ).arguments
            sink_args = snapshot_tool.run(
                ctx,
                kb,
                WindowsProjectCallArgumentSnapshotArgs(
                    binary_path=args.binary_path,
                    project_path=args.project_path,
                    callsite_va=chain.sink_callsite_va,
                    binary_id=args.binary_id,
                    add_to_kb=False,
                ),
            ).arguments
            if helper_args:
                helper_argument_snapshot_count += 1
            if sink_args:
                sink_argument_snapshot_count += 1
            flows.extend(_flows_for_chain(chain, helper_args, sink_args, args))
            if len(flows) >= args.max_flows:
                flows = flows[: args.max_flows]
                break

        coverage = _coverage(chains.coverage, flows)
        missing = _missing_capabilities(flows)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_onehop_argument_flow",
                    props={
                        "project_path": str(project_path),
                        "binary_path": str(binary_path),
                        "scanned_chain_count": chains.chain_count,
                        "flow_count": len(flows),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOnehopArgumentFlowResult(
            binary_path=str(binary_path),
            project_path=str(project_path),
            binary_id=chains.binary_id,
            scanned_chain_count=chains.chain_count,
            helper_argument_snapshot_count=helper_argument_snapshot_count,
            sink_argument_snapshot_count=sink_argument_snapshot_count,
            flow_count=len(flows),
            flows=flows,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "one-hop argument flow uses local callsite snapshots on both calls; "
                "it is conservative calling-convention evidence, not full alias or "
                "path-sensitive interprocedural proof"
            ],
        )


def _flows_for_chain(
    chain: WindowsProjectOnehopSinkChain,
    helper_args: list[ProjectCallArgumentFact],
    sink_args: list[ProjectCallArgumentFact],
    args: WindowsProjectOnehopArgumentFlowArgs,
) -> list[WindowsProjectOnehopArgumentFlow]:
    out: list[WindowsProjectOnehopArgumentFlow] = []
    for helper_arg in helper_args:
        if args.source_arg_index is not None and helper_arg.index != args.source_arg_index:
            continue
        if args.source_arg and not _argument_matches(args.source_arg, helper_arg):
            continue
        expected = f"caller_arg{helper_arg.index}"
        for sink_arg in sink_args:
            if args.sink_arg_index is not None and sink_arg.index != args.sink_arg_index:
                continue
            if sink_arg.expression != expected:
                continue
            out.append(_flow(chain, helper_arg, sink_arg))
    return out


def _flow(
    chain: WindowsProjectOnehopSinkChain,
    helper_arg: ProjectCallArgumentFact,
    sink_arg: ProjectCallArgumentFact,
) -> WindowsProjectOnehopArgumentFlow:
    return WindowsProjectOnehopArgumentFlow(
        caller_va=chain.caller_va,
        caller_name=chain.caller_name,
        helper_callsite_va=chain.helper_callsite_va,
        helper_va=chain.helper_va,
        helper_name=chain.helper_name,
        sink_callsite_va=chain.sink_callsite_va,
        sink_symbol=chain.sink_symbol,
        sink_kind=chain.sink_kind,
        caller_arg_index=helper_arg.index,
        caller_arg_expression=helper_arg.expression,
        caller_arg_register=helper_arg.register_name,
        helper_sink_arg_index=sink_arg.index,
        helper_sink_arg_role=sink_arg.role,
        helper_sink_arg_expression=sink_arg.expression,
        sink_effects=chain.sink_effects,
        required_gates=chain.required_gates,
        confidence=round(min(helper_arg.confidence, sink_arg.confidence, 0.74), 2),
        provenance=[
            "windows_project_onehop_sink_chains",
            "windows_project_call_argument_snapshot",
            "asb_pe_sink_metadata",
            "windows_x64_calling_convention",
            "helper_incoming_arg_match",
        ],
    )


def _argument_matches(source: str, argument: ProjectCallArgumentFact) -> bool:
    needle = _norm(source)
    values = [
        f"arg{argument.index}",
        argument.expression,
        argument.register_name,
        argument.role,
        argument.source_text,
    ]
    return any(_norm(value) == needle for value in values if value)


def _coverage(
    chain_coverage: list[str],
    flows: list[WindowsProjectOnehopArgumentFlow],
) -> list[str]:
    coverage = list(dict.fromkeys(chain_coverage))
    if flows:
        coverage.extend(
            [
                "project_onehop_argument_flow",
                "helper_incoming_arg_match",
                "local_call_argument_snapshots",
                "asb_sink_required_gate_metadata",
            ]
        )
    return list(dict.fromkeys(coverage))


def _missing_capabilities(flows: list[WindowsProjectOnehopArgumentFlow]) -> list[str]:
    missing = []
    if not flows:
        missing.append("project_onehop_argument_flow")
    missing.extend(
        [
            "full_memory_alias_tracking",
            "path_sensitive_argument_values",
            "helper_side_effect_summary",
        ]
    )
    return missing


def _norm(value: str) -> str:
    return value.strip().lower().replace(" ", "")


def build_tool() -> WindowsProjectOnehopArgumentFlowTool:
    return WindowsProjectOnehopArgumentFlowTool()
