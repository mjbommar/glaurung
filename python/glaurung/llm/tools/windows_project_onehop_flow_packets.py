from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_cfg_dominance import (
    WindowsCfgDominanceArgs,
    WindowsCfgDominanceResult,
    WindowsCfgDominanceTool,
)
from .windows_check_gate_to_sink import (
    _gate_record,
    _gates_by_symbol,
    _load_yaml_list,
    _matches_by_symbol,
)
from .windows_emit_review_packet import (
    GateStatus,
    WindowsEmitReviewPacketArgs,
    WindowsEmitReviewPacketTool,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from .windows_gate_semantics import (
    gate_proof_sources,
    matched_required_gates,
    missing_required_gates,
)
from .windows_project_callsite_facts import (
    WindowsProjectCallsiteFactsArgs,
    WindowsProjectCallsiteFactsTool,
)
from .windows_project_branch_condition_facts import (
    ProjectBranchConditionFact,
    WindowsProjectBranchConditionFactsArgs,
    WindowsProjectBranchConditionFactsTool,
)
from .windows_project_cfg_path_query import (
    WindowsProjectCfgPathQueryArgs,
    WindowsProjectCfgPathQueryResult,
    WindowsProjectCfgPathQueryTool,
)
from .windows_project_onehop_argument_flow import (
    WindowsProjectOnehopArgumentFlow,
    WindowsProjectOnehopArgumentFlowArgs,
    WindowsProjectOnehopArgumentFlowTool,
)
from .windows_surface_metadata import GateRecord, _resolve_metadata_path


class WindowsProjectOnehopFlowPacketsArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary backing the project.")
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary: str = Field(..., description="Binary or driver filename.")
    build: str | None = Field(None, description="Windows build or corpus label.")
    attacker_class: str = Field(
        "unknown",
        description="Attacker class to attach to emitted packets.",
    )
    source_role: str = Field(
        "unknown",
        description="Source role to attach to the matched caller-side value.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    refine_helper_gates: bool = Field(
        False,
        description=(
            "If true, look for compatible gate callsites inside the helper and "
            "attach persisted-CFG dominance evidence before the helper-local sink."
        ),
    )
    attach_helper_gate_paths: bool = Field(
        False,
        description=(
            "If true with refine_helper_gates, attach compact persisted CFG "
            "entry/gate-to-sink path evidence for the helper-local gate."
        ),
    )
    attach_helper_gate_predicates: bool = Field(
        False,
        description=(
            "If true with refine_helper_gates, attach nearby persisted branch "
            "condition facts for the helper-local gate path."
        ),
    )
    max_helper_gate_predicates: int = Field(
        4,
        ge=0,
        le=32,
        description="Maximum helper branch-condition facts to attach per packet.",
    )
    max_helper_gate_path_blocks: int = Field(
        64,
        ge=1,
        le=512,
        description="Maximum helper CFG block ids to include in gate path evidence.",
    )
    binary_id: int | None = Field(None, description="Optional project binary_id filter.")
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
    project_facts_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-project-facts.yaml for packet auto-join.",
    )
    ghidra_delta_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-ghidra-delta.yaml for packet auto-join.",
    )
    manifest_target_id: str | None = Field(
        None,
        description="Optional ASB target id used for packet manifest auto-join.",
    )
    manifest_build_label: str | None = Field(
        None,
        description="Optional ASB build label used for packet manifest auto-join.",
    )
    manifest_component: str | None = Field(
        None,
        description="Optional component filename used for Ghidra-delta auto-join.",
    )
    required_project_facts: list[str] = Field(
        default_factory=lambda: ["function_names", "call_xrefs"],
        description="Project fact classes required before packet promotion.",
    )
    max_packets: int = Field(16, ge=0, le=256, description="Maximum packets to emit.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact one-hop flow-packet evidence node to the KB.",
    )


class WindowsProjectOnehopFlowPacketsResult(BaseModel):
    project_path: str
    packet_count: int
    scanned_chain_count: int
    onehop_argument_flow_count: int
    helper_gate_refinement_count: int
    helper_cfg_path_count: int
    helper_gate_predicate_count: int
    packets: list[WindowsReviewPacket]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOnehopFlowPacketsTool(
    MemoryTool[
        WindowsProjectOnehopFlowPacketsArgs,
        WindowsProjectOnehopFlowPacketsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_onehop_flow_packets",
                description=(
                    "Convert conservative one-hop caller/helper/sink argument-flow "
                    "matches into Windows review packets."
                ),
                tags=("windows", "pe", "project", "onehop", "candidate", "packet"),
            ),
            WindowsProjectOnehopFlowPacketsArgs,
            WindowsProjectOnehopFlowPacketsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOnehopFlowPacketsArgs,
    ) -> WindowsProjectOnehopFlowPacketsResult:
        flow_result = WindowsProjectOnehopArgumentFlowTool().run(
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
                source_arg=args.source_arg,
                source_arg_index=args.source_arg_index,
                sink_arg_index=args.sink_arg_index,
                max_flows=args.max_packets,
                add_to_kb=False,
            ),
        )
        packet_items = [
            (flow, _refine_helper_gate(ctx, kb, args, flow))
            for flow in flow_result.flows[: args.max_packets]
        ]
        packets = [
            _emit_packet(ctx, kb, args, flow, gate_refinement)
            for flow, gate_refinement in packet_items
        ]
        helper_gate_refinement_count = sum(
            1 for _flow, refinement in packet_items if refinement is not None
        )
        helper_cfg_path_count = sum(
            1
            for _flow, refinement in packet_items
            if refinement is not None and refinement.cfg_path is not None
        )
        helper_gate_predicate_count = sum(
            len(refinement.predicates)
            for _flow, refinement in packet_items
            if refinement is not None
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_onehop_flow_packets",
                    props={
                        "project_path": args.project_path,
                        "binary": args.binary,
                        "packet_count": len(packets),
                        "scanned_chain_count": flow_result.scanned_chain_count,
                        "onehop_argument_flow_count": flow_result.flow_count,
                        "helper_gate_refinement_count": helper_gate_refinement_count,
                        "helper_cfg_path_count": helper_cfg_path_count,
                        "helper_gate_predicate_count": helper_gate_predicate_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOnehopFlowPacketsResult(
            project_path=args.project_path,
            packet_count=len(packets),
            scanned_chain_count=flow_result.scanned_chain_count,
            onehop_argument_flow_count=flow_result.flow_count,
            helper_gate_refinement_count=helper_gate_refinement_count,
            helper_cfg_path_count=helper_cfg_path_count,
            helper_gate_predicate_count=helper_gate_predicate_count,
            packets=packets,
            evidence_node_id=evidence_node_id,
            notes=[
                "packets are static one-hop argument-flow candidates; gate evidence "
                "and general helper summaries still require dedicated rules"
            ],
        )


def _emit_packet(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOnehopFlowPacketsArgs,
    flow: WindowsProjectOnehopArgumentFlow,
    gate_refinement: "_HelperGateRefinement | None",
) -> WindowsReviewPacket:
    source_arg = args.source_arg or flow.caller_arg_expression or (
        f"arg{flow.caller_arg_index}"
    )
    entrypoint = flow.caller_name or _va_label(flow.caller_va, "function")
    helper = flow.helper_name or _va_label(flow.helper_va, "helper")
    gate_path = _gate_path_step(helper, gate_refinement)
    result = WindowsEmitReviewPacketTool().run(
        ctx,
        kb,
        WindowsEmitReviewPacketArgs(
            candidate_id=_candidate_id(args.binary, flow),
            binary=args.binary,
            build=args.build,
            entrypoint=entrypoint,
            attacker_class=args.attacker_class,
            source_role=args.source_role,
            source_arg=source_arg,
            source_refinement_status="matched",
            source_refinement_sources=_source_refinement_sources(
                args,
                flow,
                source_arg,
            ),
            source_refinement_blockers=[],
            sink_symbol=flow.sink_symbol,
            sink_kind=flow.sink_kind,
            required_gates=flow.required_gates,
            proven_gates=(
                gate_refinement.matched_required_gates
                if gate_refinement is not None
                else []
            ),
            gate_proof_sources=(
                gate_refinement.gate_proof_sources
                if gate_refinement is not None
                else {}
            ),
            missing_required_gates=(
                gate_refinement.missing_required_gates
                if gate_refinement is not None
                else []
            ),
            gate_status=(
                gate_refinement.packet_gate_status
                if gate_refinement is not None
                else "unknown"
            ),
            path=[
                WindowsReviewPathStep(
                    function=entrypoint,
                    symbol=helper,
                    arg_index=flow.caller_arg_index,
                    role="helper_argument",
                    evidence=(
                        f"caller invokes helper at VA 0x{flow.helper_callsite_va:x}"
                    ),
                ),
                *gate_path,
                WindowsReviewPathStep(
                    function=helper,
                    symbol=flow.sink_symbol,
                    arg_index=flow.helper_sink_arg_index,
                    role=flow.helper_sink_arg_role,
                    evidence=(
                        f"helper invokes sink at VA 0x{flow.sink_callsite_va:x}"
                    ),
                ),
            ],
            evidence=[
                WindowsReviewEvidence(
                    source="windows_project_onehop_argument_flow",
                    summary=_flow_summary(flow, source_arg),
                    provenance=[
                        "windows_project_onehop_flow_packets",
                        *flow.provenance,
                    ],
                ),
                WindowsReviewEvidence(
                    source="windows_project_onehop_sink_gate_metadata",
                    summary=_gate_summary(flow),
                    provenance=[
                        "windows_project_onehop_sink_chains",
                        "asb_pe_sink_metadata",
                    ],
                ),
                *_gate_evidence(gate_refinement),
            ],
            provenance=[
                "windows_project_onehop_flow_packets",
                "windows_project_onehop_argument_flow",
                "project_call_xrefs",
            ],
            required_project_facts=_required_project_facts(args),
            auto_join_manifest_context=True,
            project_facts_path=args.project_facts_path,
            ghidra_delta_path=args.ghidra_delta_path,
            manifest_target_id=args.manifest_target_id,
            manifest_build_label=args.manifest_build_label,
            manifest_component=args.manifest_component or args.binary,
            notes=[
                "emitted from conservative one-hop argument-flow match",
                "source refinement is matched only across one helper hop",
                _gate_note(gate_refinement),
            ],
        ),
    )
    return result.packet


@dataclass(frozen=True)
class _HelperGateRefinement:
    gate_symbol: str
    gate_va: int
    gate_proves: list[str]
    matched_required_gates: list[str]
    gate_proof_sources: dict[str, str]
    missing_required_gates: list[str]
    packet_gate_status: GateStatus
    summary: str
    provenance: list[str]
    dominance: WindowsCfgDominanceResult
    cfg_path: WindowsProjectCfgPathQueryResult | None
    predicates: list[ProjectBranchConditionFact]


def _refine_helper_gate(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOnehopFlowPacketsArgs,
    flow: WindowsProjectOnehopArgumentFlow,
) -> _HelperGateRefinement | None:
    if not args.refine_helper_gates or not flow.required_gates:
        return None
    try:
        gates_path = _resolve_metadata_path(args.gates_path, "data/kg/pe-gates.yaml")
        gates = [_gate_record(entry, gates_path) for entry in _load_yaml_list(gates_path)]
        function_calls = WindowsProjectCallsiteFactsTool().run(
            ctx,
            kb,
            WindowsProjectCallsiteFactsArgs(
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                function_va=flow.helper_va,
                operation_only=False,
                max_calls=512,
                add_to_kb=False,
            ),
        ).callsites
    except Exception:
        return None

    gates_by_symbol = _gates_by_symbol(gates)
    for candidate in function_calls:
        if candidate.callsite_va == flow.sink_callsite_va:
            continue
        name = candidate.callee_name or candidate.callee_demangled
        if not name:
            continue
        for gate in _matches_by_symbol(name, gates_by_symbol):
            if not _gate_compatible(gate, flow.required_gates):
                continue
            dominance = _dominance(ctx, kb, args, flow, candidate.callsite_va)
            if dominance is None:
                continue
            matched = matched_required_gates(gate.proves, flow.required_gates)
            missing = missing_required_gates(gate.proves, flow.required_gates)
            cfg_path = _cfg_path_query(
                ctx,
                kb,
                args,
                flow,
                candidate.callsite_va,
            )
            predicates = _gate_predicates(
                ctx,
                kb,
                args,
                flow,
                candidate.callsite_va,
                dominance,
                cfg_path,
            )
            return _HelperGateRefinement(
                gate_symbol=name,
                gate_va=candidate.callsite_va,
                gate_proves=gate.proves,
                matched_required_gates=matched,
                gate_proof_sources=gate_proof_sources(
                    gate.proves,
                    flow.required_gates,
                ),
                missing_required_gates=missing,
                packet_gate_status=_packet_gate_status(
                    dominance.status,
                    gate,
                    flow.required_gates,
                ),
                summary=(
                    f"{name}@0x{candidate.callsite_va:x} vs "
                    f"sink@0x{flow.sink_callsite_va:x}: {dominance.reason}"
                ),
                provenance=dominance.provenance,
                dominance=dominance,
                cfg_path=cfg_path,
                predicates=predicates,
            )
    return None


def _dominance(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOnehopFlowPacketsArgs,
    flow: WindowsProjectOnehopArgumentFlow,
    gate_va: int,
) -> WindowsCfgDominanceResult | None:
    try:
        return WindowsCfgDominanceTool().run(
            ctx,
            kb,
            WindowsCfgDominanceArgs(
                project_path=args.project_path,
                function_va=flow.helper_va,
                gate_va=gate_va,
                sink_va=flow.sink_callsite_va,
                add_to_kb=False,
            ),
        )
    except Exception:
        return None


def _cfg_path_query(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOnehopFlowPacketsArgs,
    flow: WindowsProjectOnehopArgumentFlow,
    gate_va: int,
) -> WindowsProjectCfgPathQueryResult | None:
    if not args.attach_helper_gate_paths:
        return None
    try:
        return WindowsProjectCfgPathQueryTool().run(
            ctx,
            kb,
            WindowsProjectCfgPathQueryArgs(
                project_path=args.project_path,
                function_va=flow.helper_va,
                gate_va=gate_va,
                sink_va=flow.sink_callsite_va,
                max_path_blocks=args.max_helper_gate_path_blocks,
                add_to_kb=False,
            ),
        )
    except Exception:
        return None


def _gate_predicates(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOnehopFlowPacketsArgs,
    flow: WindowsProjectOnehopArgumentFlow,
    gate_va: int,
    dominance: WindowsCfgDominanceResult,
    cfg_path: WindowsProjectCfgPathQueryResult | None,
) -> list[ProjectBranchConditionFact]:
    if not args.attach_helper_gate_predicates or args.max_helper_gate_predicates == 0:
        return []
    path_block_ids = cfg_path.entry_to_sink_path_block_ids if cfg_path else []
    try:
        result = WindowsProjectBranchConditionFactsTool().run(
            ctx,
            kb,
            WindowsProjectBranchConditionFactsArgs(
                project_path=args.project_path,
                function_va=flow.helper_va,
                path_block_ids=path_block_ids,
                max_rows=128,
                add_to_kb=False,
            ),
        )
    except Exception:
        return []
    if not result.facts:
        return []
    return _select_gate_predicates(
        result.facts,
        gate_va,
        dominance,
        args.max_helper_gate_predicates,
    )


def _gate_compatible(gate: GateRecord, required_gates: list[str]) -> bool:
    if not required_gates:
        return False
    return bool(matched_required_gates(gate.proves, required_gates))


def _packet_gate_status(
    status: str,
    gate: GateRecord,
    required_gates: list[str],
) -> GateStatus:
    if missing_required_gates(gate.proves, required_gates):
        return "unknown"
    if status == "dominated":
        return "dominated"
    if status == "not_dominated":
        return "not_dominated"
    if status == "same_block":
        return "gate_same_line"
    return "unknown"


def _gate_path_step(
    helper: str,
    refinement: _HelperGateRefinement | None,
) -> list[WindowsReviewPathStep]:
    if refinement is None:
        return []
    return [
        WindowsReviewPathStep(
            function=helper,
            symbol=refinement.gate_symbol,
            role="gate",
            evidence=f"helper-local gate call xref at VA 0x{refinement.gate_va:x}",
        )
    ]


def _gate_evidence(
    refinement: _HelperGateRefinement | None,
) -> list[WindowsReviewEvidence]:
    if refinement is None:
        return []
    return [
        WindowsReviewEvidence(
            source="windows_project_onehop_helper_gate_dominance",
            summary=refinement.summary,
            provenance=[
                "windows_project_onehop_flow_packets",
                "asb_pe_gate_metadata",
                "persisted_project_cfg",
                *refinement.provenance,
            ],
        ),
        WindowsReviewEvidence(
            source="windows_project_onehop_helper_gate_requirement_coverage",
            summary=_gate_requirement_summary(refinement),
            provenance=[
                "windows_project_onehop_flow_packets",
                "asb_pe_gate_metadata",
                "asb_pe_sink_metadata",
            ],
        ),
        *_cfg_path_evidence(refinement),
        *_predicate_evidence(refinement),
    ]


def _predicate_evidence(
    refinement: _HelperGateRefinement,
) -> list[WindowsReviewEvidence]:
    if not refinement.predicates:
        return []
    return [
        WindowsReviewEvidence(
            source="windows_project_onehop_helper_branch_condition_facts",
            summary=_predicate_summary(refinement.predicates),
            provenance=[
                "windows_project_onehop_flow_packets",
                "windows_project_branch_condition_facts",
                "persisted_project_branch_facts",
            ],
        )
    ]


def _select_gate_predicates(
    facts: list[ProjectBranchConditionFact],
    gate_va: int,
    dominance: WindowsCfgDominanceResult,
    max_count: int,
) -> list[ProjectBranchConditionFact]:
    gate_block_id = dominance.gate_block_id
    entry_block_id = dominance.entry_block_id
    sink_block_id = dominance.sink_block_id

    def score(fact: ProjectBranchConditionFact) -> tuple[int, int, int, int]:
        relation = 4
        if gate_block_id and fact.block_id == gate_block_id:
            relation = 0
        elif gate_block_id and (
            fact.target_block_id == gate_block_id
            or fact.fallthrough_block_id == gate_block_id
        ):
            relation = 1
        elif entry_block_id and fact.block_id == entry_block_id:
            relation = 2
        elif sink_block_id and (
            fact.target_block_id == sink_block_id
            or fact.fallthrough_block_id == sink_block_id
        ):
            relation = 3
        direction = 0 if fact.branch_va <= gate_va else 1
        return (relation, direction, abs(fact.branch_va - gate_va), fact.branch_va)

    ranked = sorted(facts, key=score)
    useful = [fact for fact in ranked if score(fact)[0] < 4]
    return (useful or ranked)[:max_count]


def _predicate_summary(facts: list[ProjectBranchConditionFact]) -> str:
    rendered = []
    for fact in facts:
        predicate = (
            fact.target_predicate or fact.fallthrough_predicate or fact.condition_kind
        )
        rendered.append(
            f"{fact.block_id}@0x{fact.branch_va:x} {fact.branch_mnemonic}: {predicate}"
        )
    return "nearby helper gate branch predicates: " + "; ".join(rendered)


def _cfg_path_evidence(
    refinement: _HelperGateRefinement,
) -> list[WindowsReviewEvidence]:
    if refinement.cfg_path is None:
        return []
    return [
        WindowsReviewEvidence(
            source="windows_project_onehop_helper_cfg_path",
            summary=_cfg_path_summary(refinement.cfg_path),
            provenance=[
                "windows_project_onehop_flow_packets",
                "windows_project_cfg_path_query",
                "persisted_project_cfg_sql",
            ],
        )
    ]


def _cfg_path_summary(result: WindowsProjectCfgPathQueryResult) -> str:
    parts = [f"status={result.status}", f"reason={result.reason}"]
    if result.entry_to_sink_path_block_ids:
        parts.append("entry_path=" + "->".join(result.entry_to_sink_path_block_ids))
    if result.gate_to_sink_path_block_ids:
        parts.append("gate_path=" + "->".join(result.gate_to_sink_path_block_ids))
    if result.bypass_path_block_ids:
        parts.append("bypass_path=" + "->".join(result.bypass_path_block_ids))
    return "; ".join(parts)


def _gate_requirement_summary(refinement: _HelperGateRefinement) -> str:
    matched = (
        ", ".join(refinement.matched_required_gates)
        if refinement.matched_required_gates
        else "none"
    )
    missing = (
        ", ".join(refinement.missing_required_gates)
        if refinement.missing_required_gates
        else "none"
    )
    proves = ", ".join(refinement.gate_proves) if refinement.gate_proves else "none"
    return (
        f"{refinement.gate_symbol}@0x{refinement.gate_va:x} proves [{proves}]; "
        f"matched required gates [{matched}]; missing required gates [{missing}]"
    )


def _gate_note(refinement: _HelperGateRefinement | None) -> str:
    if refinement is None:
        return (
            "gate status is unknown until dominance/path rules prove the required gates"
        )
    return "helper-local gate refinement attached from persisted CFG dominance"


def _required_project_facts(args: WindowsProjectOnehopFlowPacketsArgs) -> list[str]:
    facts = list(args.required_project_facts)
    if args.refine_helper_gates:
        facts.extend(["cfg", "cfg_dominance"])
    if args.attach_helper_gate_paths:
        facts.append("cfg_paths")
    if args.attach_helper_gate_predicates:
        facts.append("branch_conditions")
    return list(dict.fromkeys(facts))


def _source_refinement_sources(
    args: WindowsProjectOnehopFlowPacketsArgs,
    flow: WindowsProjectOnehopArgumentFlow,
    source_arg: str,
) -> list[str]:
    return [
        f"caller_arg{flow.caller_arg_index}",
        f"source_arg={source_arg}",
        f"source_role={args.source_role}",
        f"helper_sink_arg{flow.helper_sink_arg_index}:{flow.helper_sink_arg_role}",
        f"helper={flow.helper_name or _va_label(flow.helper_va, 'helper')}",
    ]


def _flow_summary(flow: WindowsProjectOnehopArgumentFlow, source_arg: str) -> str:
    return (
        f"caller arg{flow.caller_arg_index} {source_arg} reaches "
        f"{flow.sink_symbol} arg{flow.helper_sink_arg_index} "
        f"({flow.helper_sink_arg_role}) through "
        f"{flow.helper_name or _va_label(flow.helper_va, 'helper')} "
        f"at helper callsite 0x{flow.helper_callsite_va:x} and "
        f"sink callsite 0x{flow.sink_callsite_va:x}"
    )


def _gate_summary(flow: WindowsProjectOnehopArgumentFlow) -> str:
    effects = ", ".join(flow.sink_effects) if flow.sink_effects else "none"
    required = ", ".join(flow.required_gates) if flow.required_gates else "none"
    return f"sink effects [{effects}]; required gates [{required}]"


def _candidate_id(binary: str, flow: WindowsProjectOnehopArgumentFlow) -> str:
    return (
        f"{_safe(binary)}-onehop-0x{flow.helper_callsite_va:x}-"
        f"0x{flow.sink_callsite_va:x}-{_safe(flow.sink_symbol)}"
    )


def _safe(value: str) -> str:
    return (
        value.lower()
        .replace("\\", "-")
        .replace("/", "-")
        .replace("!", "-")
        .replace("::", "-")
    )


def _va_label(value: int | None, fallback: str) -> str:
    if value is None:
        return fallback
    return f"{fallback}_0x{value:x}"


def build_tool() -> WindowsProjectOnehopFlowPacketsTool:
    return WindowsProjectOnehopFlowPacketsTool()
