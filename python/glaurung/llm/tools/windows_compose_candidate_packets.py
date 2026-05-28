from __future__ import annotations

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_check_gate_to_sink import (
    GateSinkAssessment,
    WindowsCheckGateToSinkArgs,
    WindowsCheckGateToSinkTool,
)
from .windows_emit_review_packet import (
    WindowsComponentProfileContext,
    WindowsDiffContext,
    WindowsEmitReviewPacketArgs,
    WindowsEmitReviewPacketTool,
    WindowsGhidraDeltaContext,
    WindowsPdbIdentityContext,
    WindowsProjectFactContext,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from .windows_operation_metadata import OperationRecord
from .windows_trace_arg_flow import (
    ArgFlowHit,
    WindowsTraceArgFlowArgs,
    WindowsTraceArgFlowTool,
)
from .windows_trace_onehop_flow import (
    HelperPseudocode,
    OneHopFlowHit,
    WindowsTraceOnehopFlowArgs,
    WindowsTraceOnehopFlowTool,
)


class WindowsComposeCandidatePacketsArgs(BaseModel):
    binary: str = Field(..., description="Binary or driver name.")
    build: str | None = Field(None, description="Windows build or product version.")
    entrypoint: str = Field(..., description="Entrypoint or audited function name.")
    attacker_class: str = Field(..., description="Attacker class for the source.")
    source_role: str = Field(
        ...,
        description="Role of attacker-controlled value: buffer, length, handle, etc.",
    )
    source_arg_index: int | None = Field(
        None,
        description="Zero-based source argument index to trace from caller signature.",
    )
    source_name: str | None = Field(
        None,
        description="Source variable name. Used directly or derived from source_arg_index.",
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
        description="Optional helper pseudocode entries for one-hop flow.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    gate_kind: str | None = Field(None, description="Optional gate kind filter.")
    sink_kind: str | None = Field(None, description="Optional sink kind filter.")
    max_candidates: int = Field(8, description="Maximum review packets to emit.")
    max_depth: int = Field(2, description="Maximum simple alias depth.")
    timeout_ms: int = Field(500, description="Decompile timeout when VA is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    pdb_identity: WindowsPdbIdentityContext | None = Field(
        None,
        description="Optional target/PDB identity manifest context to attach to packets.",
    )
    component_profile: WindowsComponentProfileContext | None = Field(
        None,
        description="Optional high-risk Windows component profile context.",
    )
    diff_context: WindowsDiffContext | None = Field(
        None,
        description="Optional patch-regression or binary-diff context.",
    )
    project_facts: WindowsProjectFactContext | None = Field(
        None,
        description="Optional .glaurung project fact coverage context.",
    )
    required_project_facts: list[str] = Field(
        default_factory=list,
        description="Project fact classes required before packet promotion.",
    )
    ghidra_delta: WindowsGhidraDeltaContext | None = Field(
        None,
        description="Optional Ghidra-parity gap context for this target.",
    )
    auto_join_manifest_context: bool = Field(
        False,
        description="If true, fill missing project/Ghidra context from ASB manifests.",
    )
    project_facts_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-project-facts.yaml for auto-join.",
    )
    ghidra_delta_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-ghidra-delta.yaml for auto-join.",
    )
    manifest_target_id: str | None = Field(
        None,
        description="Optional ASB target id used for manifest auto-join.",
    )
    manifest_build_label: str | None = Field(
        None,
        description="Optional ASB build label used for manifest auto-join.",
    )
    manifest_component: str | None = Field(
        None,
        description="Optional Windows component filename used for Ghidra-delta auto-join.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact candidate-composition evidence node to the KB.",
    )


class WindowsCandidateComposition(BaseModel):
    packet: WindowsReviewPacket
    flow_kind: str
    gate_assessment: GateSinkAssessment | None = None


class WindowsComposeCandidatePacketsResult(BaseModel):
    packets: list[WindowsCandidateComposition]
    flow_count: int
    gate_assessment_count: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsComposeCandidatePacketsTool(
    MemoryTool[WindowsComposeCandidatePacketsArgs, WindowsComposeCandidatePacketsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_compose_candidate_packets",
                description=(
                    "Compose Windows argument-flow and gate-order primitive outputs "
                    "into candidate review packets. This is a triage bridge, not a "
                    "finding verdict."
                ),
                tags=("windows", "pe", "candidate", "review", "flow"),
            ),
            WindowsComposeCandidatePacketsArgs,
            WindowsComposeCandidatePacketsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsComposeCandidatePacketsArgs,
    ) -> WindowsComposeCandidatePacketsResult:
        notes = [
            "candidate composition uses pseudocode/simple-flow evidence; it is not CFG or IR proof"
        ]
        flow_items = _collect_flows(ctx, kb, args, notes)
        gate_result = _check_gates(ctx, kb, args)
        packets = []

        for flow_kind, flow, helper in flow_items:
            operation = _flow_operation(flow)
            if operation is None:
                continue
            if args.sink_kind and operation.sink_kind != args.sink_kind:
                continue
            assessment = _matching_assessment(gate_result.assessments, operation)
            packet = _emit_packet(ctx, kb, args, flow_kind, flow, helper, operation, assessment)
            packets.append(
                WindowsCandidateComposition(
                    packet=packet,
                    flow_kind=flow_kind,
                    gate_assessment=assessment,
                )
            )
            if len(packets) >= args.max_candidates:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_compose_candidate_packets",
                    props={
                        "entrypoint": args.entrypoint,
                        "flow_count": len(flow_items),
                        "packet_count": len(packets),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsComposeCandidatePacketsResult(
            packets=packets,
            flow_count=len(flow_items),
            gate_assessment_count=len(gate_result.assessments),
            evidence_node_id=evidence_node_id,
            notes=[*notes, *gate_result.notes],
        )


def _collect_flows(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsComposeCandidatePacketsArgs,
    notes: list[str],
) -> list[tuple[str, ArgFlowHit | OneHopFlowHit, HelperPseudocode | None]]:
    if args.helpers:
        result = WindowsTraceOnehopFlowTool().run(
            ctx,
            kb,
            WindowsTraceOnehopFlowArgs(
                source_arg_index=args.source_arg_index,
                source_name=args.source_name,
                caller_pseudocode=args.caller_pseudocode,
                caller_function_va=args.caller_function_va,
                helpers=args.helpers,
                sinks_path=args.sinks_path,
                max_depth=args.max_depth,
                max_flows=args.max_candidates,
                timeout_ms=args.timeout_ms,
                pdb_cache=args.pdb_cache,
            ),
        )
        notes.extend(result.notes)
        helper_by_name = {helper.name: helper for helper in args.helpers}
        return [
            ("onehop", flow, helper_by_name.get(flow.helper))
            for flow in result.flows
        ]

    result = WindowsTraceArgFlowTool().run(
        ctx,
        kb,
        WindowsTraceArgFlowArgs(
            source_arg_index=args.source_arg_index,
            source_name=args.source_name,
            pseudocode=args.caller_pseudocode,
            function_va=args.caller_function_va,
            sinks_path=args.sinks_path,
            max_depth=args.max_depth,
            max_flows=args.max_candidates,
            timeout_ms=args.timeout_ms,
            pdb_cache=args.pdb_cache,
        ),
    )
    notes.extend(result.notes)
    return [("intra", flow, None) for flow in result.flows]


def _check_gates(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsComposeCandidatePacketsArgs,
):
    return WindowsCheckGateToSinkTool().run(
        ctx,
        kb,
        WindowsCheckGateToSinkArgs(
            gates_path=args.gates_path,
            sinks_path=args.sinks_path,
            pseudocode=_combined_pseudocode(args),
            function_va=args.caller_function_va if not args.caller_pseudocode else None,
            gate_kind=args.gate_kind,
            sink_kind=args.sink_kind,
            timeout_ms=args.timeout_ms,
            pdb_cache=args.pdb_cache,
        ),
    )


def _combined_pseudocode(args: WindowsComposeCandidatePacketsArgs) -> str | None:
    parts: list[str] = []
    if args.caller_pseudocode:
        parts.append(args.caller_pseudocode)
    for helper in args.helpers:
        parts.append(helper.pseudocode)
    if not parts:
        return None
    return "\n".join(parts)


def _flow_operation(flow: ArgFlowHit | OneHopFlowHit) -> OperationRecord | None:
    if isinstance(flow, OneHopFlowHit):
        return flow.sink_flow.operation
    return flow.operation


def _flow_sink_symbol(flow: ArgFlowHit | OneHopFlowHit) -> str:
    if isinstance(flow, OneHopFlowHit):
        return flow.sink_flow.callee
    return flow.callee


def _matching_assessment(
    assessments: list[GateSinkAssessment],
    operation: OperationRecord,
) -> GateSinkAssessment | None:
    for assessment in assessments:
        if assessment.sink.operation.id == operation.id:
            return assessment
    return None


def _emit_packet(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsComposeCandidatePacketsArgs,
    flow_kind: str,
    flow: ArgFlowHit | OneHopFlowHit,
    helper: HelperPseudocode | None,
    operation: OperationRecord,
    assessment: GateSinkAssessment | None,
) -> WindowsReviewPacket:
    evidence = [
        WindowsReviewEvidence(
            source=(
                "windows_trace_onehop_flow"
                if isinstance(flow, OneHopFlowHit)
                else "windows_trace_arg_flow"
            ),
            summary=_flow_summary(flow),
            provenance=_flow_provenance(flow),
        ),
    ]
    if assessment is not None:
        evidence.append(
            WindowsReviewEvidence(
                source="windows_check_gate_to_sink",
                summary=assessment.reason,
                provenance=assessment.provenance,
            )
        )

    result = WindowsEmitReviewPacketTool().run(
        ctx,
        kb,
        WindowsEmitReviewPacketArgs(
            binary=args.binary,
            build=args.build,
            entrypoint=args.entrypoint,
            attacker_class=args.attacker_class,
            source_role=args.source_role,
            source_arg=args.source_name or _source_arg_label(args.source_arg_index),
            sink_symbol=_flow_sink_symbol(flow),
            sink_kind=operation.sink_kind,
            required_gates=operation.required_gates,
            gate_status=assessment.status if assessment is not None else "unknown",
            path=_path_steps(args, flow_kind, flow, helper, operation),
            evidence=evidence,
            provenance=["asb_pe_sink_metadata", "pseudocode_candidate_composition"],
            pdb_identity=args.pdb_identity,
            component_profile=args.component_profile,
            diff_context=args.diff_context,
            project_facts=args.project_facts,
            required_project_facts=args.required_project_facts,
            ghidra_delta=args.ghidra_delta,
            auto_join_manifest_context=args.auto_join_manifest_context,
            project_facts_path=args.project_facts_path,
            ghidra_delta_path=args.ghidra_delta_path,
            manifest_target_id=args.manifest_target_id,
            manifest_build_label=args.manifest_build_label,
            manifest_component=args.manifest_component,
            notes=[
                "composed from existing primitive tools",
                "candidate is static triage evidence only",
            ],
        ),
    )
    return result.packet


def _source_arg_label(index: int | None) -> str | None:
    if index is None:
        return None
    return f"arg{index}"


def _flow_summary(flow: ArgFlowHit | OneHopFlowHit) -> str:
    if isinstance(flow, OneHopFlowHit):
        return (
            f"caller arg {flow.caller_arg_index} reaches {flow.helper} "
            f"then sink {flow.sink_flow.callee} arg {flow.sink_flow.callee_arg_index}"
        )
    return f"source reaches sink {flow.callee} arg {flow.callee_arg_index}"


def _flow_provenance(flow: ArgFlowHit | OneHopFlowHit) -> list[str]:
    if isinstance(flow, OneHopFlowHit):
        return [*flow.provenance, *flow.sink_flow.provenance]
    return flow.provenance


def _path_steps(
    args: WindowsComposeCandidatePacketsArgs,
    flow_kind: str,
    flow: ArgFlowHit | OneHopFlowHit,
    helper: HelperPseudocode | None,
    operation: OperationRecord,
) -> list[WindowsReviewPathStep]:
    if isinstance(flow, OneHopFlowHit):
        return [
            WindowsReviewPathStep(
                function=args.entrypoint,
                symbol=flow.helper,
                arg_index=flow.caller_arg_index,
                role=args.source_role,
                evidence=flow.caller_snippet,
            ),
            WindowsReviewPathStep(
                function=helper.name if helper is not None else flow.helper,
                symbol=flow.sink_flow.callee,
                arg_index=flow.sink_flow.callee_arg_index,
                role=_operation_role(operation, flow.sink_flow.callee_arg_index),
                evidence=flow.sink_flow.snippet,
            ),
        ]
    return [
        WindowsReviewPathStep(
            function=args.entrypoint,
            symbol=flow.callee,
            arg_index=flow.callee_arg_index,
            role=_operation_role(operation, flow.callee_arg_index),
            evidence=flow.snippet,
        )
    ]


def _operation_role(operation: OperationRecord, index: int) -> str | None:
    for role in operation.arg_roles:
        if role.index == index:
            return role.role
    return None


def build_tool() -> MemoryTool[
    WindowsComposeCandidatePacketsArgs, WindowsComposeCandidatePacketsResult
]:
    return WindowsComposeCandidatePacketsTool()
