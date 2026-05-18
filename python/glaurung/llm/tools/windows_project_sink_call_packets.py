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
from .windows_function_arg_roles import (
    ArgumentRoleEvidence,
    WindowsFunctionArgRolesArgs,
    WindowsFunctionArgRolesTool,
)
from .windows_project_callsite_facts import (
    ProjectCallsiteFact,
    WindowsProjectCallsiteFactsArgs,
    WindowsProjectCallsiteFactsTool,
)
from .windows_project_call_argument_snapshot import (
    ProjectCallArgumentFact,
    WindowsProjectCallArgumentSnapshotArgs,
    WindowsProjectCallArgumentSnapshotTool,
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
from .windows_surface_metadata import GateRecord, _resolve_metadata_path


class WindowsProjectSinkCallPacketsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_path: str | None = Field(
        None,
        description=(
            "Optional PE binary path. When supplied, local call-argument snapshots "
            "are attached to emitted packets."
        ),
    )
    binary: str = Field(..., description="Binary or driver filename.")
    build: str | None = Field(None, description="Windows build or corpus label.")
    attacker_class: str = Field(
        "unknown",
        description="Attacker class to attach to emitted packets.",
    )
    source_role: str = Field(
        "unknown",
        description="Source role to attach before source-specific rules refine the packet.",
    )
    source_arg: str | None = Field(
        None,
        description="Optional source argument/expression if already known.",
    )
    source_arg_index: int | None = Field(
        None,
        description=(
            "Optional sink call argument index expected to carry the source value. "
            "Used only as local value-equivalence evidence."
        ),
    )
    infer_source_roles: bool = Field(
        False,
        description=(
            "If true, use ASB source metadata for the caller symbol to infer "
            "candidate source roles for local sink-argument matching."
        ),
    )
    binary_id: int | None = Field(None, description="Optional project binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter callsites.",
    )
    call_symbol: str | None = Field(
        None,
        description="Optional sink/callee symbol filter, e.g. RtlCopyMemory.",
    )
    sink_kind: str | None = Field(
        None,
        description="Optional ASB sink kind filter, e.g. copy, free, completion.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sources_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sources.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    refine_gates: bool = Field(
        False,
        description=(
            "If true, look for required-gate callsites in the same project "
            "function and attach persisted-CFG dominance evidence."
        ),
    )
    attach_gate_predicates: bool = Field(
        False,
        description=(
            "If true, attach nearby persisted branch-condition facts for refined "
            "gate callsites when cfg_branch_facts are available."
        ),
    )
    max_gate_predicates: int = Field(
        4,
        ge=0,
        le=32,
        description="Maximum branch-condition facts to attach per refined gate.",
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
        description="If true, add a compact project-sink packet evidence node to the KB.",
    )


class WindowsProjectSinkCallPacketsResult(BaseModel):
    project_path: str
    packet_count: int
    scanned_callsite_count: int
    argument_snapshot_count: int
    gate_refinement_count: int
    cfg_path_count: int
    gate_predicate_count: int
    gate_missing_required_count: int
    source_value_match_count: int
    source_role_inference_count: int
    packets: list[WindowsReviewPacket]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectSinkCallPacketsTool(
    MemoryTool[WindowsProjectSinkCallPacketsArgs, WindowsProjectSinkCallPacketsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_sink_call_packets",
                description=(
                    "Scan persisted .glaurung call xrefs for ASB sink operations "
                    "and emit manifest-backed Windows review packets."
                ),
                tags=("windows", "pe", "project", "callsites", "candidate", "packet"),
            ),
            WindowsProjectSinkCallPacketsArgs,
            WindowsProjectSinkCallPacketsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectSinkCallPacketsArgs,
    ) -> WindowsProjectSinkCallPacketsResult:
        callsites = WindowsProjectCallsiteFactsTool().run(
            ctx,
            kb,
            WindowsProjectCallsiteFactsArgs(
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                function_va=args.function_va,
                call_symbol=args.call_symbol,
                operation_only=True,
                max_calls=args.max_packets,
                add_to_kb=False,
            ),
        )

        packets: list[WindowsReviewPacket] = []
        argument_snapshot_count = 0
        gate_refinement_count = 0
        cfg_path_count = 0
        gate_predicate_count = 0
        gate_missing_required_count = 0
        source_value_match_count = 0
        source_role_inference_count = 0
        for callsite in callsites.callsites:
            if callsite.operation is None:
                continue
            if args.sink_kind and callsite.operation.sink_kind != args.sink_kind:
                continue
            snapshot_args = _snapshot_arguments(ctx, kb, args, callsite)
            if snapshot_args:
                argument_snapshot_count += 1
            gate_refinement = _refine_gate(ctx, kb, args, callsite)
            if gate_refinement is not None:
                gate_refinement_count += 1
                if gate_refinement.cfg_path is not None:
                    cfg_path_count += 1
                gate_predicate_count += len(gate_refinement.predicates)
                gate_missing_required_count += len(gate_refinement.missing_required_gates)
            inferred_roles = _infer_source_roles(ctx, kb, args, callsite)
            if inferred_roles:
                source_role_inference_count += 1
            source_match = _source_value_match(
                args,
                callsite,
                snapshot_args,
                inferred_roles,
            )
            if source_match is not None:
                source_value_match_count += 1
            packets.append(
                _emit_packet(
                    ctx,
                    kb,
                    args,
                    callsite,
                    snapshot_args,
                    gate_refinement,
                    source_match,
                )
            )
            if len(packets) >= args.max_packets:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_sink_call_packets",
                    props={
                        "project_path": args.project_path,
                        "binary": args.binary,
                        "call_symbol": args.call_symbol,
                        "sink_kind": args.sink_kind,
                        "packet_count": len(packets),
                        "scanned_callsite_count": callsites.scanned_call_count,
                        "argument_snapshot_count": argument_snapshot_count,
                        "gate_refinement_count": gate_refinement_count,
                        "cfg_path_count": cfg_path_count,
                        "gate_predicate_count": gate_predicate_count,
                        "gate_missing_required_count": gate_missing_required_count,
                        "source_value_match_count": source_value_match_count,
                        "source_role_inference_count": source_role_inference_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectSinkCallPacketsResult(
            project_path=args.project_path,
            packet_count=len(packets),
            scanned_callsite_count=callsites.scanned_call_count,
            argument_snapshot_count=argument_snapshot_count,
            gate_refinement_count=gate_refinement_count,
            cfg_path_count=cfg_path_count,
            gate_predicate_count=gate_predicate_count,
            gate_missing_required_count=gate_missing_required_count,
            source_value_match_count=source_value_match_count,
            source_role_inference_count=source_role_inference_count,
            packets=packets,
            evidence_node_id=evidence_node_id,
            notes=[
                "packets are project-scan seeds from sink callsites; source and gate proof still need dedicated rules"
            ],
        )


def _emit_packet(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    callsite: ProjectCallsiteFact,
    snapshot_args: list[ProjectCallArgumentFact],
    gate_refinement: "_GateRefinement | None",
    source_match: "_SourceValueMatch | None",
) -> WindowsReviewPacket:
    assert callsite.operation is not None
    sink_symbol = (
        callsite.callee_name
        or callsite.callee_demangled
        or args.call_symbol
        or callsite.operation.symbols[0]
    )
    entrypoint = callsite.caller_name or callsite.caller_demangled or _va_label(
        callsite.caller_va,
        "function",
    )
    role = _first_arg_role(callsite)
    gate_status: GateStatus = "unknown"
    evidence = [
        WindowsReviewEvidence(
            source="windows_project_callsite_facts",
            summary=(
                f"{entrypoint} calls {sink_symbol} at "
                f"0x{callsite.callsite_va:x}; sink_kind="
                f"{callsite.operation.sink_kind}"
            ),
            provenance=[
                *callsite.provenance,
                "windows_project_callsite_facts",
            ],
        )
    ]
    path = []
    if gate_refinement is not None:
        gate_status = gate_refinement.packet_gate_status
        path.append(
            WindowsReviewPathStep(
                function=entrypoint,
                symbol=gate_refinement.gate_symbol,
                role="gate",
                evidence=(
                    f"project gate call xref at VA "
                    f"0x{gate_refinement.gate_va:x}"
                ),
            )
        )
        evidence.append(
            WindowsReviewEvidence(
                source="windows_cfg_dominance",
                summary=gate_refinement.summary,
                provenance=[
                    "windows_project_sink_call_packets",
                    "asb_pe_gate_metadata",
                    "persisted_project_cfg",
                    *gate_refinement.provenance,
                ],
            )
        )
        if gate_refinement.cfg_path is not None:
            evidence.append(
                WindowsReviewEvidence(
                    source="windows_project_cfg_path_query",
                    summary=_cfg_path_summary(gate_refinement.cfg_path),
                    provenance=[
                        "windows_project_sink_call_packets",
                        "windows_project_cfg_path_query",
                        "persisted_project_cfg_sql",
                    ],
                )
            )
        evidence.append(
            WindowsReviewEvidence(
                source="windows_project_gate_requirement_coverage",
                summary=_gate_requirement_summary(gate_refinement),
                provenance=[
                    "windows_project_sink_call_packets",
                    "asb_pe_gate_metadata",
                    "asb_pe_sink_metadata",
                ],
            )
        )
        if gate_refinement.predicates:
            evidence.append(
                WindowsReviewEvidence(
                    source="windows_project_branch_condition_facts",
                    summary=_predicate_summary(gate_refinement.predicates),
                    provenance=[
                        "windows_project_sink_call_packets",
                        "windows_project_branch_condition_facts",
                        "persisted_project_branch_facts",
                    ],
                )
            )
    if snapshot_args:
        evidence.append(
            WindowsReviewEvidence(
                source="windows_project_call_argument_snapshot",
                summary=_argument_summary(snapshot_args),
                provenance=[
                    "windows_project_call_argument_snapshot",
                    "nearby_disassembly",
                ],
            )
        )
    if source_match is not None:
        evidence.append(
            WindowsReviewEvidence(
                source="windows_project_sink_argument_match",
                summary=source_match.summary,
                provenance=[
                    "windows_project_call_argument_snapshot",
                    "asb_pe_sink_metadata",
                    "local_value_equivalence",
                ],
            )
        )
    result = WindowsEmitReviewPacketTool().run(
        ctx,
        kb,
        WindowsEmitReviewPacketArgs(
            candidate_id=_candidate_id(args.binary, callsite.callsite_va, sink_symbol),
            binary=args.binary,
            build=args.build,
            entrypoint=entrypoint,
            attacker_class=args.attacker_class,
            source_role=(
                source_match.source_role
                if source_match is not None and args.source_role == "unknown"
                else args.source_role
            ),
            source_arg=args.source_arg or (source_match.source_arg if source_match else None),
            sink_symbol=sink_symbol,
            sink_kind=callsite.operation.sink_kind,
            required_gates=callsite.operation.required_gates,
            gate_status=gate_status,
            path=[
                *path,
                WindowsReviewPathStep(
                    function=entrypoint,
                    symbol=sink_symbol,
                    arg_index=role[0],
                    role=role[1],
                    evidence=f"project call xref at VA 0x{callsite.callsite_va:x}",
                ),
            ],
            evidence=evidence,
            provenance=["project_sink_call_scan"],
            required_project_facts=_required_project_facts(args),
            auto_join_manifest_context=True,
            project_facts_path=args.project_facts_path,
            ghidra_delta_path=args.ghidra_delta_path,
            manifest_target_id=args.manifest_target_id,
            manifest_build_label=args.manifest_build_label,
            manifest_component=args.manifest_component or args.binary,
            notes=[
                "emitted from project sink-call scan",
                "source role and gate status are placeholders until source/gate rules refine this packet",
            ],
        ),
    )
    return result.packet


def _first_arg_role(callsite: ProjectCallsiteFact) -> tuple[int | None, str | None]:
    if callsite.operation is None or not callsite.operation.arg_roles:
        return None, None
    role = callsite.operation.arg_roles[0]
    return role.index, role.role


def _required_project_facts(args: WindowsProjectSinkCallPacketsArgs) -> list[str]:
    facts = list(args.required_project_facts)
    if args.refine_gates:
        facts.extend(["cfg", "cfg_dominance"])
    if args.attach_gate_predicates:
        facts.append("branch_conditions")
    return _dedupe(facts)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


@dataclass(frozen=True)
class _SourceValueMatch:
    source_arg: str
    source_role: str
    sink_arg_index: int
    sink_arg_role: str | None
    expression: str | None
    summary: str


@dataclass(frozen=True)
class _GateRefinement:
    gate_symbol: str
    gate_va: int
    gate_proves: list[str]
    matched_required_gates: list[str]
    missing_required_gates: list[str]
    packet_gate_status: GateStatus
    summary: str
    provenance: list[str]
    cfg_path: WindowsProjectCfgPathQueryResult | None
    predicates: list[ProjectBranchConditionFact]


def _refine_gate(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    sink_callsite: ProjectCallsiteFact,
) -> _GateRefinement | None:
    if not args.refine_gates or sink_callsite.operation is None:
        return None
    if not sink_callsite.operation.required_gates or sink_callsite.caller_va is None:
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
                function_va=sink_callsite.caller_va,
                operation_only=False,
                max_calls=512,
                add_to_kb=False,
            ),
        ).callsites
    except Exception:
        return None

    gates_by_symbol = _gates_by_symbol(gates)
    for candidate in function_calls:
        if candidate.callsite_va == sink_callsite.callsite_va:
            continue
        name = candidate.callee_name or candidate.callee_demangled
        if not name:
            continue
        for gate in _matches_by_symbol(name, gates_by_symbol):
            if not _gate_compatible(gate, sink_callsite.operation.required_gates):
                continue
            dominance = _dominance(ctx, kb, args, sink_callsite, candidate)
            if dominance is None:
                continue
            cfg_path = _gate_cfg_path_query(ctx, kb, args, sink_callsite, candidate)
            predicates = _gate_predicates(
                ctx,
                kb,
                args,
                sink_callsite,
                candidate,
                dominance,
                cfg_path,
            )
            return _GateRefinement(
                gate_symbol=name,
                gate_va=candidate.callsite_va,
                gate_proves=gate.proves,
                matched_required_gates=_matched_required_gates(
                    gate,
                    sink_callsite.operation.required_gates,
                ),
                missing_required_gates=_missing_required_gates(
                    gate,
                    sink_callsite.operation.required_gates,
                ),
                packet_gate_status=_packet_gate_status(
                    dominance.status,
                    gate,
                    sink_callsite.operation.required_gates,
                ),
                summary=(
                    f"{name}@0x{candidate.callsite_va:x} vs "
                    f"sink@0x{sink_callsite.callsite_va:x}: {dominance.reason}"
                ),
                provenance=dominance.provenance,
                cfg_path=cfg_path,
                predicates=predicates,
            )
    return None


def _gate_compatible(gate: GateRecord, required_gates: list[str]) -> bool:
    required = set(required_gates)
    if not required:
        return False
    return bool(required & set(gate.proves))


def _dominance(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    sink_callsite: ProjectCallsiteFact,
    gate_callsite: ProjectCallsiteFact,
) -> WindowsCfgDominanceResult | None:
    try:
        return WindowsCfgDominanceTool().run(
            ctx,
            kb,
            WindowsCfgDominanceArgs(
                project_path=args.project_path,
                function_va=sink_callsite.caller_va,
                gate_va=gate_callsite.callsite_va,
                sink_va=sink_callsite.callsite_va,
                add_to_kb=False,
            ),
        )
    except Exception:
        return None


def _packet_gate_status(
    status: str,
    gate: GateRecord,
    required_gates: list[str],
) -> GateStatus:
    if _missing_required_gates(gate, required_gates):
        return "unknown"
    if status == "dominated":
        return "dominated"
    if status == "not_dominated":
        return "not_dominated"
    if status == "same_block":
        return "gate_same_line"
    return "unknown"


def _matched_required_gates(gate: GateRecord, required_gates: list[str]) -> list[str]:
    proven = set(gate.proves)
    return [required for required in required_gates if required in proven]


def _missing_required_gates(gate: GateRecord, required_gates: list[str]) -> list[str]:
    proven = set(gate.proves)
    return [required for required in required_gates if required not in proven]


def _gate_requirement_summary(refinement: _GateRefinement) -> str:
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


def _gate_predicates(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    sink_callsite: ProjectCallsiteFact,
    gate_callsite: ProjectCallsiteFact,
    dominance: WindowsCfgDominanceResult,
    cfg_path: WindowsProjectCfgPathQueryResult | None,
) -> list[ProjectBranchConditionFact]:
    if not args.attach_gate_predicates or args.max_gate_predicates == 0:
        return []
    function_va = sink_callsite.caller_va or dominance.function_va
    if function_va is None:
        return []
    path_block_ids = cfg_path.entry_to_sink_path_block_ids if cfg_path else []
    try:
        result = WindowsProjectBranchConditionFactsTool().run(
            ctx,
            kb,
            WindowsProjectBranchConditionFactsArgs(
                project_path=args.project_path,
                function_va=function_va,
                path_block_ids=path_block_ids,
                max_rows=128,
                add_to_kb=False,
            ),
        )
    except Exception:
        return []
    if not result.facts:
        return []
    selected = _select_gate_predicates(
        result.facts,
        gate_callsite.callsite_va,
        dominance,
        args.max_gate_predicates,
    )
    return selected


def _gate_cfg_path_query(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    sink_callsite: ProjectCallsiteFact,
    gate_callsite: ProjectCallsiteFact,
) -> WindowsProjectCfgPathQueryResult | None:
    if sink_callsite.caller_va is None:
        return None
    try:
        return WindowsProjectCfgPathQueryTool().run(
            ctx,
            kb,
            WindowsProjectCfgPathQueryArgs(
                project_path=args.project_path,
                function_va=sink_callsite.caller_va,
                gate_va=gate_callsite.callsite_va,
                sink_va=sink_callsite.callsite_va,
                max_path_blocks=64,
                add_to_kb=False,
            ),
        )
    except Exception:
        return None


def _cfg_path_summary(result: WindowsProjectCfgPathQueryResult) -> str:
    parts = [f"status={result.status}", f"reason={result.reason}"]
    if result.entry_to_sink_path_block_ids:
        parts.append("entry_path=" + "->".join(result.entry_to_sink_path_block_ids))
    if result.gate_to_sink_path_block_ids:
        parts.append("gate_path=" + "->".join(result.gate_to_sink_path_block_ids))
    if result.bypass_path_block_ids:
        parts.append("bypass_path=" + "->".join(result.bypass_path_block_ids))
    return "; ".join(parts)


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
    return "nearby gate branch predicates: " + "; ".join(rendered)


def _source_value_match(
    args: WindowsProjectSinkCallPacketsArgs,
    callsite: ProjectCallsiteFact,
    snapshot_args: list[ProjectCallArgumentFact],
    inferred_roles: list[ArgumentRoleEvidence],
) -> _SourceValueMatch | None:
    if not snapshot_args:
        return None
    if args.source_arg_index is None and not args.source_arg and not inferred_roles:
        return None

    for argument in snapshot_args:
        if args.source_arg_index is not None and argument.index == args.source_arg_index:
            return _source_match_from_argument(
                args,
                callsite,
                argument,
                f"arg{argument.index}",
                args.source_role,
            )
        if args.source_arg and _argument_matches_source(args.source_arg, argument):
            return _source_match_from_argument(
                args,
                callsite,
                argument,
                args.source_arg,
                args.source_role,
            )
        for role in inferred_roles:
            source_label = _source_label(role)
            if source_label and _argument_matches_inferred_role(role, argument):
                return _source_match_from_argument(
                    args,
                    callsite,
                    argument,
                    source_label,
                    role.role,
                    source_provenance=role.provenance,
                )
    return None


def _infer_source_roles(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    callsite: ProjectCallsiteFact,
) -> list[ArgumentRoleEvidence]:
    if not args.infer_source_roles:
        return []
    caller = callsite.caller_name or callsite.caller_demangled
    if not caller:
        return []
    names = [caller]
    if "!" in caller:
        names.append(caller.split("!", 1)[1])
    for name in names:
        try:
            result = WindowsFunctionArgRolesTool().run(
                ctx,
                kb,
                WindowsFunctionArgRolesArgs(
                    function_name=name,
                    sources_path=args.sources_path,
                    include_unmatched_prototype_args=False,
                ),
            )
        except Exception:
            continue
        if result.combined_roles:
            return result.combined_roles
    return []


def _source_match_from_argument(
    args: WindowsProjectSinkCallPacketsArgs,
    callsite: ProjectCallsiteFact,
    argument: ProjectCallArgumentFact,
    source_arg: str,
    source_role: str,
    *,
    source_provenance: str | None = None,
) -> _SourceValueMatch:
    role = _operation_arg_role(callsite, argument.index)
    expression = argument.expression
    summary = (
        f"source {source_role} {source_arg} matches sink arg"
        f"{argument.index}"
    )
    if role:
        summary += f" ({role})"
    if expression:
        summary += f" expression {expression}"
    return _SourceValueMatch(
        source_arg=source_arg,
        source_role=source_role,
        sink_arg_index=argument.index,
        sink_arg_role=role,
        expression=expression,
        summary=summary
        + (f"; source_provenance={source_provenance}" if source_provenance else ""),
    )


def _argument_matches_source(
    source_arg: str,
    argument: ProjectCallArgumentFact,
) -> bool:
    needle = _norm(source_arg)
    if needle == f"arg{argument.index}":
        return True
    values = [
        argument.expression,
        argument.register_name,
        argument.role,
        argument.source_text,
    ]
    return any(_norm(value) == needle for value in values if value)


def _argument_matches_inferred_role(
    role: ArgumentRoleEvidence,
    argument: ProjectCallArgumentFact,
) -> bool:
    if role.index is not None:
        if argument.expression == f"caller_arg{role.index}":
            return True
        if argument.alias_kind == "incoming_arg" and argument.expression == f"caller_arg{role.index}":
            return True
    if role.expression and _argument_matches_source(role.expression, argument):
        return True
    return False


def _source_label(role: ArgumentRoleEvidence) -> str | None:
    if role.expression:
        return role.expression
    if role.index is not None:
        return f"caller_arg{role.index}"
    return None


def _operation_arg_role(
    callsite: ProjectCallsiteFact,
    index: int,
) -> str | None:
    if callsite.operation is None:
        return None
    for role in callsite.operation.arg_roles:
        if role.index == index:
            return role.role
    return None


def _norm(value: str) -> str:
    return value.strip().lower().replace(" ", "")


def _snapshot_arguments(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    callsite: ProjectCallsiteFact,
) -> list[ProjectCallArgumentFact]:
    if not args.binary_path:
        return []
    try:
        result = WindowsProjectCallArgumentSnapshotTool().run(
            ctx,
            kb,
            WindowsProjectCallArgumentSnapshotArgs(
                binary_path=args.binary_path,
                project_path=args.project_path,
                callsite_va=callsite.callsite_va,
                binary_id=args.binary_id,
                add_to_kb=False,
            ),
        )
    except Exception:
        return []
    return result.arguments


def _argument_summary(arguments: list[ProjectCallArgumentFact]) -> str:
    rendered = []
    for argument in arguments[:6]:
        expr = argument.expression or "unknown"
        rendered.append(f"arg{argument.index}={expr}")
    suffix = "" if len(arguments) <= 6 else f"; +{len(arguments) - 6} more"
    return "local call argument snapshot: " + ", ".join(rendered) + suffix


def _candidate_id(binary: str, callsite_va: int, sink_symbol: str) -> str:
    safe_binary = binary.lower().replace("\\", "-").replace("/", "-")
    safe_symbol = sink_symbol.lower().replace("!", "-").replace("::", "-")
    return f"{safe_binary}-sink-0x{callsite_va:x}-{safe_symbol}"


def _va_label(value: int | None, fallback: str) -> str:
    if value is None:
        return fallback
    return f"{fallback}_0x{value:x}"


def build_tool() -> MemoryTool[
    WindowsProjectSinkCallPacketsArgs, WindowsProjectSinkCallPacketsResult
]:
    return WindowsProjectSinkCallPacketsTool()
