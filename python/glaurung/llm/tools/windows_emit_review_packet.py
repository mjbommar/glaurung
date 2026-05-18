from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_ghidra_delta_manifest import (
    WindowsGhidraDeltaManifestArgs,
    WindowsGhidraDeltaManifestTool,
)
from .windows_project_fact_manifest import (
    ProjectFactRecord,
    WindowsProjectFactManifestArgs,
    WindowsProjectFactManifestTool,
)


GateStatus = Literal[
    "unknown",
    "missing",
    "gate_before_sink",
    "gate_after_sink",
    "gate_same_line",
    "dominated",
    "not_dominated",
]
CandidatePriority = Literal["low", "medium", "high"]


class WindowsReviewPathStep(BaseModel):
    function: str
    symbol: str | None = None
    arg_index: int | None = None
    role: str | None = None
    evidence: str | None = None


class WindowsReviewEvidence(BaseModel):
    source: str
    summary: str
    provenance: list[str] = Field(default_factory=list)


class WindowsPdbIdentityContext(BaseModel):
    target_id: str | None = None
    expected_pdb_name: str | None = None
    codeview_guid_age: str | None = None
    cache_status: str | None = None
    symbol_cache_path: str | None = None
    fact_coverage: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)


class WindowsComponentProfileContext(BaseModel):
    profile_id: str | None = None
    target_id: str | None = None
    component: str | None = None
    entrypoint_kinds: list[str] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    validation_requirements: list[str] = Field(default_factory=list)
    harness_strategy: str | None = None
    evidence_packet_fields: list[str] = Field(default_factory=list)


class WindowsDiffContext(BaseModel):
    seed_id: str | None = None
    public_ids: list[str] = Field(default_factory=list)
    pre_build: str | None = None
    post_build: str | None = None
    changed_functions: list[str] = Field(default_factory=list)
    missing_functions: list[str] = Field(default_factory=list)
    diff_signals: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WindowsProjectFactContext(BaseModel):
    target_id: str | None = None
    build_label: str | None = None
    project_path: str | None = None
    fact_coverage: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class WindowsGhidraDeltaContext(BaseModel):
    target_id: str | None = None
    component: str | None = None
    build_label: str | None = None
    blocking_fact_classes: list[str] = Field(default_factory=list)
    current_capabilities: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WindowsEmitReviewPacketArgs(BaseModel):
    candidate_id: str | None = Field(
        None,
        description="Optional stable candidate id. If absent, one is derived.",
    )
    binary: str = Field(..., description="Binary or driver name.")
    build: str | None = Field(None, description="Windows build or product version.")
    entrypoint: str = Field(..., description="Surface entrypoint or audited function.")
    attacker_class: str = Field(
        ...,
        description="Attacker class, e.g. local_unprivileged, appcontainer, remote.",
    )
    source_role: str = Field(
        ...,
        description="Role of attacker-controlled value: buffer, length, handle, etc.",
    )
    source_arg: str | None = Field(
        None,
        description="Optional source argument name, index, or expression.",
    )
    sink_symbol: str = Field(..., description="Security-relevant operation symbol.")
    sink_kind: str = Field(
        ...,
        description="Security-relevant operation family: copy, write, free, etc.",
    )
    required_gates: list[str] = Field(
        default_factory=list,
        description="Gate semantics expected before the sink.",
    )
    proven_gates: list[str] = Field(
        default_factory=list,
        description=(
            "Gate semantics already proven by the supplied gate evidence. "
            "If empty with gate_status=dominated, all required gates are assumed proven."
        ),
    )
    gate_proof_sources: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Map required gate semantics to the concrete gate proof fact that "
            "established each semantic, e.g. destination_range_valid -> "
            "user_pointer_write_range_valid."
        ),
    )
    missing_required_gates: list[str] = Field(
        default_factory=list,
        description=(
            "Required gate semantics known to remain unproven. Supplying this "
            "disables the dominated-status fallback that assumes all gates are proven."
        ),
    )
    gate_status: GateStatus = Field(
        "unknown",
        description="Current gate evidence for the source-to-sink path.",
    )
    path: list[WindowsReviewPathStep] = Field(
        default_factory=list,
        description="Observed source-to-sink path steps.",
    )
    evidence: list[WindowsReviewEvidence] = Field(
        default_factory=list,
        description="Atomic observations that support or weaken the packet.",
    )
    provenance: list[str] = Field(
        default_factory=list,
        description="Overall fact provenance: PE, PDB, ASB metadata, IR, dynamic trace.",
    )
    pdb_identity: WindowsPdbIdentityContext | None = Field(
        None,
        description="Optional target/PDB identity manifest context.",
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
        description=(
            "Project fact classes required before this packet can be promoted. "
            "If empty, a conservative set is inferred from the packet shape."
        ),
    )
    ghidra_delta: WindowsGhidraDeltaContext | None = Field(
        None,
        description="Optional Ghidra-parity gap context for this target.",
    )
    auto_join_manifest_context: bool = Field(
        False,
        description=(
            "If true, fill missing project_facts and ghidra_delta context from "
            "ASB manifests using manifest_target_id/build/component or packet fields."
        ),
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
    notes: list[str] = Field(default_factory=list)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact review-packet evidence node to the KB.",
    )


class WindowsReviewPacket(BaseModel):
    candidate_id: str
    claim_level: Literal["candidate_not_finding"] = "candidate_not_finding"
    binary: str
    build: str | None
    entrypoint: str
    attacker_class: str
    source_role: str
    source_arg: str | None
    sink_symbol: str
    sink_kind: str
    required_gates: list[str]
    proven_gates: list[str] = Field(default_factory=list)
    gate_proof_sources: dict[str, str] = Field(default_factory=dict)
    missing_required_gates: list[str] = Field(default_factory=list)
    gate_status: GateStatus
    path: list[WindowsReviewPathStep]
    evidence: list[WindowsReviewEvidence]
    provenance: list[str]
    pdb_identity: WindowsPdbIdentityContext | None = None
    component_profile: WindowsComponentProfileContext | None = None
    diff_context: WindowsDiffContext | None = None
    project_facts: WindowsProjectFactContext | None = None
    required_project_facts: list[str] = Field(default_factory=list)
    ghidra_delta: WindowsGhidraDeltaContext | None = None
    promotion_preconditions_met: bool
    promotion_blockers: list[str] = Field(default_factory=list)
    priority: CandidatePriority
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_reason: str
    next_validation: list[str]
    false_positive_questions: list[str]
    notes: list[str] = Field(default_factory=list)


class WindowsEmitReviewPacketResult(BaseModel):
    packet: WindowsReviewPacket
    evidence_node_id: str | None = None


class WindowsEmitReviewPacketTool(
    MemoryTool[WindowsEmitReviewPacketArgs, WindowsEmitReviewPacketResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_emit_review_packet",
                description=(
                    "Normalize Windows source/sink/gate/path observations into a "
                    "review packet for candidate triage. This does not claim a bug."
                ),
                tags=("windows", "pe", "review", "candidate", "triage"),
            ),
            WindowsEmitReviewPacketArgs,
            WindowsEmitReviewPacketResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsEmitReviewPacketArgs,
    ) -> WindowsEmitReviewPacketResult:
        args = _with_manifest_context(ctx, kb, args)
        required_gates = _dedupe(
            [
                *args.required_gates,
                *(args.component_profile.required_gates if args.component_profile else []),
            ]
        )
        proven_gates = _proven_gates(args, required_gates)
        missing_required_gates = _missing_required_gate_semantics(
            args,
            required_gates,
            proven_gates,
        )
        provenance = _dedupe(
            args.provenance
            + _evidence_provenance(args.evidence)
            + _context_provenance(args)
        )
        required_project_facts = _required_project_facts(args)
        promotion_blockers = _promotion_blockers(
            args,
            required_project_facts,
            required_gates,
            missing_required_gates,
        )
        priority = _priority(args, required_gates)
        confidence, reason = _confidence(
            args,
            provenance,
            required_gates,
            promotion_blockers,
        )
        packet = WindowsReviewPacket(
            candidate_id=args.candidate_id or _candidate_id(args),
            binary=args.binary,
            build=args.build,
            entrypoint=args.entrypoint,
            attacker_class=args.attacker_class,
            source_role=args.source_role,
            source_arg=args.source_arg,
            sink_symbol=args.sink_symbol,
            sink_kind=args.sink_kind,
            required_gates=required_gates,
            proven_gates=proven_gates,
            gate_proof_sources=dict(args.gate_proof_sources),
            missing_required_gates=missing_required_gates,
            gate_status=args.gate_status,
            path=args.path,
            evidence=args.evidence,
            provenance=provenance,
            pdb_identity=args.pdb_identity,
            component_profile=args.component_profile,
            diff_context=args.diff_context,
            project_facts=args.project_facts,
            required_project_facts=required_project_facts,
            ghidra_delta=args.ghidra_delta,
            promotion_preconditions_met=not promotion_blockers,
            promotion_blockers=promotion_blockers,
            priority=priority,
            confidence=confidence,
            confidence_reason=reason,
            next_validation=_next_validation(args, priority, promotion_blockers),
            false_positive_questions=_false_positive_questions(args, required_gates),
            notes=[
                "review packet only; VM or dynamic validation is required before finding promotion",
                *args.notes,
            ],
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_emit_review_packet",
                    props={
                        "candidate_id": packet.candidate_id,
                        "priority": packet.priority,
                        "confidence": packet.confidence,
                        "gate_status": packet.gate_status,
                        "missing_required_gates": packet.missing_required_gates,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsEmitReviewPacketResult(
            packet=packet,
            evidence_node_id=evidence_node_id,
        )


def _candidate_id(args: WindowsEmitReviewPacketArgs) -> str:
    raw = "-".join(
        [
            args.binary,
            args.build or "unknown-build",
            args.entrypoint,
            args.source_role,
            args.sink_symbol,
        ]
    )
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-").lower()


def _evidence_provenance(evidence: list[WindowsReviewEvidence]) -> list[str]:
    out: list[str] = []
    for item in evidence:
        out.extend(item.provenance)
        if item.source:
            out.append(item.source)
    return out


def _context_provenance(args: WindowsEmitReviewPacketArgs) -> list[str]:
    provenance: list[str] = []
    if args.pdb_identity is not None:
        provenance.append("asb_pdb_identity_manifest")
        if args.pdb_identity.cache_status:
            provenance.append(f"pdb_cache_{args.pdb_identity.cache_status}")
    if args.component_profile is not None:
        provenance.append("asb_component_profile")
    if args.diff_context is not None:
        provenance.append("patch_diff_context")
    if args.project_facts is not None:
        provenance.append("asb_pe_project_facts_manifest")
    if args.ghidra_delta is not None:
        provenance.append("asb_pe_ghidra_delta_manifest")
    return provenance


def _with_manifest_context(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsEmitReviewPacketArgs,
) -> WindowsEmitReviewPacketArgs:
    if not args.auto_join_manifest_context:
        return args

    updates: dict[str, object] = {}
    if args.project_facts is None:
        project_facts = _auto_project_fact_context(ctx, kb, args)
        if project_facts is not None:
            updates["project_facts"] = project_facts
    if args.ghidra_delta is None:
        ghidra_delta = _auto_ghidra_delta_context(ctx, kb, args)
        if ghidra_delta is not None:
            updates["ghidra_delta"] = ghidra_delta
    if not updates:
        return args
    if hasattr(args, "model_copy"):
        return args.model_copy(update=updates)
    return args.copy(update=updates)


def _auto_project_fact_context(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsEmitReviewPacketArgs,
) -> WindowsProjectFactContext | None:
    target_id = _manifest_target_id(args)
    try:
        result = WindowsProjectFactManifestTool().run(
            ctx,
            kb,
            WindowsProjectFactManifestArgs(
                project_facts_path=args.project_facts_path,
                target_id=target_id,
                binary_filename=args.binary if not target_id else None,
                build_label=args.manifest_build_label,
                add_to_kb=False,
            ),
        )
    except FileNotFoundError:
        if args.project_facts_path:
            raise
        return None
    if not result.records:
        return None
    return _project_fact_context_from_record(_best_project_record(result.records, args))


def _auto_ghidra_delta_context(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsEmitReviewPacketArgs,
) -> WindowsGhidraDeltaContext | None:
    target_id = _manifest_target_id(args)
    component = args.manifest_component or args.binary
    try:
        result = WindowsGhidraDeltaManifestTool().run(
            ctx,
            kb,
            WindowsGhidraDeltaManifestArgs(
                ghidra_delta_path=args.ghidra_delta_path,
                target_id=target_id,
                component=component,
                build_label=args.manifest_build_label,
                max_records=512,
                add_to_kb=False,
            ),
        )
    except FileNotFoundError:
        if args.ghidra_delta_path:
            raise
        return None
    if not result.records:
        return None

    records = result.records
    first = records[0]
    return WindowsGhidraDeltaContext(
        target_id=target_id or first.target_id,
        component=component or first.component,
        build_label=args.manifest_build_label or first.build_label,
        blocking_fact_classes=_dedupe(
            [record.fact_class for record in records if record.blocking]
        ),
        current_capabilities=_dedupe(
            [
                capability
                for record in records
                for capability in record.current_capabilities
            ]
        ),
        missing_capabilities=_dedupe(
            [
                capability
                for record in records
                for capability in record.missing_capabilities
            ]
        ),
        notes=[
            f"{record.id}:{record.coverage_state}{':blocking' if record.blocking else ''}"
            for record in records
        ],
    )


def _manifest_target_id(args: WindowsEmitReviewPacketArgs) -> str | None:
    if args.manifest_target_id:
        return args.manifest_target_id
    if args.pdb_identity is not None and args.pdb_identity.target_id:
        return args.pdb_identity.target_id
    if args.component_profile is not None and args.component_profile.target_id:
        return args.component_profile.target_id
    return None


def _best_project_record(
    records: list[ProjectFactRecord],
    args: WindowsEmitReviewPacketArgs,
) -> ProjectFactRecord:
    if len(records) == 1:
        return records[0]
    if args.manifest_build_label:
        for record in records:
            if record.build_label == args.manifest_build_label:
                return record
    binary = args.binary.lower()
    for record in records:
        if record.binary_filename.lower() == binary:
            return record
    return records[0]


def _project_fact_context_from_record(
    record: ProjectFactRecord,
) -> WindowsProjectFactContext:
    if hasattr(record.counts, "model_dump"):
        counts = record.counts.model_dump()
    else:
        counts = record.counts.dict()
    return WindowsProjectFactContext(
        target_id=record.target_id,
        build_label=record.build_label,
        project_path=record.project_path,
        fact_coverage=record.fact_coverage,
        missing_facts=record.missing_facts,
        counts={key: int(value) for key, value in counts.items()},
    )


def _priority(
    args: WindowsEmitReviewPacketArgs,
    required_gates: list[str],
) -> CandidatePriority:
    score = 0
    attacker = args.attacker_class.lower()
    if any(token in attacker for token in ("remote", "network", "unpriv", "low", "appcontainer")):
        score += 2
    if args.sink_kind.lower() in {
        "copy",
        "write",
        "free",
        "refcount",
        "completion",
        "lock",
        "irql",
    }:
        score += 2
    if args.gate_status in {"missing", "gate_after_sink", "not_dominated"}:
        score += 2
    elif args.gate_status in {"unknown", "gate_same_line"}:
        score += 1
    if args.path:
        score += 1
    if required_gates and not args.required_gates:
        score += 1
    if len(args.path) > 3:
        score -= 1
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _confidence(
    args: WindowsEmitReviewPacketArgs,
    provenance: list[str],
    required_gates: list[str],
    promotion_blockers: list[str],
) -> tuple[float, str]:
    score = 0.2
    reasons: list[str] = ["base packet fields supplied"]
    provenance_text = " ".join(provenance).lower()
    if any(token in provenance_text for token in ("pdb", "symbol", "prototype")):
        score += 0.15
        reasons.append("symbol/type provenance present")
    if any(token in provenance_text for token in ("ir", "cfg", "decompiler", "pseudocode")):
        score += 0.15
        reasons.append("code-path evidence present")
    if "asb" in provenance_text or "metadata" in provenance_text:
        score += 0.15
        reasons.append("ASB semantic metadata present")
    if any(token in provenance_text for token in ("dynamic", "trace", "vm", "kd")):
        score += 0.2
        reasons.append("dynamic evidence present")
    if args.pdb_identity is not None:
        if (args.pdb_identity.cache_status or "").lower() == "cached":
            score += 0.1
            reasons.append("cached PDB identity context present")
        else:
            score += 0.03
            reasons.append("PDB identity context present but incomplete")
    if args.component_profile is not None:
        score += 0.1
        reasons.append("component profile context present")
    if args.diff_context is not None:
        if args.diff_context.changed_functions or args.diff_context.diff_signals:
            score += 0.1
            reasons.append("patch-diff context present")
        else:
            score += 0.03
            reasons.append("diff context present but sparse")
    if args.project_facts is not None:
        if args.project_facts.fact_coverage:
            score += 0.08
            reasons.append("project fact coverage context present")
        else:
            score += 0.03
            reasons.append("project fact context present but sparse")
    if args.ghidra_delta is not None:
        if args.ghidra_delta.blocking_fact_classes:
            score -= 0.05
            reasons.append("blocking Ghidra-parity gaps remain")
        elif args.ghidra_delta.current_capabilities:
            score += 0.03
            reasons.append("Ghidra-parity context present")
    if args.path:
        score += min(0.15, 0.05 * len(args.path))
        reasons.append("source-to-sink path supplied")
    if required_gates:
        score += 0.05
        reasons.append("expected gate semantics supplied")
    if args.gate_status == "unknown":
        score -= 0.1
        reasons.append("gate status unknown")
    if promotion_blockers:
        score -= 0.12
        reasons.append("promotion blocked by unmet project/Ghidra preconditions")
    if not args.evidence:
        score -= 0.1
        reasons.append("no atomic evidence items supplied")
    return max(0.0, min(0.95, round(score, 2))), "; ".join(reasons)


def _required_project_facts(args: WindowsEmitReviewPacketArgs) -> list[str]:
    if args.required_project_facts:
        return _dedupe(args.required_project_facts)

    required = ["function_names"]
    if args.sink_symbol or args.path:
        required.append("call_xrefs")
    if args.gate_status in {"dominated", "not_dominated"} or any(
        item.source in {"windows_cfg_gate_to_sink", "windows_project_cfg_path_query"}
        for item in args.evidence
    ):
        required.extend(["cfg", "cfg_dominance"])
    if any(
        item.source == "windows_project_branch_condition_facts"
        for item in args.evidence
    ):
        required.append("branch_conditions")
    return _dedupe(required)


def _promotion_blockers(
    args: WindowsEmitReviewPacketArgs,
    required_project_facts: list[str],
    required_gates: list[str],
    missing_required_gates: list[str],
) -> list[str]:
    blockers: list[str] = []
    facts = args.project_facts
    if facts is None:
        blockers.append("missing project fact coverage context")
    else:
        if not facts.project_path:
            blockers.append("missing .glaurung project path")
        if not facts.fact_coverage:
            blockers.append("no project fact coverage classes supplied")
        missing_required = [
            fact
            for fact in required_project_facts
            if fact not in facts.fact_coverage or fact in facts.missing_facts
        ]
        if missing_required:
            blockers.append(
                "missing required project fact coverage: "
                + ", ".join(missing_required[:6])
            )
        zero_counts = [
            fact
            for fact in required_project_facts
            if _project_fact_count(facts, fact) == 0
        ]
        if zero_counts:
            blockers.append(
                "required project fact count is zero: "
                + ", ".join(zero_counts[:6])
            )

    if args.ghidra_delta is not None and args.ghidra_delta.blocking_fact_classes:
        blockers.append(
            "blocking Ghidra-parity gaps: "
            + ", ".join(args.ghidra_delta.blocking_fact_classes[:6])
        )
    blockers.extend(
        _gate_promotion_blockers(args, required_gates, missing_required_gates)
    )

    return blockers


def _proven_gates(
    args: WindowsEmitReviewPacketArgs,
    required_gates: list[str],
) -> list[str]:
    if args.proven_gates:
        return _dedupe(args.proven_gates)
    if args.gate_status == "dominated" and not args.missing_required_gates:
        return list(required_gates)
    return []


def _missing_required_gate_semantics(
    args: WindowsEmitReviewPacketArgs,
    required_gates: list[str],
    proven_gates: list[str],
) -> list[str]:
    proven = set(proven_gates)
    explicit_missing = set(args.missing_required_gates)
    return _dedupe(
        [
            *[gate for gate in required_gates if gate not in proven],
            *[gate for gate in args.missing_required_gates if gate not in proven],
        ]
        if explicit_missing
        else [gate for gate in required_gates if gate not in proven]
    )


def _gate_promotion_blockers(
    args: WindowsEmitReviewPacketArgs,
    required_gates: list[str],
    missing_required_gates: list[str],
) -> list[str]:
    if not required_gates:
        return []
    unresolved = missing_required_gates or required_gates
    rendered = ", ".join(unresolved[:6])
    if args.gate_status == "dominated":
        if not missing_required_gates:
            return []
        return [f"required gate coverage unresolved: {rendered}"]
    if args.gate_status in {"missing", "not_dominated", "gate_after_sink"}:
        return [f"required gate semantics not proven before sink: {rendered}"]
    if args.gate_status in {"unknown", "gate_before_sink", "gate_same_line"}:
        return [f"required gate coverage unresolved: {rendered}"]
    return []


def _project_fact_count(
    facts: WindowsProjectFactContext,
    fact_class: str,
) -> int | None:
    count_keys = {
        "function_names": ("function_name_count",),
        "call_xrefs": ("call_xref_count",),
        "data_xrefs": ("data_read_xref_count", "data_write_xref_count", "xref_count"),
        "data_labels": ("data_label_count",),
        "function_prototypes": ("function_prototype_count",),
        "cfg": ("basic_block_count", "cfg_edge_count"),
        "cfg_dominance": ("cfg_dominance_count",),
        "branch_conditions": ("cfg_branch_fact_count",),
    }
    keys = count_keys.get(fact_class)
    if not keys:
        return None
    present = [facts.counts[key] for key in keys if key in facts.counts]
    if not present:
        return None
    return min(present)


def _next_validation(
    args: WindowsEmitReviewPacketArgs,
    priority: CandidatePriority,
    promotion_blockers: list[str],
) -> list[str]:
    steps = [
        "verify the source role against the function prototype or PDB type data",
        "replace line-order or pseudocode evidence with CFG dominance/path facts",
    ]
    if args.gate_status in {"missing", "gate_after_sink", "not_dominated"}:
        steps.append("trace whether any equivalent gate exists on all paths to the sink")
    elif args.gate_status in {"gate_before_sink", "gate_same_line", "unknown"}:
        steps.append("prove or reject that the observed gate dominates the sink")
    if priority == "high":
        steps.append("build a VM validation plan for the shortest reachable surface")
    if args.pdb_identity is not None and args.pdb_identity.missing_facts:
        facts = ", ".join(args.pdb_identity.missing_facts[:4])
        steps.append(f"fill missing PDB-backed facts before promotion: {facts}")
    if args.component_profile is not None:
        if args.component_profile.validation_requirements:
            reqs = ", ".join(args.component_profile.validation_requirements[:4])
            steps.append(f"satisfy component validation requirements: {reqs}")
        if args.component_profile.harness_strategy:
            steps.append(
                f"use component harness strategy: {args.component_profile.harness_strategy}"
            )
    if args.diff_context is not None:
        if args.diff_context.diff_signals:
            signals = ", ".join(args.diff_context.diff_signals[:4])
            steps.append(f"compare patch-diff signals against the candidate: {signals}")
        if args.diff_context.changed_functions:
            functions = ", ".join(args.diff_context.changed_functions[:4])
            steps.append(f"prioritize changed functions from diff context: {functions}")
    if args.project_facts is not None and args.project_facts.missing_facts:
        missing = ", ".join(args.project_facts.missing_facts[:4])
        steps.append(f"account for missing project facts before promotion: {missing}")
    if args.ghidra_delta is not None and args.ghidra_delta.blocking_fact_classes:
        gaps = ", ".join(args.ghidra_delta.blocking_fact_classes[:4])
        steps.append(f"close or explicitly caveat blocking Ghidra-parity gaps: {gaps}")
    if promotion_blockers:
        steps.append(
            "clear promotion blockers before treating this packet as more than a seed: "
            + "; ".join(promotion_blockers[:4])
        )
    return steps


def _false_positive_questions(
    args: WindowsEmitReviewPacketArgs,
    required_gates: list[str],
) -> list[str]:
    questions = [
        "Is the source value actually attacker-controlled for this build and caller class?",
        "Does the source-to-sink path require a prior privilege, mode, object, or state gate?",
        "Do the sink arguments consume the same value, or only a sanitized copy?",
        "Do all feasible paths reach the sink, or only an unreachable/error path?",
    ]
    if required_gates:
        questions.append("Does an equivalent gate exist under a different wrapper or helper name?")
    if args.pdb_identity is not None:
        if (args.pdb_identity.cache_status or "").lower() != "cached":
            questions.append("Is the PDB identity incomplete or stale for this exact binary build?")
        if args.pdb_identity.missing_facts:
            questions.append("Could missing PDB type/prototype facts change the source or sink roles?")
    if args.component_profile is not None and args.component_profile.required_gates:
        questions.append("Did the component profile add a gate expectation that this path cannot reach?")
    if args.diff_context is not None and args.diff_context.missing_functions:
        questions.append("Are seed functions absent because of renaming, inlining, or build mismatch?")
    if args.project_facts is not None and args.project_facts.missing_facts:
        questions.append("Could missing project facts hide an alternate caller, data target, or path?")
    if args.ghidra_delta is not None and args.ghidra_delta.blocking_fact_classes:
        questions.append("Does a blocking Ghidra-parity gap invalidate the packet evidence?")
    if args.sink_kind.lower() in {"copy", "write"}:
        questions.append("Are size/count units consistent between source, checks, and sink?")
    if args.sink_kind.lower() in {"free", "refcount", "completion"}:
        questions.append("Does ownership transfer or reference lifetime invalidate the apparent path?")
    return questions


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def build_tool() -> MemoryTool[
    WindowsEmitReviewPacketArgs, WindowsEmitReviewPacketResult
]:
    return WindowsEmitReviewPacketTool()
