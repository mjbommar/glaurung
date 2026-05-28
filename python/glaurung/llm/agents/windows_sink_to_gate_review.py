"""Deterministic Windows sink-to-gate review workflow."""

from __future__ import annotations

from pathlib import Path

import glaurung as g
import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.adapters import import_triage
from ..tools.windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from ..tools.windows_build_corpus import (
    WindowsBuildCorpusArgs,
    WindowsBuildCorpusTool,
    WindowsCorpusPathMatch,
)
from ..tools.windows_compose_source_gate_sink_packet import (
    WindowsComposeSourceGateSinkPacketArgs,
    WindowsComposeSourceGateSinkPacketResult,
    WindowsComposeSourceGateSinkPacketTool,
)
from ..tools.windows_emit_review_packet import WindowsReviewPacket
from ..tools.windows_project_branch_condition_facts import ProjectBranchConditionFact
from ..tools.windows_project_branch_condition_facts import (
    WindowsProjectBranchConditionFactsArgs,
    WindowsProjectBranchConditionFactsTool,
)
from ..tools.windows_project_call_argument_snapshot import (
    WindowsProjectCallArgumentSnapshotArgs,
    WindowsProjectCallArgumentSnapshotResult,
    WindowsProjectCallArgumentSnapshotTool,
)
from ..tools.windows_project_cfg_path_query import (
    WindowsProjectCfgPathQueryArgs,
    WindowsProjectCfgPathQueryResult,
    WindowsProjectCfgPathQueryTool,
)


class WindowsSinkToGateReviewConfig(BaseModel):
    packet_args: WindowsComposeSourceGateSinkPacketArgs = Field(
        ...,
        description="Concrete source/gate/sink packet-composition arguments.",
    )
    call_argument_snapshots: list[WindowsProjectCallArgumentSnapshotResult] = Field(
        default_factory=list,
        description="Optional persisted project call-argument snapshots to attach.",
    )
    cfg_path_queries: list[WindowsProjectCfgPathQueryResult] = Field(
        default_factory=list,
        description="Optional persisted project CFG path query results to attach.",
    )
    branch_conditions: list[ProjectBranchConditionFact] = Field(
        default_factory=list,
        description="Optional persisted branch-condition facts on reviewed paths.",
    )
    candidate_packet: WindowsReviewPacket | None = Field(
        None,
        description=(
            "Optional prior review packet used to inherit project/binary context "
            "for automatic project fact queries."
        ),
    )
    project_path: str | None = Field(
        None,
        description="Optional .glaurung project path for automatic project fact queries.",
    )
    binary_path: str | None = Field(
        None,
        description="Optional PE path for automatic call-argument snapshot recovery.",
    )
    build_corpus: WindowsBuildCorpusArgs | None = Field(
        None,
        description=(
            "Optional build-corpus lookup used to resolve project and binary "
            "paths when they are not supplied explicitly or by packet facts."
        ),
    )
    auto_project_facts: bool = Field(
        True,
        description=(
            "When project_path is set, invoke project CFG/branch tools, and when "
            "binary_path is also set, invoke the project call-argument tool."
        ),
    )
    max_branch_conditions: int = Field(32, ge=0, le=256)


class WindowsSinkToGateReviewResult(BaseModel):
    claim_level: str = "sink_to_gate_review_not_finding"
    packet: WindowsReviewPacket
    operand_status: str
    gate_status: str
    promotion_preconditions_met: bool
    call_argument_snapshot_count: int = 0
    cfg_path_query_count: int = 0
    branch_condition_count: int = 0
    auto_project_fact_blockers: list[str] = Field(default_factory=list)
    project_fact_blockers: list[str] = Field(default_factory=list)
    auto_project_path: str | None = None
    auto_binary_path: str | None = None
    auto_build_corpus_manifest_path: str | None = None
    auto_build_corpus_target_count: int = 0
    blockers: list[str] = Field(default_factory=list)
    tool_sequence: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


class WindowsSinkToGateReviewBatchConfig(BaseModel):
    reviews: list[WindowsSinkToGateReviewConfig] = Field(
        default_factory=list,
        description="Concrete sink-to-gate review configs to run as one bounded batch.",
    )
    candidate_packets: list[WindowsReviewPacket] = Field(
        default_factory=list,
        description=(
            "Already-emitted Windows review packets to include in the batch "
            "without retyping source/gate/sink composition args."
        ),
    )
    candidate_packets_path: str | None = Field(
        None,
        description=(
            "Optional JSON/YAML artifact containing Windows review packets. "
            "Accepts either a list or an object with candidate_packets/packets."
        ),
    )
    max_reviews: int = Field(16, ge=1, le=128)


class WindowsSinkToGateReviewBatchResult(BaseModel):
    claim_level: str = "sink_to_gate_review_batch_not_finding"
    review_count: int
    reviewed_count: int
    promotion_preconditions_met_count: int
    blocked_count: int
    results: list[WindowsSinkToGateReviewResult]
    blockers: list[str] = Field(default_factory=list)
    tool_sequence: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


def _load_candidate_packets(path_text: str | None) -> list[WindowsReviewPacket]:
    if not path_text:
        return []
    path = Path(path_text).expanduser()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if isinstance(raw, dict):
        raw = raw.get("candidate_packets", raw.get("packets", []))
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected packet list or packet artifact object")
    return [WindowsReviewPacket.model_validate(item) for item in raw]


def _review_from_candidate_packet(
    packet: WindowsReviewPacket,
) -> WindowsSinkToGateReviewResult:
    operand_status = _operand_status_from_packet(packet)
    tool_sequence = ["provided_windows_review_packet"]
    notes = [
        "Sink-to-gate review consumed a pre-emitted candidate packet.",
        "Packet evidence is static triage, not vulnerability reproduction.",
    ]
    composed = WindowsComposeSourceGateSinkPacketResult(
        packet=packet,
        operand_status=operand_status,
        gate_status=packet.gate_status,
    )
    auto_project_facts = _AutoProjectFacts(
        project_path=packet.project_facts.project_path
        if packet.project_facts is not None
        else None
    )
    return WindowsSinkToGateReviewResult(
        packet=packet,
        operand_status=operand_status,
        gate_status=packet.gate_status,
        promotion_preconditions_met=packet.promotion_preconditions_met,
        auto_project_path=auto_project_facts.project_path,
        blockers=packet.promotion_blockers,
        tool_sequence=tool_sequence,
        evidence_bundle=_evidence_bundle(
            composed,
            auto_project_facts,
            None,
            tool_sequence,
            notes,
            call_argument_snapshots=[],
            cfg_path_queries=[],
            branch_conditions=[],
            project_fact_blockers=[],
        ),
        notes=notes,
    )


def _operand_status_from_packet(packet: WindowsReviewPacket) -> str:
    if packet.source_refinement_status in {"matched", "inferred"}:
        return packet.source_refinement_status
    if packet.source_refinement_status in {"missing", "ambiguous"}:
        return f"source_{packet.source_refinement_status}"
    if packet.source_arg:
        return "packet_source_arg"
    return "not_requested"


def run_windows_sink_to_gate_review(
    config: WindowsSinkToGateReviewConfig,
) -> WindowsSinkToGateReviewResult:
    ctx = _ctx()
    composed = WindowsComposeSourceGateSinkPacketTool().run(
        ctx,
        ctx.kb,
        config.packet_args.model_copy(update={"add_to_kb": False}),
    )
    tool_sequence = [
        "windows_source_sink_operand_match",
        "windows_cfg_gate_to_sink",
        "windows_emit_review_packet",
    ]
    build_corpus = _resolve_build_corpus(ctx, config)
    if build_corpus is not None:
        tool_sequence.append("windows_build_corpus")
    if config.call_argument_snapshots:
        tool_sequence.append("provided_windows_project_call_argument_snapshot")
    if config.cfg_path_queries:
        tool_sequence.append("provided_windows_project_cfg_path_query")
    if config.branch_conditions:
        tool_sequence.append("provided_windows_project_branch_condition_facts")
    auto_project_facts = _auto_project_facts(ctx, config, composed.packet, build_corpus)
    if auto_project_facts.call_argument_snapshots:
        tool_sequence.append("auto_windows_project_call_argument_snapshot")
    if auto_project_facts.cfg_path_queries:
        tool_sequence.append("auto_windows_project_cfg_path_query")
    if auto_project_facts.branch_conditions:
        tool_sequence.append("auto_windows_project_branch_condition_facts")
    call_argument_snapshots = [
        *config.call_argument_snapshots,
        *auto_project_facts.call_argument_snapshots,
    ]
    cfg_path_queries = [*config.cfg_path_queries, *auto_project_facts.cfg_path_queries]
    branch_conditions = [
        *config.branch_conditions,
        *auto_project_facts.branch_conditions,
    ]
    notes = [
        "Sink-to-gate review is static triage, not vulnerability reproduction.",
        "Missing source equivalence, missing gate semantics, and runtime blockers stay explicit.",
    ]
    if build_corpus is not None:
        notes.extend(build_corpus.notes)
    project_fact_blockers = _dedupe(
        [
            *_project_fact_blockers(
                call_argument_snapshots=call_argument_snapshots,
                cfg_path_queries=cfg_path_queries,
            ),
            *auto_project_facts.blockers,
        ]
    )
    return WindowsSinkToGateReviewResult(
        packet=composed.packet,
        operand_status=composed.operand_status,
        gate_status=composed.gate_status,
        promotion_preconditions_met=composed.packet.promotion_preconditions_met,
        call_argument_snapshot_count=len(call_argument_snapshots),
        cfg_path_query_count=len(cfg_path_queries),
        branch_condition_count=len(branch_conditions),
        auto_project_fact_blockers=auto_project_facts.blockers,
        project_fact_blockers=project_fact_blockers,
        auto_project_path=auto_project_facts.project_path,
        auto_binary_path=auto_project_facts.binary_path,
        auto_build_corpus_manifest_path=(
            build_corpus.manifest_path if build_corpus is not None else None
        ),
        auto_build_corpus_target_count=(
            build_corpus.target_count if build_corpus is not None else 0
        ),
        blockers=_dedupe([*composed.packet.promotion_blockers, *project_fact_blockers]),
        tool_sequence=tool_sequence,
        evidence_bundle=_evidence_bundle(
            composed,
            auto_project_facts,
            build_corpus,
            tool_sequence,
            notes,
            call_argument_snapshots=call_argument_snapshots,
            cfg_path_queries=cfg_path_queries,
            branch_conditions=branch_conditions,
            project_fact_blockers=project_fact_blockers,
        ),
        notes=notes,
    )


def run_windows_sink_to_gate_review_batch(
    config: WindowsSinkToGateReviewBatchConfig,
) -> WindowsSinkToGateReviewBatchResult:
    candidate_packets = [
        *config.candidate_packets,
        *_load_candidate_packets(config.candidate_packets_path),
    ]
    review_count = len(config.reviews) + len(candidate_packets)
    if review_count == 0:
        raise ValueError("sink-to-gate batch requires at least one review config")
    selected_reviews = config.reviews[: config.max_reviews]
    remaining = max(config.max_reviews - len(selected_reviews), 0)
    selected_packets = candidate_packets[:remaining]
    results = [
        *(run_windows_sink_to_gate_review(review) for review in selected_reviews),
        *(_review_from_candidate_packet(packet) for packet in selected_packets),
    ]
    blockers = _dedupe([blocker for result in results for blocker in result.blockers])
    tool_sequence = _dedupe(
        [
            "windows_sink_to_gate_review_batch",
            *(tool for result in results for tool in result.tool_sequence),
            *(
                ["candidate_packet_artifact_loader"]
                if config.candidate_packets_path
                else []
            ),
        ]
    )
    notes = [
        "Sink-to-gate batch review is static triage, not vulnerability reproduction.",
        f"Reviewed {len(results)} of {review_count} supplied sink callsite(s).",
    ]
    if candidate_packets:
        notes.append(
            f"included {len(selected_packets)} candidate packet(s) in sink-to-gate batch."
        )
    return WindowsSinkToGateReviewBatchResult(
        review_count=review_count,
        reviewed_count=len(results),
        promotion_preconditions_met_count=sum(
            1 for result in results if result.promotion_preconditions_met
        ),
        blocked_count=sum(1 for result in results if result.blockers),
        results=results,
        blockers=blockers,
        tool_sequence=tool_sequence,
        evidence_bundle=_batch_evidence_bundle(
            results=results,
            supplied_review_count=review_count,
            tool_sequence=tool_sequence,
            blockers=blockers,
            notes=notes,
        ),
        notes=notes,
    )


class _AutoProjectFacts(BaseModel):
    project_path: str | None = None
    binary_path: str | None = None
    call_argument_snapshots: list[WindowsProjectCallArgumentSnapshotResult] = Field(
        default_factory=list
    )
    cfg_path_queries: list[WindowsProjectCfgPathQueryResult] = Field(
        default_factory=list
    )
    branch_conditions: list[ProjectBranchConditionFact] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)


class _BuildCorpusContext(BaseModel):
    manifest_path: str
    target_count: int
    target_ids: list[str] = Field(default_factory=list)
    resolved_project_path: str | None = None
    resolved_binary_path: str | None = None
    notes: list[str] = Field(default_factory=list)


def _resolve_build_corpus(
    ctx: MemoryContext,
    config: WindowsSinkToGateReviewConfig,
) -> _BuildCorpusContext | None:
    if config.build_corpus is None:
        return None
    result = WindowsBuildCorpusTool().run(
        ctx,
        ctx.kb,
        config.build_corpus.model_copy(update={"add_to_kb": False}),
    )
    corpus_matches = _path_matches(result.targets, "corpus")
    project_matches = _path_matches(result.targets, "project")
    notes = [
        f"build corpus matched {len(result.targets)} target(s) from {result.manifest_path}."
    ]
    if corpus_matches:
        notes.append(
            f"resolved binary path from build corpus: {corpus_matches[0].path}"
        )
    if project_matches:
        notes.append(
            f"resolved .glaurung project path from build corpus: {project_matches[0].path}"
        )
    return _BuildCorpusContext(
        manifest_path=result.manifest_path,
        target_count=len(result.targets),
        target_ids=[target.id for target in result.targets],
        resolved_project_path=project_matches[0].path if project_matches else None,
        resolved_binary_path=corpus_matches[0].path if corpus_matches else None,
        notes=notes,
    )


def _path_matches(targets, kind: str) -> list[WindowsCorpusPathMatch]:
    out: list[WindowsCorpusPathMatch] = []
    seen: set[str] = set()
    for target in targets:
        matches = target.corpus_matches if kind == "corpus" else target.project_matches
        for match in matches:
            if match.path in seen:
                continue
            seen.add(match.path)
            out.append(match)
    return out


def _auto_project_facts(
    ctx: MemoryContext,
    config: WindowsSinkToGateReviewConfig,
    packet: WindowsReviewPacket,
    build_corpus: _BuildCorpusContext | None,
) -> _AutoProjectFacts:
    project_path = _resolved_project_path(config, packet, build_corpus)
    binary_path = _resolved_binary_path(config, packet, build_corpus)
    if not config.auto_project_facts or not project_path:
        return _AutoProjectFacts()
    blockers: list[str] = []
    snapshots: list[WindowsProjectCallArgumentSnapshotResult] = []
    cfg_queries: list[WindowsProjectCfgPathQueryResult] = []
    branch_conditions: list[ProjectBranchConditionFact] = []
    if binary_path:
        try:
            snapshots.append(
                WindowsProjectCallArgumentSnapshotTool().run(
                    ctx,
                    ctx.kb,
                    WindowsProjectCallArgumentSnapshotArgs(
                        binary_path=binary_path,
                        project_path=project_path,
                        callsite_va=config.packet_args.sink_va,
                        add_to_kb=False,
                    ),
                )
            )
        except Exception as exc:
            blockers.append(f"project_call_argument_snapshot failed: {exc}")
    cfg_query = WindowsProjectCfgPathQueryTool().run(
        ctx,
        ctx.kb,
        WindowsProjectCfgPathQueryArgs(
            project_path=project_path,
            function_va=config.packet_args.function_va,
            gate_va=config.packet_args.gate_va,
            sink_va=config.packet_args.sink_va,
            add_to_kb=False,
        ),
    )
    cfg_queries.append(cfg_query)
    function_va = cfg_query.function_va or config.packet_args.function_va
    if function_va is None:
        blockers.append(
            "project_branch_condition_facts skipped: function_va unavailable"
        )
    else:
        path_block_ids = _dedupe(
            [
                *cfg_query.entry_to_sink_path_block_ids,
                *cfg_query.branch_to_sink_path_block_ids,
                *cfg_query.bypass_path_block_ids,
            ]
        )
        branch_result = WindowsProjectBranchConditionFactsTool().run(
            ctx,
            ctx.kb,
            WindowsProjectBranchConditionFactsArgs(
                project_path=project_path,
                function_va=function_va,
                path_block_ids=path_block_ids,
                max_rows=config.max_branch_conditions,
                add_to_kb=False,
            ),
        )
        branch_conditions.extend(branch_result.facts)
        blockers.extend(
            f"project_branch_condition_facts missing {capability}"
            for capability in branch_result.missing_capabilities
        )
    return _AutoProjectFacts(
        project_path=project_path,
        binary_path=binary_path,
        call_argument_snapshots=snapshots,
        cfg_path_queries=cfg_queries,
        branch_conditions=branch_conditions,
        blockers=_dedupe(blockers),
    )


def _resolved_project_path(
    config: WindowsSinkToGateReviewConfig,
    packet: WindowsReviewPacket,
    build_corpus: _BuildCorpusContext | None,
) -> str | None:
    if config.project_path:
        return config.project_path
    for candidate in (config.candidate_packet, packet):
        if candidate is None or candidate.project_facts is None:
            continue
        if candidate.project_facts.project_path:
            return candidate.project_facts.project_path
    if build_corpus is not None and build_corpus.resolved_project_path:
        return build_corpus.resolved_project_path
    return None


def _resolved_binary_path(
    config: WindowsSinkToGateReviewConfig,
    packet: WindowsReviewPacket,
    build_corpus: _BuildCorpusContext | None,
) -> str | None:
    if config.binary_path:
        return config.binary_path
    for candidate in (config.candidate_packet, packet):
        if candidate is None:
            continue
        if candidate.binary and _existing_path(candidate.binary):
            return candidate.binary
    if build_corpus is not None and build_corpus.resolved_binary_path:
        return build_corpus.resolved_binary_path
    return None


def _existing_path(value: str) -> bool:
    return bool(value) and Path(value).expanduser().exists()


def _project_fact_blockers(
    *,
    call_argument_snapshots: list[WindowsProjectCallArgumentSnapshotResult],
    cfg_path_queries: list[WindowsProjectCfgPathQueryResult],
) -> list[str]:
    blockers: list[str] = []
    for snapshot in call_argument_snapshots:
        blockers.extend(
            f"call_argument_snapshot missing {capability}"
            for capability in snapshot.missing_capabilities
        )
    for query in cfg_path_queries:
        blockers.extend(
            f"cfg_path_query missing {capability}"
            for capability in query.provenance
            if capability.startswith("missing:")
        )
        if query.status in {"bypass", "unknown", "unreachable"}:
            blockers.append(f"cfg_path_query status {query.status}: {query.reason}")
    if cfg_path_queries and not any(
        query.status in {"covered", "same_block"} for query in cfg_path_queries
    ):
        blockers.append("no project CFG path query proves gate coverage")
    return _dedupe(blockers)


def _evidence_bundle(
    composed: WindowsComposeSourceGateSinkPacketResult,
    auto_project_facts: _AutoProjectFacts,
    build_corpus: _BuildCorpusContext | None,
    tool_sequence: list[str],
    notes: list[str],
    *,
    call_argument_snapshots: list[WindowsProjectCallArgumentSnapshotResult],
    cfg_path_queries: list[WindowsProjectCfgPathQueryResult],
    branch_conditions: list[ProjectBranchConditionFact],
    project_fact_blockers: list[str],
) -> WindowsEvidenceBundle:
    packet = composed.packet
    fact_coverage: list[str] = []
    missing_facts: list[str] = []
    current_capabilities: list[str] = []
    missing_capabilities: list[str] = []
    stale_or_blocking: list[str] = []
    if packet.project_facts is not None:
        fact_coverage = list(packet.project_facts.fact_coverage)
        missing_facts = list(packet.project_facts.missing_facts)
    if packet.ghidra_delta is not None:
        current_capabilities = list(packet.ghidra_delta.current_capabilities)
        missing_capabilities = list(packet.ghidra_delta.missing_capabilities)
        stale_or_blocking = list(packet.ghidra_delta.blocking_fact_classes)
    fact_coverage.extend(
        [
            *("project_call_argument_snapshot" for _ in call_argument_snapshots[:1]),
            *("project_cfg_path_query" for _ in cfg_path_queries[:1]),
            *("project_branch_conditions" for _ in branch_conditions[:1]),
        ]
    )
    stale_or_blocking.extend(project_fact_blockers)
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="candidate",
            binary=packet.binary,
            build=packet.build,
            entrypoint=packet.entrypoint,
            candidate_id=packet.candidate_id,
            attributes={
                "sink_symbol": packet.sink_symbol,
                "sink_kind": packet.sink_kind,
                "operand_status": composed.operand_status,
                "gate_status": composed.gate_status,
                "call_argument_snapshot_count": len(call_argument_snapshots),
                "cfg_path_query_count": len(cfg_path_queries),
                "branch_condition_count": len(branch_conditions),
                "auto_project_path": auto_project_facts.project_path,
                "auto_binary_path": auto_project_facts.binary_path,
                "build_corpus_manifest_path": (
                    build_corpus.manifest_path if build_corpus is not None else None
                ),
                "build_corpus_target_count": (
                    build_corpus.target_count if build_corpus is not None else 0
                ),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source=item.source,
                summary=item.summary,
                provenance=item.provenance,
            )
            for item in packet.evidence[:12]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=fact_coverage,
            missing_facts=missing_facts,
            current_capabilities=current_capabilities,
            missing_capabilities=missing_capabilities,
            stale_or_blocking_facts=stale_or_blocking,
        ),
        confidence=packet.confidence,
        confidence_reason=packet.confidence_reason,
        reason_codes=[
            packet.gate_status,
            packet.source_refinement_status,
            *packet.missing_required_gates,
        ],
        blockers=_dedupe([*packet.promotion_blockers, *project_fact_blockers]),
        next_actions=packet.next_validation,
        notes=notes,
    )


def _batch_evidence_bundle(
    *,
    results: list[WindowsSinkToGateReviewResult],
    supplied_review_count: int,
    tool_sequence: list[str],
    blockers: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    candidate_ids = _dedupe([result.packet.candidate_id for result in results])
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "review_count": supplied_review_count,
                "reviewed_count": len(results),
                "blocked_count": sum(1 for result in results if result.blockers),
                "promotion_preconditions_met_count": sum(
                    1 for result in results if result.promotion_preconditions_met
                ),
                "candidate_ids": ",".join(candidate_ids),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="candidate",
                source="windows_sink_to_gate_review_batch",
                summary=(
                    f"{result.packet.candidate_id}: gate={result.gate_status} "
                    f"operand={result.operand_status}"
                ),
                confidence=result.packet.confidence,
                reason_codes=[
                    result.gate_status,
                    result.operand_status,
                    *result.packet.missing_required_gates,
                ],
                provenance=[result.packet.binary, result.packet.entrypoint],
            )
            for result in results[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=_dedupe(
                [
                    fact
                    for result in results
                    for fact in result.evidence_bundle.coverage.fact_coverage
                ]
            ),
            missing_facts=_dedupe(
                [
                    fact
                    for result in results
                    for fact in result.evidence_bundle.coverage.missing_facts
                ]
            ),
            stale_or_blocking_facts=blockers,
        ),
        blockers=blockers,
        next_actions=_dedupe(
            [
                action
                for result in results
                for action in result.evidence_bundle.next_actions
            ]
        ),
        notes=notes,
    )


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-sink-to-gate-review>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-sink-to-gate-review>")
    return ctx


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
