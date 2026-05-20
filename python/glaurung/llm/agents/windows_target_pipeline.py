"""Deterministic Windows target triage-to-review pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..tools.windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from ..tools.windows_build_corpus import WindowsBuildCorpusArgs
from .windows_evidence_review import (
    WindowsEvidenceReviewConfig,
    WindowsEvidenceReviewResult,
    run_windows_evidence_review,
)
from .windows_sink_to_gate_review import (
    WindowsSinkToGateReviewBatchConfig,
    WindowsSinkToGateReviewBatchResult,
    run_windows_sink_to_gate_review_batch,
)
from .windows_triage_worklist import (
    WindowsTriageTargetFanoutBatch,
    WindowsTriageWorklistConfig,
    WindowsTriageWorklistResult,
    run_windows_triage_worklist,
)
from .windows_validation_planning import (
    WindowsValidationBuildCorpusPacketScanConfig,
    WindowsValidationPlanningBatchConfig,
    WindowsValidationPlanningBatchResult,
    run_windows_validation_planning_batch,
)
from ..tools.windows_vulnerability_seed_packets import (
    WindowsVulnerabilitySeedPacketsArgs,
)
from ..tools.windows_operation_backlog_packets import (
    WindowsOperationBacklogPacketsArgs,
)
from ..tools.windows_patch_diff_packets import (
    WindowsPatchDiffPacketsArgs,
)
from ..tools.windows_emit_review_packet import WindowsReviewPacket


WindowsTargetPipelineBlockerKind = Literal[
    "project_cache",
    "source_gate_metadata",
    "validation_inventory",
    "harness",
    "runtime_artifact",
    "functionization",
    "symbol_similarity",
    "packet_grounding",
    "unknown",
]


class WindowsTargetPipelineBlockerWorkItem(BaseModel):
    rank: int
    kind: WindowsTargetPipelineBlockerKind
    blocker: str
    count: int
    candidate_ids: list[str] = Field(default_factory=list)
    target_ids: list[str] = Field(default_factory=list)
    stages: list[str] = Field(default_factory=list)
    severity: str = "blocking"
    required_artifact: str | None = None
    next_action: str
    reason_codes: list[str] = Field(default_factory=list)


class WindowsTargetPipelineBlockerWorklist(BaseModel):
    claim_level: str = "target_pipeline_blocker_worklist_not_finding"
    blocker_work_item_count: int
    work_items: list[WindowsTargetPipelineBlockerWorkItem]
    tool_sequence: list[str] = Field(default_factory=list)


@dataclass
class _BlockerAggregate:
    count: int = 0
    candidate_ids: list[str] = field(default_factory=list)
    target_ids: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)


class WindowsTargetPipelineConfig(BaseModel):
    build_corpus: WindowsBuildCorpusArgs
    comparison_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    )
    diagnostics_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
    )
    validation_inventory_path: str | None = None
    build_label: str | None = None
    attacker_class: str = "unknown"
    source_role: str = "unknown"
    source_arg: str | None = None
    source_arg_index: int | None = None
    infer_source_roles: bool = False
    call_symbol: str | None = None
    sink_kind: str | None = None
    sinks_path: str | None = None
    sources_path: str | None = None
    gates_path: str | None = None
    project_facts_path: str | None = None
    ghidra_delta_path: str | None = None
    vulnerability_seeds_path: str | None = None
    include_vulnerability_seeds: bool = False
    vulnerability_seed_public_id: str | None = None
    vulnerability_seed_surface: str | None = None
    vulnerability_seed_invariant_family: str | None = None
    operation_backlog_path: str | None = None
    include_operation_backlog: bool = False
    operation_backlog_required_capability: str | None = None
    operation_backlog_triage_category: str | None = None
    operation_backlog_min_callsite_count: int = Field(0, ge=0)
    patch_diff_binary_a: str | None = None
    patch_diff_binary_b: str | None = None
    patch_diff_seeds_path: str | None = None
    patch_diff_function_identity_path: str | None = None
    patch_diff_pdb_backed: bool = False
    patch_diff_max_diff_rows: int = Field(32, ge=0, le=512)
    patch_diff_max_items: int = Field(20, ge=1, le=128)
    require_project_grounding: bool = True
    require_kdnet_attach: bool = True
    refine_gates: bool = True
    attach_gate_predicates: bool = True
    max_targets: int = Field(4, ge=1, le=32)
    max_packets_per_target: int = Field(16, ge=1, le=256)
    max_candidates: int = Field(32, ge=1, le=128)
    candidate_packets_export_path: str | None = None
    evidence_operator_markdown_path: str | None = None
    evidence_export_manifest_path: str | None = None
    evidence_candidate_packets_export_path: str | None = None
    pipeline_export_manifest_path: str | None = None
    blocker_worklist_path: str | None = None


class WindowsTargetPipelineExportManifest(BaseModel):
    claim_level: str = "target_pipeline_export_manifest_not_finding"
    selected_target_count: int
    ready_fanout_count: int
    candidate_count: int
    planned_count: int
    sink_review_count: int
    evidence_review_count: int
    target_ids: list[str] = Field(default_factory=list)
    ready_target_ids: list[str] = Field(default_factory=list)
    candidate_ids: list[str] = Field(default_factory=list)
    candidate_packets_path: str | None = None
    evidence_export_manifest_path: str | None = None
    evidence_candidate_packets_path: str | None = None
    evidence_operator_markdown_path: str | None = None
    blocker_worklist_path: str | None = None
    blocker_work_item_count: int = 0
    generated_artifacts: list[str] = Field(default_factory=list)
    tool_sequence: list[str] = Field(default_factory=list)


class WindowsTargetPipelineResult(BaseModel):
    claim_level: str = "target_pipeline_not_finding"
    selected_target_count: int
    ready_fanout_count: int
    candidate_count: int
    planned_count: int
    sink_review_count: int
    evidence_review_count: int
    triage: WindowsTriageWorklistResult
    validation: WindowsValidationPlanningBatchResult
    sink_review: WindowsSinkToGateReviewBatchResult
    evidence_review: WindowsEvidenceReviewResult
    export_manifest: WindowsTargetPipelineExportManifest | None = None
    export_manifest_path: str | None = None
    blocker_worklist: list[WindowsTargetPipelineBlockerWorkItem] = Field(
        default_factory=list
    )
    blocker_work_item_count: int = 0
    blocker_worklist_path: str | None = None
    tool_sequence: list[str]
    blockers: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


def run_windows_target_pipeline(
    config: WindowsTargetPipelineConfig,
) -> WindowsTargetPipelineResult:
    triage = run_windows_triage_worklist(_triage_config(config))
    ready_fanouts = [
        fanout for fanout in triage.target_fanout_batches if fanout.status == "ready"
    ][: config.max_targets]
    if not ready_fanouts:
        raise ValueError("target pipeline requires at least one ready fanout target")
    validation = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            build_corpus_project_sink_call_packet_batches=[
                _packet_scan_config(config, fanout) for fanout in ready_fanouts
            ],
            validation_inventory_path=config.validation_inventory_path,
            build_label=config.build_label,
            require_project_grounding=config.require_project_grounding,
            require_kdnet_attach=config.require_kdnet_attach,
            candidate_packets_export_path=config.candidate_packets_export_path,
            vulnerability_seed_packets=_vulnerability_seed_packet_config(config),
            operation_backlog_packet_batches=_operation_backlog_packet_configs(
                config,
                ready_fanouts,
            ),
            patch_diff_packets=_patch_diff_packet_config(config),
            max_candidates=config.max_candidates,
        )
    )
    sink_review = run_windows_sink_to_gate_review_batch(
        WindowsSinkToGateReviewBatchConfig(
            candidate_packets=validation.candidate_packets,
            max_reviews=config.max_candidates,
        )
    )
    evidence_review = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            packets=validation.candidate_packets,
            validation_plans=[result.validation_plan for result in validation.results],
            snapshot_mappings=[
                result.snapshot_mapping for result in validation.results
            ],
            harness_templates=[
                result.harness_template for result in validation.results
            ],
            operator_markdown_path=config.evidence_operator_markdown_path,
            export_manifest_path=config.evidence_export_manifest_path,
            candidate_packets_export_path=(
                config.evidence_candidate_packets_export_path
            ),
        )
    )
    blockers = _dedupe(
        [
            *validation.blockers,
            *sink_review.blockers,
            *[
                blocker
                for item in evidence_review.review_items
                for blocker in item.blockers
            ],
        ]
    )
    tool_sequence = _dedupe(
        [
            "windows_target_pipeline",
            *triage.tool_sequence,
            *validation.tool_sequence,
            *sink_review.tool_sequence,
            *evidence_review.tool_sequence,
        ]
    )
    blocker_worklist = _blocker_worklist(
        ready_fanouts=ready_fanouts,
        validation=validation,
        sink_review=sink_review,
        evidence_review=evidence_review,
    )
    blocker_worklist_path = _write_blocker_worklist(
        config.blocker_worklist_path,
        blocker_worklist,
        tool_sequence,
    )
    if blocker_worklist_path:
        tool_sequence = _dedupe(
            [*tool_sequence, "windows_target_pipeline:write_blocker_worklist"]
        )
    notes = [
        "Target pipeline is automated triage and validation planning, not reproduction.",
        f"Executed {len(ready_fanouts)} target fanout batch(es).",
    ]
    if blocker_worklist_path:
        notes.append(f"wrote blocker worklist to {blocker_worklist_path}")
    export_manifest = _export_manifest(
        triage=triage,
        ready_fanouts=ready_fanouts,
        validation=validation,
        sink_review=sink_review,
        evidence_review=evidence_review,
        blocker_worklist_path=blocker_worklist_path,
        blocker_work_item_count=len(blocker_worklist),
        tool_sequence=tool_sequence,
    )
    export_manifest_path = _write_export_manifest(
        config.pipeline_export_manifest_path,
        export_manifest,
    )
    if export_manifest_path:
        tool_sequence = _dedupe(
            [*tool_sequence, "windows_target_pipeline:write_export_manifest"]
        )
        notes.append(f"wrote target pipeline export manifest to {export_manifest_path}")
    return WindowsTargetPipelineResult(
        selected_target_count=len(triage.target_fanout_batches),
        ready_fanout_count=len(ready_fanouts),
        candidate_count=validation.candidate_count,
        planned_count=validation.planned_count,
        sink_review_count=sink_review.reviewed_count,
        evidence_review_count=len(evidence_review.review_items),
        triage=triage,
        validation=validation,
        sink_review=sink_review,
        evidence_review=evidence_review,
        export_manifest=export_manifest,
        export_manifest_path=export_manifest_path,
        tool_sequence=tool_sequence,
        blockers=blockers,
        evidence_bundle=_evidence_bundle(
            triage=triage,
            validation=validation,
            sink_review=sink_review,
            evidence_review=evidence_review,
            export_manifest_path=export_manifest_path,
            blocker_worklist_path=blocker_worklist_path,
            blocker_work_item_count=len(blocker_worklist),
            tool_sequence=tool_sequence,
            blockers=blockers,
            notes=notes,
        ),
        blocker_worklist=blocker_worklist,
        blocker_work_item_count=len(blocker_worklist),
        blocker_worklist_path=blocker_worklist_path,
        notes=notes,
    )


def _triage_config(config: WindowsTargetPipelineConfig) -> WindowsTriageWorklistConfig:
    return WindowsTriageWorklistConfig(
        comparison_path=config.comparison_path,
        diagnostics_path=config.diagnostics_path,
        max_items=max(config.max_targets, 1),
        max_tool_rows=4,
        build_corpus=config.build_corpus,
        auto_project_from_build_corpus=False,
        auto_diff_from_build_corpus=False,
        auto_select_high_volume_targets=True,
        fanout_high_volume_target_batches=True,
        max_build_corpus_target_items=config.max_targets,
        fanout_max_packets_per_target=config.max_packets_per_target,
        fanout_attacker_class=config.attacker_class,
        fanout_source_role=config.source_role,
        fanout_infer_source_roles=config.infer_source_roles,
        fanout_refine_gates=config.refine_gates,
        fanout_attach_gate_predicates=config.attach_gate_predicates,
        sinks_path=config.sinks_path,
        sources_path=config.sources_path,
        gates_path=config.gates_path,
    )


def _packet_scan_config(
    config: WindowsTargetPipelineConfig,
    fanout: WindowsTriageTargetFanoutBatch,
) -> WindowsValidationBuildCorpusPacketScanConfig:
    return WindowsValidationBuildCorpusPacketScanConfig(
        build_corpus=WindowsBuildCorpusArgs(
            manifest_path=fanout.build_corpus_manifest_path,
            corpus_root=fanout.corpus_root,
            project_root=fanout.project_root,
            target_id=fanout.target_id,
            max_matches=1,
        ),
        build=config.build_label,
        attacker_class=config.attacker_class,
        source_role=config.source_role,
        source_arg=config.source_arg,
        source_arg_index=config.source_arg_index,
        infer_source_roles=config.infer_source_roles,
        call_symbol=config.call_symbol,
        sink_kind=config.sink_kind,
        sinks_path=config.sinks_path or fanout.sinks_path,
        sources_path=config.sources_path or fanout.sources_path,
        gates_path=config.gates_path or fanout.gates_path,
        refine_gates=config.refine_gates,
        attach_gate_predicates=config.attach_gate_predicates,
        project_facts_path=config.project_facts_path,
        ghidra_delta_path=config.ghidra_delta_path,
        manifest_target_id=fanout.target_id,
        manifest_build_label=config.build_label,
        manifest_component=fanout.binary,
        max_packets=config.max_packets_per_target,
    )


def _vulnerability_seed_packet_config(
    config: WindowsTargetPipelineConfig,
) -> WindowsVulnerabilitySeedPacketsArgs | None:
    if not config.include_vulnerability_seeds and not config.vulnerability_seeds_path:
        return None
    return WindowsVulnerabilitySeedPacketsArgs(
        seeds_path=config.vulnerability_seeds_path,
        target_id=config.build_corpus.target_id,
        component=config.build_corpus.filename,
        surface=config.vulnerability_seed_surface,
        public_id=config.vulnerability_seed_public_id,
        invariant_family=config.vulnerability_seed_invariant_family,
        build_label=config.build_label,
        auto_join_manifest_context=True,
        project_facts_path=config.project_facts_path,
        ghidra_delta_path=config.ghidra_delta_path,
        max_packets=config.max_packets_per_target,
    )


def _operation_backlog_packet_config(
    config: WindowsTargetPipelineConfig,
    fanout: WindowsTriageTargetFanoutBatch,
) -> WindowsOperationBacklogPacketsArgs | None:
    if not config.include_operation_backlog and not config.operation_backlog_path:
        return None
    return WindowsOperationBacklogPacketsArgs(
        backlog_path=config.operation_backlog_path,
        target_id=fanout.target_id,
        component=fanout.binary,
        required_capability=config.operation_backlog_required_capability,
        triage_category=config.operation_backlog_triage_category,
        min_callsite_count=config.operation_backlog_min_callsite_count,
        attacker_class=config.attacker_class,
        max_packets=config.max_packets_per_target,
    )


def _operation_backlog_packet_configs(
    config: WindowsTargetPipelineConfig,
    fanouts: list[WindowsTriageTargetFanoutBatch],
) -> list[WindowsOperationBacklogPacketsArgs]:
    out: list[WindowsOperationBacklogPacketsArgs] = []
    for fanout in fanouts:
        scan = _operation_backlog_packet_config(config, fanout)
        if scan is not None:
            out.append(scan)
    return out


def _patch_diff_packet_config(
    config: WindowsTargetPipelineConfig,
) -> WindowsPatchDiffPacketsArgs | None:
    if not config.patch_diff_binary_a and not config.patch_diff_binary_b:
        return None
    if not config.patch_diff_binary_a or not config.patch_diff_binary_b:
        raise ValueError(
            "target pipeline patch-diff packets require both "
            "patch_diff_binary_a and patch_diff_binary_b"
        )
    return WindowsPatchDiffPacketsArgs(
        binary_a=config.patch_diff_binary_a,
        binary_b=config.patch_diff_binary_b,
        seeds_path=config.patch_diff_seeds_path,
        target_id=config.build_corpus.target_id,
        component=config.build_corpus.filename,
        sinks_path=config.sinks_path,
        gates_path=config.gates_path,
        pdb_backed=config.patch_diff_pdb_backed,
        function_identity_path=config.patch_diff_function_identity_path,
        attacker_class=config.attacker_class,
        max_diff_rows=config.patch_diff_max_diff_rows,
        max_items=config.patch_diff_max_items,
        max_packets=config.max_packets_per_target,
    )


def _export_manifest(
    *,
    triage: WindowsTriageWorklistResult,
    ready_fanouts: list[WindowsTriageTargetFanoutBatch],
    validation: WindowsValidationPlanningBatchResult,
    sink_review: WindowsSinkToGateReviewBatchResult,
    evidence_review: WindowsEvidenceReviewResult,
    blocker_worklist_path: str | None,
    blocker_work_item_count: int,
    tool_sequence: list[str],
) -> WindowsTargetPipelineExportManifest:
    candidate_ids = [packet.candidate_id for packet in validation.candidate_packets]
    generated_artifacts = _dedupe(
        [
            validation.candidate_packets_export_path or "",
            evidence_review.export_manifest_path or "",
            evidence_review.candidate_packets_export_path or "",
            evidence_review.operator_validation_markdown_path or "",
            blocker_worklist_path or "",
        ]
    )
    return WindowsTargetPipelineExportManifest(
        selected_target_count=len(triage.target_fanout_batches),
        ready_fanout_count=len(ready_fanouts),
        candidate_count=validation.candidate_count,
        planned_count=validation.planned_count,
        sink_review_count=sink_review.reviewed_count,
        evidence_review_count=len(evidence_review.review_items),
        target_ids=[fanout.target_id for fanout in triage.target_fanout_batches],
        ready_target_ids=[fanout.target_id for fanout in ready_fanouts],
        candidate_ids=candidate_ids,
        candidate_packets_path=validation.candidate_packets_export_path,
        evidence_export_manifest_path=evidence_review.export_manifest_path,
        evidence_candidate_packets_path=evidence_review.candidate_packets_export_path,
        evidence_operator_markdown_path=evidence_review.operator_validation_markdown_path,
        blocker_worklist_path=blocker_worklist_path,
        blocker_work_item_count=blocker_work_item_count,
        generated_artifacts=generated_artifacts,
        tool_sequence=tool_sequence,
    )


def _write_export_manifest(
    path_text: str | None,
    manifest: WindowsTargetPipelineExportManifest,
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return str(path)


def _write_blocker_worklist(
    path_text: str | None,
    work_items: list[WindowsTargetPipelineBlockerWorkItem],
    tool_sequence: list[str],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    artifact = WindowsTargetPipelineBlockerWorklist(
        blocker_work_item_count=len(work_items),
        work_items=work_items,
        tool_sequence=tool_sequence,
    )
    path.write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return str(path)


def _evidence_bundle(
    *,
    triage: WindowsTriageWorklistResult,
    validation: WindowsValidationPlanningBatchResult,
    sink_review: WindowsSinkToGateReviewBatchResult,
    evidence_review: WindowsEvidenceReviewResult,
    export_manifest_path: str | None,
    blocker_worklist_path: str | None,
    blocker_work_item_count: int,
    tool_sequence: list[str],
    blockers: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "selected_target_count": len(triage.target_fanout_batches),
                "candidate_count": validation.candidate_count,
                "planned_count": validation.planned_count,
                "sink_review_count": sink_review.reviewed_count,
                "evidence_review_count": len(evidence_review.review_items),
                "ready_for_runtime_validation_count": (
                    validation.ready_for_runtime_validation_count
                ),
                "evidence_blocked_count": evidence_review.blocked_count,
                "export_manifest_path": export_manifest_path,
                "blocker_worklist_path": blocker_worklist_path,
                "blocker_work_item_count": blocker_work_item_count,
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_target_pipeline",
                summary=(
                    f"target pipeline planned {validation.planned_count} "
                    f"candidate(s), reviewed {sink_review.reviewed_count}, "
                    f"evidence items {len(evidence_review.review_items)}"
                ),
                reason_codes=[
                    "target_pipeline_not_finding",
                    validation.claim_level,
                    sink_review.claim_level,
                    evidence_review.claim_level,
                ],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=tool_sequence,
            stale_or_blocking_facts=blockers,
            validation_ready=validation.ready_for_runtime_validation_count
            == validation.planned_count,
        ),
        reason_codes=[
            "target_pipeline_not_finding",
            validation.claim_level,
            sink_review.claim_level,
            evidence_review.claim_level,
        ],
        blockers=blockers,
        next_actions=_dedupe(
            [
                *validation.evidence_bundle.next_actions,
                *sink_review.evidence_bundle.next_actions,
                *evidence_review.evidence_bundle.next_actions,
            ]
        ),
        notes=notes,
    )


def _blocker_worklist(
    *,
    ready_fanouts: list[WindowsTriageTargetFanoutBatch],
    validation: WindowsValidationPlanningBatchResult,
    sink_review: WindowsSinkToGateReviewBatchResult,
    evidence_review: WindowsEvidenceReviewResult,
) -> list[WindowsTargetPipelineBlockerWorkItem]:
    packets_by_candidate = {
        packet.candidate_id: packet for packet in validation.candidate_packets
    }
    target_by_binary = {fanout.binary: fanout.target_id for fanout in ready_fanouts}
    target_by_candidate = {
        candidate_id: _packet_target_id(packet, target_by_binary)
        for candidate_id, packet in packets_by_candidate.items()
    }
    aggregated: dict[tuple[WindowsTargetPipelineBlockerKind, str], _BlockerAggregate] = {}

    def add(
        blocker: str,
        *,
        stage: str,
        candidate_id: str | None,
        reason_code: str,
    ) -> None:
        for term in _blocker_terms(blocker):
            kind = _blocker_kind(term)
            key = (kind, term)
            entry = aggregated.setdefault(
                key,
                _BlockerAggregate(),
            )
            entry.count += 1
            if candidate_id:
                _append_unique(entry.candidate_ids, candidate_id)
                target_id = target_by_candidate.get(candidate_id)
                if target_id:
                    _append_unique(entry.target_ids, target_id)
            _append_unique(entry.stages, stage)
            _append_unique(entry.reason_codes, reason_code)

    for result in validation.results:
        candidate_id = result.validation_plan.candidate_id
        for blocker in result.candidate_grounding.missing_project_facts:
            add(
                blocker,
                stage="validation:grounding_missing_fact",
                candidate_id=candidate_id,
                reason_code="missing_project_fact",
            )
        for blocker in result.candidate_grounding.blockers:
            add(
                blocker,
                stage="validation:grounding_blocker",
                candidate_id=candidate_id,
                reason_code="candidate_grounding_blocker",
            )
        for blocker in result.blockers:
            add(
                blocker,
                stage="validation:blocker",
                candidate_id=candidate_id,
                reason_code="validation_blocker",
            )

    for result in sink_review.results:
        candidate_id = result.packet.candidate_id
        for blocker in result.auto_project_fact_blockers:
            add(
                blocker,
                stage="sink_to_gate:auto_project_fact",
                candidate_id=candidate_id,
                reason_code="auto_project_fact_blocker",
            )
        for blocker in result.project_fact_blockers:
            add(
                blocker,
                stage="sink_to_gate:project_fact",
                candidate_id=candidate_id,
                reason_code="project_fact_blocker",
            )
        for blocker in result.blockers:
            add(
                blocker,
                stage="sink_to_gate:blocker",
                candidate_id=candidate_id,
                reason_code="sink_to_gate_blocker",
            )

    for item in evidence_review.review_items:
        candidate_id = item.candidate_id
        for blocker in item.missing_static_facts:
            add(
                blocker,
                stage="evidence_review:missing_static_fact",
                candidate_id=candidate_id,
                reason_code="missing_static_fact",
            )
        for blocker in item.project_coverage_gaps:
            add(
                blocker,
                stage="evidence_review:project_coverage_gap",
                candidate_id=candidate_id,
                reason_code="project_coverage_gap",
            )
        for blocker in item.substrate_gaps:
            add(
                blocker,
                stage="evidence_review:substrate_gap",
                candidate_id=candidate_id,
                reason_code="substrate_gap",
            )
        for blocker in item.runtime_blockers:
            add(
                blocker,
                stage="evidence_review:runtime_blocker",
                candidate_id=candidate_id,
                reason_code="runtime_blocker",
            )
        for blocker in item.blockers:
            add(
                blocker,
                stage="evidence_review:blocker",
                candidate_id=candidate_id,
                reason_code="evidence_blocker",
            )

    ranked: list[WindowsTargetPipelineBlockerWorkItem] = []
    for (kind, blocker), entry in aggregated.items():
        ranked.append(
            WindowsTargetPipelineBlockerWorkItem(
                rank=0,
                kind=kind,
                blocker=blocker,
                count=entry.count,
                candidate_ids=list(entry.candidate_ids),
                target_ids=list(entry.target_ids),
                stages=list(entry.stages),
                required_artifact=_blocker_required_artifact(kind),
                next_action=_blocker_next_action(kind),
                reason_codes=list(entry.reason_codes),
            )
        )
    ranked.sort(
        key=lambda item: (
            -_blocker_kind_priority(item.kind),
            -item.count,
            -len(item.candidate_ids),
            item.blocker,
        )
    )
    return [
        item.model_copy(update={"rank": index})
        for index, item in enumerate(ranked, start=1)
    ]


def _blocker_terms(blocker: str) -> list[str]:
    terms: list[str] = []
    for part in blocker.replace("\n", ";").split(";"):
        stripped = part.strip()
        while True:
            prefix = _matching_blocker_prefix(stripped)
            if prefix is None:
                break
            stripped = stripped[len(prefix) :].strip()
        if stripped:
            terms.append(stripped)
    return _dedupe(terms)


def _matching_blocker_prefix(value: str) -> str | None:
    prefixes = [
        "VM validation plan has blockers:",
        "candidate snapshot mapping has blockers:",
        "candidate snapshot mapping has runtime blockers:",
        "static packet promotion blockers remain:",
    ]
    for prefix in prefixes:
        if value.startswith(prefix):
            return prefix
    return None


def _blocker_kind(blocker: str) -> WindowsTargetPipelineBlockerKind:
    lowered = blocker.lower()
    if any(token in lowered for token in ("bsim", "similarity", "symbol-server")):
        return "symbol_similarity"
    if any(
        token in lowered
        for token in (
            "functionization",
            "ghidra",
            "boundary",
            "function start",
            "scanner",
        )
    ):
        return "functionization"
    if any(
        token in lowered
        for token in (
            "harness",
            "kdnet",
            "debugger",
            "component harness",
        )
    ):
        return "harness"
    if any(
        token in lowered
        for token in (
            "inventory",
            "snapshot",
            "build number",
            "build_label",
            "candidate build",
            "validation_id",
        )
    ):
        return "validation_inventory"
    if any(
        token in lowered
        for token in (
            "runtime artifact",
            "artifact bundle",
            "missing required artifact",
            "execution_status",
        )
    ):
        return "runtime_artifact"
    if any(
        token in lowered
        for token in (
            "project or ghidra build_label",
            ".glaurung project",
            "project path",
            "project facts",
            "project fact",
            "project fact coverage context",
            "function_names",
            "call_xrefs",
            "branch_conditions",
            "cfg",
            "cfg_dominance",
            "basic_blocks",
        )
    ):
        return "project_cache"
    if any(
        token in lowered
        for token in (
            "required gate",
            "gate semantics",
            "gate coverage",
            "source refinement",
            "source_arg_roles",
            "gate_semantics",
            "operation_classification",
            "destination_range",
            "byte_count",
            "source value",
        )
    ):
        return "source_gate_metadata"
    if any(
        token in lowered
        for token in (
            "candidate packet lacks",
            "packet lacks",
            "packet grounding",
        )
    ):
        return "packet_grounding"
    return "unknown"


def _blocker_kind_priority(kind: WindowsTargetPipelineBlockerKind) -> int:
    return {
        "project_cache": 100,
        "source_gate_metadata": 95,
        "validation_inventory": 85,
        "harness": 80,
        "symbol_similarity": 70,
        "functionization": 65,
        "packet_grounding": 60,
        "runtime_artifact": 50,
        "unknown": 10,
    }[kind]


def _blocker_required_artifact(
    kind: WindowsTargetPipelineBlockerKind,
) -> str | None:
    return {
        "project_cache": ".glaurung project cache and project-fact manifest",
        "source_gate_metadata": "ASB source/gate/operation metadata",
        "validation_inventory": "Windows validation inventory snapshot/build mapping",
        "harness": "component harness recipe or KDNET/debugger precondition",
        "runtime_artifact": "runtime validation artifact bundle",
        "functionization": "Ghidra parity/functionization evidence",
        "symbol_similarity": "PDB/symbol-server/BSim identity manifest",
        "packet_grounding": "candidate packet target/build/project context",
        "unknown": None,
    }[kind]


def _blocker_next_action(kind: WindowsTargetPipelineBlockerKind) -> str:
    return {
        "project_cache": (
            "Build or refresh the .glaurung project cache and project-fact "
            "manifest coverage for affected candidates."
        ),
        "source_gate_metadata": (
            "Add or refine source/gate/operation metadata, then rerun "
            "sink-to-gate and evidence review."
        ),
        "validation_inventory": (
            "Update the validation inventory or choose a snapshot/build mapping "
            "that matches the candidate packet."
        ),
        "harness": (
            "Add a component harness recipe or satisfy KDNET/debugger "
            "preconditions before runtime validation."
        ),
        "runtime_artifact": (
            "Run the VM validation plan and import the runtime artifact bundle."
        ),
        "functionization": (
            "Inspect the boundary/functionization evidence and add scanner or "
            "notebook replay coverage before packet promotion."
        ),
        "symbol_similarity": (
            "Extract PDB/symbol-server/BSim identity data for the affected "
            "patch pair and feed it into patch-diff review."
        ),
        "packet_grounding": (
            "Join the candidate packet to target, component, build, and project "
            "facts before validation planning."
        ),
        "unknown": (
            "Review this blocker manually and add a typed blocker mapping if it recurs."
        ),
    }[kind]


def _packet_target_id(
    packet: WindowsReviewPacket,
    target_by_binary: dict[str, str],
) -> str | None:
    if packet.project_facts is not None and packet.project_facts.target_id:
        return packet.project_facts.target_id
    if packet.component_profile is not None and packet.component_profile.target_id:
        return packet.component_profile.target_id
    if packet.pdb_identity is not None and packet.pdb_identity.target_id:
        return packet.pdb_identity.target_id
    return target_by_binary.get(packet.binary)


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
