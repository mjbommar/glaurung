"""Deterministic Windows validation-planning workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

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
from ..tools.windows_emit_review_packet import WindowsReviewPacket
from ..tools.windows_emit_validation_harness_template import (
    WindowsEmitValidationHarnessTemplateArgs,
    WindowsEmitValidationHarnessTemplateTool,
    WindowsValidationHarnessTemplate,
)
from ..tools.windows_emit_vm_validation_plan import (
    WindowsEmitVmValidationPlanArgs,
    WindowsEmitVmValidationPlanTool,
    WindowsVmValidationPlan,
)
from ..tools.windows_build_corpus import (
    WindowsBuildCorpusArgs,
    WindowsBuildCorpusTool,
    WindowsCorpusPathMatch,
)
from ..tools.windows_project_sink_call_packets import (
    WindowsProjectSinkCallPacketsArgs,
    WindowsProjectSinkCallPacketsTool,
)
from ..tools.windows_vulnerability_seed_packets import (
    WindowsVulnerabilitySeedPacketsArgs,
    WindowsVulnerabilitySeedPacketsTool,
)
from ..tools.windows_operation_backlog_packets import (
    WindowsOperationBacklogPacketsArgs,
    WindowsOperationBacklogPacketsTool,
)
from ..tools.windows_patch_diff_packets import (
    WindowsPatchDiffPacketsArgs,
    WindowsPatchDiffPacketsTool,
)
from ..tools.windows_record_candidate_snapshot_mapping import (
    WindowsCandidateSnapshotMapping,
    WindowsRecordCandidateSnapshotMappingArgs,
    WindowsRecordCandidateSnapshotMappingTool,
)
from ..tools.windows_record_validation_artifact_bundle import (
    WindowsRecordValidationArtifactBundleArgs,
    WindowsRecordValidationArtifactBundleTool,
    WindowsValidationArtifact,
    WindowsValidationArtifactBundle,
    WindowsValidationExecutionStatus,
)
from ..tools.windows_validation_harness_recipe import (
    WindowsValidationHarnessRecipe,
    WindowsValidationHarnessRecipeArgs,
    WindowsValidationHarnessRecipeTool,
)


WindowsValidationWorkflowState = Literal[
    "validation_plan_not_reproduction",
    "runtime_artifact_bundle_not_finding",
    "reproduced_issue_state_requires_human_review",
]
WindowsValidationCandidateSource = Literal[
    "glaurung_project",
    "asb_validation_inventory",
    "manual_packet",
]


class WindowsValidationCandidateGrounding(BaseModel):
    source: WindowsValidationCandidateSource
    candidate_id: str
    project_path: str | None = None
    validation_inventory_path: str | None = None
    project_fact_coverage: list[str] = Field(default_factory=list)
    missing_project_facts: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)


class WindowsValidationPlanningConfig(BaseModel):
    candidate_packet: WindowsReviewPacket = Field(
        ...,
        description="Static candidate packet to hand off to runtime validation.",
    )
    validation_inventory_path: str | None = None
    validation_id: str | None = None
    build_label: str | None = None
    require_project_grounding: bool = Field(
        False,
        description=(
            "If true, block the workflow unless the candidate packet carries "
            ".glaurung project facts and a project path."
        ),
    )
    require_kdnet_attach: bool = True
    harness_recipes_path: str | None = None
    require_harness_recipe: bool = False
    surface_id: str | None = None
    trigger_kind: str | None = None
    execution_status: WindowsValidationExecutionStatus | None = Field(
        None,
        description="If supplied, record the runtime artifact bundle with this status.",
    )
    artifacts: list[WindowsValidationArtifact] = Field(default_factory=list)
    operator_notes: list[str] = Field(default_factory=list)
    hash_existing_paths: bool = False
    require_existing_paths: bool = False
    require_artifact_bundle_for_mapping: bool = False
    harness_output_dir: str | None = None


class WindowsValidationPlanningResult(BaseModel):
    claim_level: WindowsValidationWorkflowState
    workflow_state: WindowsValidationWorkflowState
    validation_plan: WindowsVmValidationPlan
    harness_recipe: WindowsValidationHarnessRecipe | None = None
    harness_template: WindowsValidationHarnessTemplate
    artifact_bundle: WindowsValidationArtifactBundle | None = None
    snapshot_mapping: WindowsCandidateSnapshotMapping
    candidate_grounding: WindowsValidationCandidateGrounding
    tool_sequence: list[str]
    blockers: list[str] = Field(default_factory=list)
    ready_for_runtime_validation: bool
    ready_for_review: bool
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


class WindowsValidationBuildCorpusPacketScanConfig(BaseModel):
    build_corpus: WindowsBuildCorpusArgs
    build: str | None = None
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
    refine_gates: bool = False
    attach_gate_predicates: bool = False
    max_gate_predicates: int = Field(4, ge=0, le=32)
    project_facts_path: str | None = None
    ghidra_delta_path: str | None = None
    manifest_target_id: str | None = None
    manifest_build_label: str | None = None
    manifest_component: str | None = None
    required_project_facts: list[str] = Field(
        default_factory=lambda: ["function_names", "call_xrefs"]
    )
    source_gate_refined_only: bool = False
    max_packets: int = Field(16, ge=0, le=256)


class WindowsValidationPlanningBatchConfig(BaseModel):
    candidate_packets: list[WindowsReviewPacket] = Field(
        default_factory=list,
        description="Candidate packets to plan in one bounded batch.",
    )
    candidate_packets_path: str | None = Field(
        None,
        description=(
            "Optional JSON/YAML artifact containing review packets emitted by "
            "project or candidate-packet tools."
        ),
    )
    evidence_export_manifest_path: str | None = Field(
        None,
        description=(
            "Optional evidence-review export manifest. When it contains a "
            "candidate_packets_path, the batch loader consumes that packet "
            "artifact as a validation-planning handoff."
        ),
    )
    candidate_packets_export_path: str | None = Field(
        None,
        description=(
            "Optional JSON artifact path where the batch writes the candidate "
            "packets it loaded or emitted for downstream review stages."
        ),
    )
    project_sink_call_packets: WindowsProjectSinkCallPacketsArgs | None = Field(
        None,
        description=(
            "Optional project sink-call packet scan to invoke before validation "
            "planning."
        ),
    )
    build_corpus_project_sink_call_packets: (
        WindowsValidationBuildCorpusPacketScanConfig | None
    ) = Field(
        None,
        description=(
            "Optional build-corpus-backed project sink-call packet scan. The "
            "manifest resolves project and binary paths before packet emission."
        ),
    )
    build_corpus_project_sink_call_packet_batches: list[
        WindowsValidationBuildCorpusPacketScanConfig
    ] = Field(
        default_factory=list,
        description=(
            "Optional list of build-corpus-backed project sink-call packet scans "
            "to execute as one validation-planning batch."
        ),
    )
    vulnerability_seed_packets: WindowsVulnerabilitySeedPacketsArgs | None = Field(
        None,
        description=(
            "Optional ASB public vulnerability-seed packet scan. This emits "
            "invariant-driven review packets beyond project sink-call inventories."
        ),
    )
    operation_backlog_packets: WindowsOperationBacklogPacketsArgs | None = Field(
        None,
        description=(
            "Optional ASB operation-classification backlog packet scan. This emits "
            "classifier-work-item review packets beyond sink-call inventories."
        ),
    )
    operation_backlog_packet_batches: list[WindowsOperationBacklogPacketsArgs] = Field(
        default_factory=list,
        description=(
            "Optional list of operation-backlog packet scans to execute as one "
            "validation-planning batch."
        ),
    )
    patch_diff_packets: WindowsPatchDiffPacketsArgs | None = Field(
        None,
        description=(
            "Optional patch-diff packet scan. This emits changed-function review "
            "packets from deterministic patch-diff review output."
        ),
    )
    validation_inventory_path: str | None = None
    validation_id: str | None = None
    build_label: str | None = None
    require_project_grounding: bool = False
    require_kdnet_attach: bool = True
    harness_recipes_path: str | None = None
    require_harness_recipe: bool = False
    surface_id: str | None = None
    trigger_kind: str | None = None
    harness_output_dir: str | None = None
    max_candidates: int = Field(16, ge=1, le=128)


class WindowsValidationPlanningBatchResult(BaseModel):
    claim_level: str = "validation_batch_not_reproduction"
    candidate_count: int
    candidate_packets: list[WindowsReviewPacket] = Field(default_factory=list)
    candidate_packets_path: str | None = None
    candidate_packets_export_path: str | None = None
    evidence_export_manifest_path: str | None = None
    loaded_candidate_packet_count: int = 0
    evidence_export_candidate_packet_count: int = 0
    project_emitted_candidate_packet_count: int = 0
    vulnerability_seed_packet_count: int = 0
    vulnerability_seed_manifest_path: str | None = None
    operation_backlog_packet_count: int = 0
    operation_backlog_batch_count: int = 0
    operation_backlog_path: str | None = None
    patch_diff_packet_count: int = 0
    project_sink_call_packets_path: str | None = None
    build_corpus_manifest_path: str | None = None
    build_corpus_target_count: int = 0
    build_corpus_project_packet_count: int = 0
    build_corpus_project_batch_count: int = 0
    build_corpus_resolved_project_path: str | None = None
    build_corpus_resolved_binary_path: str | None = None
    planned_count: int
    ready_for_runtime_validation_count: int
    ready_for_review_count: int
    blocked_count: int
    results: list[WindowsValidationPlanningResult]
    tool_sequence: list[str]
    blockers: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


class _BatchCandidateLoad(BaseModel):
    packets: list[WindowsReviewPacket] = Field(default_factory=list)
    artifact_packet_count: int = 0
    evidence_export_candidate_packet_count: int = 0
    evidence_export_manifest_path: str | None = None
    evidence_export_candidate_packets_path: str | None = None
    project_packet_count: int = 0
    vulnerability_seed_packet_count: int = 0
    vulnerability_seed_manifest_path: str | None = None
    operation_backlog_packet_count: int = 0
    operation_backlog_batch_count: int = 0
    operation_backlog_path: str | None = None
    patch_diff_packet_count: int = 0
    project_path: str | None = None
    build_corpus_manifest_path: str | None = None
    build_corpus_target_count: int = 0
    build_corpus_project_packet_count: int = 0
    build_corpus_project_batch_count: int = 0
    build_corpus_resolved_project_path: str | None = None
    build_corpus_resolved_binary_path: str | None = None


def run_windows_validation_planning(
    config: WindowsValidationPlanningConfig,
) -> WindowsValidationPlanningResult:
    ctx = _ctx()
    plan = _emit_plan(ctx, config)
    recipe = _select_recipe(ctx, config)
    artifact_bundle = _record_artifacts(ctx, config, plan)
    mapping = _record_mapping(ctx, config, plan, artifact_bundle)
    harness_template = _emit_harness_template(ctx, config, plan, mapping, recipe)
    grounding = _candidate_grounding(config)
    tool_sequence = _tool_sequence(config, artifact_bundle, recipe)
    blockers = _blockers(
        config, plan, mapping, harness_template, artifact_bundle, recipe, grounding
    )
    state = _workflow_state(artifact_bundle)
    notes = _notes(config, recipe, artifact_bundle, state)
    return WindowsValidationPlanningResult(
        claim_level=state,
        workflow_state=state,
        validation_plan=plan,
        harness_recipe=recipe,
        harness_template=harness_template,
        artifact_bundle=artifact_bundle,
        snapshot_mapping=mapping,
        candidate_grounding=grounding,
        tool_sequence=tool_sequence,
        blockers=blockers,
        ready_for_runtime_validation=mapping.ready_for_runtime_validation,
        ready_for_review=artifact_bundle.ready_for_review
        if artifact_bundle is not None
        else False,
        evidence_bundle=_evidence_bundle(
            config=config,
            plan=plan,
            mapping=mapping,
            harness_template=harness_template,
            artifact_bundle=artifact_bundle,
            grounding=grounding,
            tool_sequence=tool_sequence,
            blockers=blockers,
            notes=notes,
        ),
        notes=notes,
    )


def run_windows_validation_planning_batch(
    config: WindowsValidationPlanningBatchConfig,
) -> WindowsValidationPlanningBatchResult:
    ctx = _ctx()
    loaded = _load_batch_candidate_packets(ctx, config)
    candidate_packets = loaded.packets
    if not candidate_packets:
        raise ValueError(
            "validation planning batch requires at least one candidate packet"
        )
    candidate_packets_export_path = _write_candidate_packets_export(
        config.candidate_packets_export_path,
        candidate_packets,
    )
    effective_config = config.model_copy(
        update={"candidate_packets": candidate_packets}
    )
    packets = candidate_packets[: effective_config.max_candidates]
    results = [
        run_windows_validation_planning(
            WindowsValidationPlanningConfig(
                candidate_packet=packet,
                validation_inventory_path=effective_config.validation_inventory_path,
                validation_id=effective_config.validation_id,
                build_label=effective_config.build_label,
                require_project_grounding=effective_config.require_project_grounding,
                require_kdnet_attach=effective_config.require_kdnet_attach,
                harness_recipes_path=effective_config.harness_recipes_path,
                require_harness_recipe=effective_config.require_harness_recipe,
                surface_id=effective_config.surface_id,
                trigger_kind=effective_config.trigger_kind,
                harness_output_dir=effective_config.harness_output_dir,
            )
        )
        for packet in packets
    ]
    tool_sequence = _dedupe(
        [
            "windows_validation_planning_batch",
            *(
                ["candidate_packet_artifact_loader"]
                if effective_config.candidate_packets_path
                else []
            ),
            *(
                ["windows_validation_planning_batch:write_candidate_packets"]
                if candidate_packets_export_path
                else []
            ),
            *(
                [
                    "evidence_export_manifest_loader",
                    "evidence_export_candidate_packet_loader",
                ]
                if effective_config.evidence_export_manifest_path
                else []
            ),
            *(
                ["windows_project_sink_call_packets"]
                if effective_config.project_sink_call_packets is not None
                else []
            ),
            *(
                [
                    "windows_build_corpus:project_sink_call_packets",
                    "windows_project_sink_call_packets",
                ]
                if effective_config.build_corpus_project_sink_call_packets is not None
                or effective_config.build_corpus_project_sink_call_packet_batches
                else []
            ),
            *(
                ["windows_vulnerability_seed_packets"]
                if effective_config.vulnerability_seed_packets is not None
                else []
            ),
            *(
                ["windows_operation_backlog_packets"]
                if effective_config.operation_backlog_packets is not None
                or effective_config.operation_backlog_packet_batches
                else []
            ),
            *(
                ["windows_patch_diff_packets"]
                if effective_config.patch_diff_packets is not None
                else []
            ),
            *(tool for result in results for tool in result.tool_sequence),
        ]
    )
    blockers = _dedupe([blocker for result in results for blocker in result.blockers])
    notes = [
        "Batch validation planning emits runtime handoffs only; it is not reproduction.",
        f"Processed {len(results)} of {len(candidate_packets)} candidate packet(s).",
    ]
    if effective_config.candidate_packets_path:
        notes.append(
            f"loaded candidate packets from {effective_config.candidate_packets_path}"
        )
    if candidate_packets_export_path:
        notes.append(f"wrote candidate packets to {candidate_packets_export_path}")
    if loaded.evidence_export_manifest_path:
        notes.append(
            "loaded evidence-review export manifest from "
            f"{loaded.evidence_export_manifest_path}"
        )
    if loaded.project_path:
        notes.append(f"loaded project sink-call packets from {loaded.project_path}")
    if loaded.vulnerability_seed_manifest_path:
        notes.append(
            "loaded vulnerability-seed packets from "
            f"{loaded.vulnerability_seed_manifest_path}"
        )
    if loaded.operation_backlog_path:
        notes.append(
            "loaded operation-backlog packets from "
            f"{loaded.operation_backlog_path}"
        )
    if loaded.patch_diff_packet_count:
        notes.append(
            f"loaded {loaded.patch_diff_packet_count} patch-diff packet(s)"
        )
    if loaded.build_corpus_manifest_path:
        notes.append(
            "loaded build-corpus project sink-call packets from "
            f"{loaded.build_corpus_manifest_path}"
        )
    return WindowsValidationPlanningBatchResult(
        candidate_count=len(candidate_packets),
        candidate_packets=candidate_packets,
        candidate_packets_path=effective_config.candidate_packets_path,
        candidate_packets_export_path=candidate_packets_export_path,
        evidence_export_manifest_path=loaded.evidence_export_manifest_path,
        loaded_candidate_packet_count=loaded.artifact_packet_count,
        evidence_export_candidate_packet_count=(
            loaded.evidence_export_candidate_packet_count
        ),
        project_emitted_candidate_packet_count=loaded.project_packet_count,
        vulnerability_seed_packet_count=loaded.vulnerability_seed_packet_count,
        vulnerability_seed_manifest_path=loaded.vulnerability_seed_manifest_path,
        operation_backlog_packet_count=loaded.operation_backlog_packet_count,
        operation_backlog_batch_count=loaded.operation_backlog_batch_count,
        operation_backlog_path=loaded.operation_backlog_path,
        patch_diff_packet_count=loaded.patch_diff_packet_count,
        project_sink_call_packets_path=loaded.project_path,
        build_corpus_manifest_path=loaded.build_corpus_manifest_path,
        build_corpus_target_count=loaded.build_corpus_target_count,
        build_corpus_project_packet_count=loaded.build_corpus_project_packet_count,
        build_corpus_project_batch_count=loaded.build_corpus_project_batch_count,
        build_corpus_resolved_project_path=loaded.build_corpus_resolved_project_path,
        build_corpus_resolved_binary_path=loaded.build_corpus_resolved_binary_path,
        planned_count=len(results),
        ready_for_runtime_validation_count=sum(
            1 for result in results if result.ready_for_runtime_validation
        ),
        ready_for_review_count=sum(1 for result in results if result.ready_for_review),
        blocked_count=sum(1 for result in results if result.blockers),
        results=results,
        tool_sequence=tool_sequence,
        blockers=blockers,
        evidence_bundle=_batch_evidence_bundle(
            config=effective_config,
            loaded=loaded,
            results=results,
            tool_sequence=tool_sequence,
            blockers=blockers,
            notes=notes,
        ),
        notes=notes,
    )


def _load_batch_candidate_packets(
    ctx: MemoryContext,
    config: WindowsValidationPlanningBatchConfig,
) -> _BatchCandidateLoad:
    packets = list(config.candidate_packets)
    artifact_packet_count = 0
    evidence_export_candidate_packet_count = 0
    evidence_export_manifest_path = None
    evidence_export_candidate_packets_path = None
    project_packet_count = 0
    vulnerability_seed_packet_count = 0
    vulnerability_seed_manifest_path = None
    operation_backlog_packet_count = 0
    operation_backlog_batch_count = 0
    operation_backlog_path = None
    patch_diff_packet_count = 0
    project_path = None
    build_corpus_manifest_path = None
    build_corpus_target_count = 0
    build_corpus_project_packet_count = 0
    build_corpus_project_batch_count = 0
    build_corpus_resolved_project_path = None
    build_corpus_resolved_binary_path = None
    if config.project_sink_call_packets is not None:
        result = WindowsProjectSinkCallPacketsTool().run(
            ctx,
            ctx.kb,
            config.project_sink_call_packets.model_copy(update={"add_to_kb": False}),
        )
        packets.extend(result.packets)
        project_packet_count = len(result.packets)
        project_path = result.project_path
    build_corpus_packet_scans = [
        *(
            [config.build_corpus_project_sink_call_packets]
            if config.build_corpus_project_sink_call_packets is not None
            else []
        ),
        *config.build_corpus_project_sink_call_packet_batches,
    ]
    for scan in build_corpus_packet_scans:
        build_result = _load_build_corpus_project_packets(
            ctx,
            scan,
        )
        packets.extend(build_result.packets)
        project_packet_count += build_result.project_packet_count
        build_corpus_project_packet_count += build_result.project_packet_count
        build_corpus_project_batch_count += 1
        build_corpus_manifest_path = (
            build_corpus_manifest_path or build_result.build_corpus_manifest_path
        )
        build_corpus_target_count += build_result.build_corpus_target_count
        build_corpus_resolved_project_path = build_corpus_resolved_project_path or (
            build_result.build_corpus_resolved_project_path
        )
        build_corpus_resolved_binary_path = build_corpus_resolved_binary_path or (
            build_result.build_corpus_resolved_binary_path
        )
        project_path = project_path or build_result.project_path
    if config.vulnerability_seed_packets is not None:
        result = WindowsVulnerabilitySeedPacketsTool().run(
            ctx,
            ctx.kb,
            config.vulnerability_seed_packets.model_copy(update={"add_to_kb": False}),
        )
        packets.extend(result.packets)
        vulnerability_seed_packet_count = len(result.packets)
        vulnerability_seed_manifest_path = result.seeds_path
    operation_backlog_scans = [
        *(
            [config.operation_backlog_packets]
            if config.operation_backlog_packets is not None
            else []
        ),
        *config.operation_backlog_packet_batches,
    ]
    for scan in operation_backlog_scans:
        result = WindowsOperationBacklogPacketsTool().run(
            ctx,
            ctx.kb,
            scan.model_copy(update={"add_to_kb": False}),
        )
        packets.extend(result.packets)
        operation_backlog_packet_count += len(result.packets)
        operation_backlog_batch_count += 1
        operation_backlog_path = operation_backlog_path or result.backlog_path
    if config.patch_diff_packets is not None:
        result = WindowsPatchDiffPacketsTool().run(
            ctx,
            ctx.kb,
            config.patch_diff_packets.model_copy(update={"add_to_kb": False}),
        )
        packets.extend(result.packets)
        patch_diff_packet_count = len(result.packets)
    if config.candidate_packets_path:
        path = Path(config.candidate_packets_path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        artifact_packets = _packets_from_raw(raw, path)
        packets.extend(artifact_packets)
        artifact_packet_count = len(artifact_packets)
    if config.evidence_export_manifest_path:
        manifest_path = Path(config.evidence_export_manifest_path)
        export_packets_path, export_packets = _load_export_manifest_packets(
            manifest_path
        )
        packets.extend(export_packets)
        evidence_export_manifest_path = str(manifest_path)
        evidence_export_candidate_packets_path = str(export_packets_path)
        evidence_export_candidate_packet_count = len(export_packets)
        artifact_packet_count += len(export_packets)
    return _BatchCandidateLoad(
        packets=packets,
        artifact_packet_count=artifact_packet_count,
        evidence_export_candidate_packet_count=evidence_export_candidate_packet_count,
        evidence_export_manifest_path=evidence_export_manifest_path,
        evidence_export_candidate_packets_path=evidence_export_candidate_packets_path,
        project_packet_count=project_packet_count,
        vulnerability_seed_packet_count=vulnerability_seed_packet_count,
        vulnerability_seed_manifest_path=vulnerability_seed_manifest_path,
        operation_backlog_packet_count=operation_backlog_packet_count,
        operation_backlog_batch_count=operation_backlog_batch_count,
        operation_backlog_path=operation_backlog_path,
        patch_diff_packet_count=patch_diff_packet_count,
        project_path=project_path,
        build_corpus_manifest_path=build_corpus_manifest_path,
        build_corpus_target_count=build_corpus_target_count,
        build_corpus_project_packet_count=build_corpus_project_packet_count,
        build_corpus_project_batch_count=build_corpus_project_batch_count,
        build_corpus_resolved_project_path=build_corpus_resolved_project_path,
        build_corpus_resolved_binary_path=build_corpus_resolved_binary_path,
    )


def _write_candidate_packets_export(
    path_text: str | None,
    packets: list[WindowsReviewPacket],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "claim_level": "validation_candidate_packet_export_not_finding",
        "candidate_count": len(packets),
        "candidate_packets": [packet.model_dump(mode="json") for packet in packets],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return str(path)


def _load_export_manifest_packets(
    manifest_path: Path,
) -> tuple[Path, list[WindowsReviewPacket]]:
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{manifest_path}: expected evidence export manifest object")
    packets_path_text = raw.get("candidate_packets_path")
    if not isinstance(packets_path_text, str) or not packets_path_text:
        raise ValueError(f"{manifest_path}: missing candidate_packets_path")
    packets_path = Path(packets_path_text).expanduser()
    if not packets_path.is_absolute():
        packets_path = manifest_path.parent / packets_path
    packets_raw = yaml.safe_load(packets_path.read_text(encoding="utf-8")) or []
    return packets_path, _packets_from_raw(packets_raw, packets_path)


def _load_build_corpus_project_packets(
    ctx: MemoryContext,
    scan: WindowsValidationBuildCorpusPacketScanConfig,
) -> _BatchCandidateLoad:
    corpus = WindowsBuildCorpusTool().run(
        ctx,
        ctx.kb,
        scan.build_corpus.model_copy(update={"add_to_kb": False}),
    )
    target = corpus.targets[0] if corpus.targets else None
    project_matches = _path_matches(corpus.targets, "project")
    corpus_matches = _path_matches(corpus.targets, "corpus")
    project_path = project_matches[0].path if project_matches else None
    binary_path = corpus_matches[0].path if corpus_matches else None
    if target is None or project_path is None:
        return _BatchCandidateLoad(
            build_corpus_manifest_path=corpus.manifest_path,
            build_corpus_target_count=len(corpus.targets),
            build_corpus_resolved_project_path=project_path,
            build_corpus_resolved_binary_path=binary_path,
        )
    result = WindowsProjectSinkCallPacketsTool().run(
        ctx,
        ctx.kb,
        WindowsProjectSinkCallPacketsArgs(
            project_path=project_path,
            binary_path=binary_path,
            binary=target.filename,
            build=scan.build,
            attacker_class=scan.attacker_class,
            source_role=scan.source_role,
            source_arg=scan.source_arg,
            source_arg_index=scan.source_arg_index,
            infer_source_roles=scan.infer_source_roles,
            call_symbol=scan.call_symbol,
            sink_kind=scan.sink_kind,
            sinks_path=scan.sinks_path,
            sources_path=scan.sources_path,
            gates_path=scan.gates_path,
            refine_gates=scan.refine_gates,
            attach_gate_predicates=scan.attach_gate_predicates,
            max_gate_predicates=scan.max_gate_predicates,
            project_facts_path=scan.project_facts_path,
            ghidra_delta_path=scan.ghidra_delta_path,
            manifest_target_id=scan.manifest_target_id or target.id,
            manifest_build_label=scan.manifest_build_label,
            manifest_component=scan.manifest_component or target.filename,
            required_project_facts=scan.required_project_facts,
            source_gate_refined_only=scan.source_gate_refined_only,
            max_packets=scan.max_packets,
            add_to_kb=False,
        ),
    )
    return _BatchCandidateLoad(
        packets=result.packets,
        project_packet_count=len(result.packets),
        project_path=result.project_path,
        build_corpus_manifest_path=corpus.manifest_path,
        build_corpus_target_count=len(corpus.targets),
        build_corpus_project_packet_count=len(result.packets),
        build_corpus_resolved_project_path=project_path,
        build_corpus_resolved_binary_path=binary_path,
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


def _packets_from_raw(raw: Any, path: Path) -> list[WindowsReviewPacket]:
    if isinstance(raw, dict):
        data: dict[str, Any] = {str(key): value for key, value in raw.items()}
        for key in ("packets", "candidate_packets", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return _packets_from_raw_list(value, path)
        if isinstance(data.get("packet"), dict):
            return [WindowsReviewPacket.model_validate(data["packet"])]
        return [WindowsReviewPacket.model_validate(data)]
    if isinstance(raw, list):
        return _packets_from_raw_list(raw, path)
    raise ValueError(f"{path}: expected packet list or object")


def _packets_from_raw_list(raw: list[Any], path: Path) -> list[WindowsReviewPacket]:
    packets: list[WindowsReviewPacket] = []
    for idx, entry in enumerate(raw):
        if isinstance(entry, dict) and isinstance(entry.get("packet"), dict):
            packets.append(WindowsReviewPacket.model_validate(entry["packet"]))
        elif isinstance(entry, dict):
            packets.append(WindowsReviewPacket.model_validate(entry))
        else:
            raise ValueError(f"{path}: packet entry {idx} is not a mapping")
    return packets


def _emit_plan(
    ctx: MemoryContext,
    config: WindowsValidationPlanningConfig,
) -> WindowsVmValidationPlan:
    result = WindowsEmitVmValidationPlanTool().run(
        ctx,
        ctx.kb,
        WindowsEmitVmValidationPlanArgs(
            candidate_packet=config.candidate_packet,
            validation_inventory_path=config.validation_inventory_path,
            validation_id=config.validation_id,
            build_label=config.build_label,
            require_kdnet_attach=config.require_kdnet_attach,
            add_to_kb=False,
        ),
    )
    return result.plan


def _select_recipe(
    ctx: MemoryContext,
    config: WindowsValidationPlanningConfig,
) -> WindowsValidationHarnessRecipe | None:
    if not config.harness_recipes_path:
        return None
    packet = config.candidate_packet
    result = WindowsValidationHarnessRecipeTool().run(
        ctx,
        ctx.kb,
        WindowsValidationHarnessRecipeArgs(
            recipes_path=config.harness_recipes_path,
            profile_id=(
                packet.component_profile.profile_id
                if packet.component_profile is not None
                else None
            ),
            target_id=_target_id(packet),
            component=_component(packet),
            surface_id=config.surface_id,
            trigger_kind=config.trigger_kind,
            add_to_kb=False,
        ),
    )
    if result.recipes:
        return result.recipes[0]
    return None


def _record_artifacts(
    ctx: MemoryContext,
    config: WindowsValidationPlanningConfig,
    plan: WindowsVmValidationPlan,
) -> WindowsValidationArtifactBundle | None:
    if config.execution_status is None:
        return None
    result = WindowsRecordValidationArtifactBundleTool().run(
        ctx,
        ctx.kb,
        WindowsRecordValidationArtifactBundleArgs(
            candidate_id=config.candidate_packet.candidate_id,
            validation_plan=plan,
            execution_status=config.execution_status,
            artifacts=config.artifacts,
            operator_notes=config.operator_notes,
            hash_existing_paths=config.hash_existing_paths,
            require_existing_paths=config.require_existing_paths,
            add_to_kb=False,
        ),
    )
    return result.bundle


def _record_mapping(
    ctx: MemoryContext,
    config: WindowsValidationPlanningConfig,
    plan: WindowsVmValidationPlan,
    artifact_bundle: WindowsValidationArtifactBundle | None,
) -> WindowsCandidateSnapshotMapping:
    result = WindowsRecordCandidateSnapshotMappingTool().run(
        ctx,
        ctx.kb,
        WindowsRecordCandidateSnapshotMappingArgs(
            candidate_packet=config.candidate_packet,
            validation_plan=plan,
            artifact_bundle=artifact_bundle,
            validation_inventory_path=config.validation_inventory_path,
            require_artifact_bundle=config.require_artifact_bundle_for_mapping,
            add_to_kb=False,
        ),
    )
    return result.mapping


def _emit_harness_template(
    ctx: MemoryContext,
    config: WindowsValidationPlanningConfig,
    plan: WindowsVmValidationPlan,
    mapping: WindowsCandidateSnapshotMapping,
    recipe: WindowsValidationHarnessRecipe | None,
) -> WindowsValidationHarnessTemplate:
    result = WindowsEmitValidationHarnessTemplateTool().run(
        ctx,
        ctx.kb,
        WindowsEmitValidationHarnessTemplateArgs(
            candidate_packet=config.candidate_packet,
            validation_plan=plan,
            snapshot_mapping=mapping,
            harness_recipe=recipe,
            output_dir=config.harness_output_dir,
            add_to_kb=False,
        ),
    )
    return result.template


def _workflow_state(
    artifact_bundle: WindowsValidationArtifactBundle | None,
) -> WindowsValidationWorkflowState:
    if artifact_bundle is None:
        return "validation_plan_not_reproduction"
    if (
        artifact_bundle.execution_status == "crash_observed"
        and artifact_bundle.ready_for_review
    ):
        return "reproduced_issue_state_requires_human_review"
    return "runtime_artifact_bundle_not_finding"


def _evidence_claim_level(
    artifact_bundle: WindowsValidationArtifactBundle | None,
) -> Literal["validation_plan_not_reproduction", "runtime_artifact_bundle_not_finding"]:
    if artifact_bundle is None:
        return "validation_plan_not_reproduction"
    return "runtime_artifact_bundle_not_finding"


def _tool_sequence(
    config: WindowsValidationPlanningConfig,
    artifact_bundle: WindowsValidationArtifactBundle | None,
    recipe: WindowsValidationHarnessRecipe | None,
) -> list[str]:
    sequence = ["windows_emit_vm_validation_plan"]
    if config.harness_recipes_path:
        sequence.append("windows_validation_harness_recipe")
    if artifact_bundle is not None:
        sequence.append("windows_record_validation_artifact_bundle")
    sequence.extend(
        [
            "windows_record_candidate_snapshot_mapping",
            "windows_emit_validation_harness_template",
        ]
    )
    if config.require_harness_recipe and recipe is None:
        sequence.append("harness_recipe_missing_blocker")
    sequence.append("candidate_packet_grounding_check")
    return sequence


def _blockers(
    config: WindowsValidationPlanningConfig,
    plan: WindowsVmValidationPlan,
    mapping: WindowsCandidateSnapshotMapping,
    harness_template: WindowsValidationHarnessTemplate,
    artifact_bundle: WindowsValidationArtifactBundle | None,
    recipe: WindowsValidationHarnessRecipe | None,
    grounding: WindowsValidationCandidateGrounding,
) -> list[str]:
    blockers: list[str] = []
    blockers.extend(plan.blockers)
    blockers.extend(mapping.mapping_blockers)
    blockers.extend(mapping.runtime_blockers)
    blockers.extend(harness_template.blockers)
    if artifact_bundle is not None:
        blockers.extend(artifact_bundle.runtime_blockers)
    if config.require_harness_recipe and recipe is None:
        blockers.append("component harness recipe is required but no recipe matched")
    blockers.extend(grounding.blockers)
    return _dedupe(blockers)


def _candidate_grounding(
    config: WindowsValidationPlanningConfig,
) -> WindowsValidationCandidateGrounding:
    packet = config.candidate_packet
    project_facts = packet.project_facts
    source: WindowsValidationCandidateSource
    if project_facts is not None and project_facts.project_path:
        source = "glaurung_project"
    elif config.validation_inventory_path:
        source = "asb_validation_inventory"
    else:
        source = "manual_packet"
    coverage = list(project_facts.fact_coverage) if project_facts is not None else []
    missing = _missing_facts(packet)
    blockers: list[str] = []
    if config.require_project_grounding:
        if project_facts is None:
            blockers.append("candidate packet lacks .glaurung project facts")
        elif not project_facts.project_path:
            blockers.append("candidate packet lacks .glaurung project path")
    return WindowsValidationCandidateGrounding(
        source=source,
        candidate_id=packet.candidate_id,
        project_path=project_facts.project_path if project_facts is not None else None,
        validation_inventory_path=config.validation_inventory_path,
        project_fact_coverage=coverage,
        missing_project_facts=missing,
        blockers=_dedupe(blockers),
    )


def _evidence_bundle(
    *,
    config: WindowsValidationPlanningConfig,
    plan: WindowsVmValidationPlan,
    mapping: WindowsCandidateSnapshotMapping,
    harness_template: WindowsValidationHarnessTemplate,
    artifact_bundle: WindowsValidationArtifactBundle | None,
    grounding: WindowsValidationCandidateGrounding,
    tool_sequence: list[str],
    blockers: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    refs = [
        evidence_ref(
            kind="validation",
            source="windows_validation_planning",
            summary=(
                f"snapshot {plan.snapshot_name} selected with KDNET "
                f"{plan.kdnet_status} and debugger {plan.debugger_status}"
            ),
            provenance=[plan.image_path, plan.ovmf_vars_path],
            reason_codes=[plan.validation_id, plan.build_label],
        ),
        evidence_ref(
            kind="tool_result",
            source="windows_validation_planning",
            summary=(
                "snapshot mapping "
                f"{mapping.mapping_confidence}; runtime ready="
                f"{mapping.ready_for_runtime_validation}"
            ),
            provenance=[mapping.snapshot_name, mapping.image_path],
            reason_codes=[mapping.mapping_confidence],
        ),
        evidence_ref(
            kind="artifact",
            source="windows_validation_planning",
            summary=(
                f"harness template {harness_template.harness_id}; "
                f"ready={harness_template.ready_to_collect_artifacts}"
            ),
            provenance=harness_template.output_files,
            reason_codes=harness_template.blockers,
        ),
    ]
    if artifact_bundle is not None:
        refs.append(
            evidence_ref(
                kind="artifact",
                source="windows_validation_planning",
                summary=(
                    f"runtime bundle {artifact_bundle.execution_status}; "
                    f"artifacts={artifact_bundle.artifact_count}"
                ),
                provenance=[
                    artifact.path for artifact in artifact_bundle.artifacts[:8]
                ],
                reason_codes=artifact_bundle.runtime_blockers,
            )
        )
    return make_windows_evidence_bundle(
        claim_level=_evidence_claim_level(artifact_bundle),
        subject=WindowsEvidenceSubject(
            kind="validation_plan",
            binary=plan.binary,
            build=plan.build,
            candidate_id=plan.candidate_id,
            validation_id=plan.validation_id,
            attributes={
                "snapshot_name": plan.snapshot_name,
                "workflow_state": _workflow_state(artifact_bundle),
                "ready_for_runtime_validation": mapping.ready_for_runtime_validation,
                "ready_for_review": (
                    artifact_bundle.ready_for_review
                    if artifact_bundle is not None
                    else False
                ),
                "candidate_grounding_source": grounding.source,
                "candidate_project_path": grounding.project_path,
                "validation_inventory_path": grounding.validation_inventory_path,
            },
        ),
        source_tools=[tool for tool in tool_sequence if not tool.endswith("_blocker")],
        tool_sequence=tool_sequence,
        evidence_refs=refs,
        coverage=WindowsEvidenceCoverage(
            fact_coverage=_dedupe(
                [
                    *config.candidate_packet.required_project_facts,
                    *grounding.project_fact_coverage,
                    f"candidate_grounding:{grounding.source}",
                ]
            ),
            missing_facts=_dedupe(
                [*grounding.missing_project_facts, *grounding.blockers]
            ),
            validation_status=(
                artifact_bundle.execution_status
                if artifact_bundle is not None
                else plan.kdnet_status
            ),
            validation_ready=mapping.ready_for_runtime_validation,
            runtime_artifact_count=(
                artifact_bundle.artifact_count if artifact_bundle is not None else 0
            ),
            stale_or_blocking_facts=blockers,
        ),
        reason_codes=[
            _workflow_state(artifact_bundle),
            mapping.mapping_confidence,
            *harness_template.blockers,
        ],
        blockers=blockers,
        next_actions=_next_actions(plan, harness_template, artifact_bundle),
        notes=notes,
    )


def _batch_evidence_bundle(
    *,
    config: WindowsValidationPlanningBatchConfig,
    loaded: _BatchCandidateLoad,
    results: list[WindowsValidationPlanningResult],
    tool_sequence: list[str],
    blockers: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="validation_plan_not_reproduction",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "candidate_count": len(config.candidate_packets),
                "planned_count": len(results),
                "ready_for_runtime_validation_count": sum(
                    1 for result in results if result.ready_for_runtime_validation
                ),
                "blocked_count": sum(1 for result in results if result.blockers),
                "validation_inventory_path": config.validation_inventory_path,
                "candidate_packets_path": config.candidate_packets_path,
                "candidate_packets_export_path": config.candidate_packets_export_path,
                "evidence_export_manifest_path": config.evidence_export_manifest_path,
                "evidence_export_candidate_packets_path": (
                    loaded.evidence_export_candidate_packets_path
                ),
                "evidence_export_candidate_packet_count": (
                    loaded.evidence_export_candidate_packet_count
                ),
                "project_sink_call_packets_path": (
                    config.project_sink_call_packets.project_path
                    if config.project_sink_call_packets is not None
                    else None
                ),
                "vulnerability_seed_manifest_path": (
                    loaded.vulnerability_seed_manifest_path
                ),
                "vulnerability_seed_packet_count": (
                    loaded.vulnerability_seed_packet_count
                ),
                "operation_backlog_path": loaded.operation_backlog_path,
                "operation_backlog_packet_count": (
                    loaded.operation_backlog_packet_count
                ),
                "operation_backlog_batch_count": loaded.operation_backlog_batch_count,
                "patch_diff_packet_count": loaded.patch_diff_packet_count,
                "build_corpus_manifest_path": loaded.build_corpus_manifest_path,
                "build_corpus_target_count": loaded.build_corpus_target_count,
                "build_corpus_project_packet_count": (
                    loaded.build_corpus_project_packet_count
                ),
                "build_corpus_project_batch_count": (
                    loaded.build_corpus_project_batch_count
                ),
                "build_corpus_resolved_project_path": (
                    loaded.build_corpus_resolved_project_path
                ),
                "build_corpus_resolved_binary_path": (
                    loaded.build_corpus_resolved_binary_path
                ),
            },
        ),
        source_tools=[tool for tool in tool_sequence if not tool.endswith("_blocker")],
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="validation",
                source="windows_validation_planning_batch",
                summary=(
                    f"{result.validation_plan.candidate_id}: "
                    f"ready={result.ready_for_runtime_validation} "
                    f"blockers={len(result.blockers)}"
                ),
                provenance=[
                    result.validation_plan.image_path,
                    result.validation_plan.ovmf_vars_path,
                ],
                reason_codes=[
                    result.workflow_state,
                    result.candidate_grounding.source,
                ],
            )
            for result in results[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=_dedupe(
                [
                    f"candidate_grounding:{result.candidate_grounding.source}"
                    for result in results
                ]
            ),
            missing_facts=_dedupe(
                [
                    fact
                    for result in results
                    for fact in result.evidence_bundle.coverage.missing_facts
                ]
            ),
            validation_ready=all(
                result.ready_for_runtime_validation for result in results
            ),
            stale_or_blocking_facts=blockers,
        ),
        reason_codes=_dedupe([result.workflow_state for result in results]),
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


def _notes(
    config: WindowsValidationPlanningConfig,
    recipe: WindowsValidationHarnessRecipe | None,
    artifact_bundle: WindowsValidationArtifactBundle | None,
    state: WindowsValidationWorkflowState,
) -> list[str]:
    notes = [
        "Validation planning is a runtime handoff workflow, not finding promotion.",
        "Stock/current comparison and hashed artifacts are required before review.",
    ]
    if config.harness_recipes_path and recipe is None:
        notes.append("No component-specific harness recipe matched the candidate.")
    if artifact_bundle is None:
        notes.append("No runtime artifacts were supplied.")
    elif state == "reproduced_issue_state_requires_human_review":
        notes.append(
            "Crash artifacts are present and ready for review; promotion still needs human gate checks."
        )
    return notes


def _next_actions(
    plan: WindowsVmValidationPlan,
    harness_template: WindowsValidationHarnessTemplate,
    artifact_bundle: WindowsValidationArtifactBundle | None,
) -> list[str]:
    actions = list(plan.operator_steps)
    actions.extend(harness_template.stock_steps[:4])
    actions.extend(harness_template.current_steps[:4])
    if artifact_bundle is None:
        actions.append("record runtime artifact bundle after executing the harness")
    elif not artifact_bundle.ready_for_review:
        actions.extend(artifact_bundle.runtime_blockers)
    else:
        actions.append("review runtime artifact bundle against promotion gates")
    return _dedupe(actions)


def _target_id(packet: WindowsReviewPacket) -> str | None:
    if packet.component_profile is not None and packet.component_profile.target_id:
        return packet.component_profile.target_id
    if packet.project_facts is not None and packet.project_facts.target_id:
        return packet.project_facts.target_id
    return None


def _component(packet: WindowsReviewPacket) -> str | None:
    if packet.component_profile is not None and packet.component_profile.component:
        return packet.component_profile.component
    return packet.binary


def _missing_facts(packet: WindowsReviewPacket) -> list[str]:
    missing = []
    if packet.project_facts is not None:
        missing.extend(packet.project_facts.missing_facts)
    for fact in packet.required_project_facts:
        if (
            packet.project_facts is None
            or fact not in packet.project_facts.fact_coverage
        ):
            missing.append(fact)
    return _dedupe(missing)


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-validation-planning>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-validation-planning>")
    return ctx


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
