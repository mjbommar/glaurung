"""Deterministic Windows evidence-review workflow."""

from __future__ import annotations

import json
import time
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
from ..tools.windows_candidate_validation_report import (
    WindowsCandidateValidationReportArgs,
    WindowsCandidateValidationReportTool,
)
from ..tools.windows_emit_review_packet import WindowsReviewPacket
from ..tools.windows_emit_validation_harness_template import (
    WindowsValidationHarnessTemplate,
)
from ..tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from ..tools.windows_project_fact_manifest import (
    ProjectFactRecord,
    WindowsProjectFactManifestArgs,
    WindowsProjectFactManifestTool,
)
from ..tools.windows_rank_candidate_packets import (
    RankedWindowsCandidate,
    WindowsRankCandidatePacketsArgs,
    WindowsRankCandidatePacketsTool,
)
from ..tools.windows_record_candidate_snapshot_mapping import (
    WindowsCandidateSnapshotMapping,
)
from ..tools.windows_record_validation_artifact_bundle import (
    WindowsValidationArtifactBundle,
)


EvidenceGapSeverity = Literal["warning", "blocking"]
EvidenceReviewDecision = Literal[
    "reject_missing_static_facts",
    "blocked_runtime_validation",
    "blocked_runtime_artifacts",
    "ready_for_runtime_validation",
    "ready_for_human_review",
    "needs_more_static_evidence",
]
EvidenceReviewValidationState = Literal[
    "not_ready",
    "plan_ready",
    "artifacts_ready",
    "runtime_blocked",
]
EvidenceReviewTriagePriority = Literal["low", "medium", "high", "critical"]
ArtifactFreshnessStatus = Literal["fresh", "stale", "not_checked"]


class WindowsEvidenceReviewGap(BaseModel):
    candidate_id: str
    fact_class: str
    detail: str
    severity: EvidenceGapSeverity = "blocking"


class WindowsArtifactFreshness(BaseModel):
    candidate_id: str
    path: str
    kind: str
    status: ArtifactFreshnessStatus
    age_seconds: int | None = None
    last_modified_epoch: float | None = None
    detail: str


class WindowsEvidenceReviewConfig(BaseModel):
    packets: list[WindowsReviewPacket] = Field(default_factory=list)
    candidate_packets_path: str | None = Field(
        None,
        description=(
            "Optional JSON/YAML candidate-packet artifact to review. Accepts "
            "candidate_packets, packets, results, or a raw packet object."
        ),
    )
    evidence_export_manifest_path: str | None = Field(
        None,
        description=(
            "Optional evidence export manifest whose candidate_packets_path "
            "should be loaded before review."
        ),
    )
    validation_plans: list[WindowsVmValidationPlan] = Field(default_factory=list)
    artifact_bundles: list[WindowsValidationArtifactBundle] = Field(
        default_factory=list
    )
    snapshot_mappings: list[WindowsCandidateSnapshotMapping] = Field(
        default_factory=list
    )
    harness_templates: list[WindowsValidationHarnessTemplate] = Field(
        default_factory=list
    )
    substrate_gaps: list[WindowsEvidenceReviewGap] = Field(default_factory=list)
    project_fact_manifest_path: str | None = None
    project_fact_records: list[ProjectFactRecord] = Field(default_factory=list)
    max_artifact_age_seconds: int | None = Field(
        7 * 24 * 60 * 60,
        description=(
            "Maximum local artifact age before evidence review treats an existing "
            "runtime artifact path as stale. None disables freshness checks."
        ),
    )
    current_time_epoch: float | None = Field(
        None,
        description="Optional deterministic clock for artifact freshness tests.",
    )
    max_candidates: int = Field(20, ge=1, le=128)
    include_validation_report: bool = True
    validation_report_markdown_path: str | None = Field(
        None,
        description="Optional path to write the candidate validation report markdown.",
    )
    operator_markdown_path: str | None = Field(
        None,
        description="Optional path to write the skeptical operator evidence review markdown.",
    )
    export_manifest_path: str | None = Field(
        None,
        description=(
            "Optional JSON path to write a higher-level evidence handoff manifest "
            "containing markdown/report paths and candidate ids."
        ),
    )
    candidate_packets_export_path: str | None = Field(
        None,
        description=(
            "Optional JSON path to write the reviewed candidate packets as a "
            "structured validation-planning handoff artifact."
        ),
    )


class WindowsEvidenceReviewItem(BaseModel):
    rank: int
    candidate_id: str
    triage_score: float
    triage_priority: EvidenceReviewTriagePriority
    validation_state: EvidenceReviewValidationState
    decision: EvidenceReviewDecision
    promotion_allowed: bool = False
    binary: str
    entrypoint: str
    sink_symbol: str
    missing_static_facts: list[str] = Field(default_factory=list)
    substrate_gaps: list[str] = Field(default_factory=list)
    runtime_blockers: list[str] = Field(default_factory=list)
    artifact_status: str | None = None
    artifact_freshness: list[WindowsArtifactFreshness] = Field(default_factory=list)
    project_coverage_gaps: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class WindowsEvidenceReviewResult(BaseModel):
    claim_level: str = "evidence_review_not_finding"
    review_items: list[WindowsEvidenceReviewItem]
    ranked_candidates: list[RankedWindowsCandidate]
    validation_report_markdown: str | None = None
    validation_report_markdown_path: str | None = None
    operator_validation_markdown: str
    operator_validation_markdown_path: str | None = None
    export_manifest: "WindowsEvidenceReviewExportManifest"
    export_manifest_path: str | None = None
    loaded_candidate_packet_count: int = 0
    candidate_packets_path: str | None = None
    evidence_export_manifest_path: str | None = None
    candidate_packets_export_path: str | None = None
    tool_sequence: list[str]
    ready_for_human_review_count: int
    blocked_count: int
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


class WindowsEvidenceReviewExportManifest(BaseModel):
    claim_level: str = "evidence_review_export_manifest_not_finding"
    candidate_count: int
    ready_for_human_review_count: int
    blocked_count: int
    candidate_ids: list[str] = Field(default_factory=list)
    operator_markdown_path: str | None = None
    validation_report_markdown_path: str | None = None
    candidate_packets_path: str | None = None
    evidence_bundle_claim_level: str
    generated_artifacts: list[str] = Field(default_factory=list)
    tool_sequence: list[str] = Field(default_factory=list)


def run_windows_evidence_review(
    config: WindowsEvidenceReviewConfig,
) -> WindowsEvidenceReviewResult:
    ctx = _ctx()
    loaded_candidate_packets_path, loaded_packets = _load_candidate_packets(config)
    packets = [*config.packets, *loaded_packets]
    if not packets:
        raise ValueError("evidence review requires at least one candidate packet")
    effective_config = config.model_copy(update={"packets": packets})
    ranked = WindowsRankCandidatePacketsTool().run(
        ctx,
        ctx.kb,
        WindowsRankCandidatePacketsArgs(
            packets=effective_config.packets,
            validation_plans=effective_config.validation_plans,
            max_results=effective_config.max_candidates,
            add_to_kb=False,
        ),
    )
    bundle_by_candidate = _artifact_bundles_by_candidate(
        effective_config.artifact_bundles
    )
    mapping_by_candidate = _snapshot_mappings_by_candidate(
        effective_config.snapshot_mappings
    )
    harness_by_candidate = _harness_templates_by_candidate(
        effective_config.harness_templates
    )
    gap_by_candidate = _gaps_by_candidate(effective_config.substrate_gaps)
    project_fact_records = _project_fact_records(ctx, effective_config)
    freshness_by_candidate = _freshness_by_candidate(
        effective_config.artifact_bundles,
        max_age_seconds=effective_config.max_artifact_age_seconds,
        now=effective_config.current_time_epoch
        if effective_config.current_time_epoch is not None
        else time.time(),
    )
    items = [
        _review_item(
            ranked_candidate,
            artifact_bundle=bundle_by_candidate.get(
                ranked_candidate.packet.candidate_id
            ),
            mapping=mapping_by_candidate.get(ranked_candidate.packet.candidate_id),
            harness_template=harness_by_candidate.get(
                ranked_candidate.packet.candidate_id
            ),
            substrate_gaps=gap_by_candidate.get(
                ranked_candidate.packet.candidate_id, []
            ),
            project_fact_records=project_fact_records,
            project_fact_manifest_checked=bool(
                effective_config.project_fact_manifest_path
                or effective_config.project_fact_records
            ),
            artifact_freshness=freshness_by_candidate.get(
                ranked_candidate.packet.candidate_id, []
            ),
        )
        for ranked_candidate in ranked.ranked
    ]
    report_markdown = None
    tool_sequence = ["windows_rank_candidate_packets"]
    if config.include_validation_report:
        report = WindowsCandidateValidationReportTool().run(
            ctx,
            ctx.kb,
            WindowsCandidateValidationReportArgs(
                ranked_candidates=ranked.ranked,
                max_candidates=config.max_candidates,
                artifact_bundles=config.artifact_bundles,
                snapshot_mappings=config.snapshot_mappings,
                harness_templates=config.harness_templates,
                markdown_path=config.validation_report_markdown_path,
                add_to_kb=False,
            ),
        )
        report_markdown = report.markdown
        validation_report_path = report.markdown_path
        tool_sequence.append("windows_candidate_validation_report")
        if validation_report_path:
            tool_sequence.append("windows_candidate_validation_report:write_markdown")
    else:
        validation_report_path = None
    if config.project_fact_manifest_path:
        tool_sequence.append("windows_project_fact_manifest")
    if config.project_fact_records:
        tool_sequence.append("provided_project_fact_records")
    if config.candidate_packets_path:
        tool_sequence.append("candidate_packet_artifact_loader")
    if config.evidence_export_manifest_path:
        tool_sequence.extend(
            [
                "evidence_export_manifest_loader",
                "evidence_export_candidate_packet_loader",
            ]
        )
    if config.max_artifact_age_seconds is not None and config.artifact_bundles:
        tool_sequence.append("local_artifact_freshness_check")
    notes = [
        "Evidence review is a skeptical pre-promotion gate, not finding promotion.",
        "Triage score and validation readiness are reported separately.",
    ]
    operator_markdown = _operator_validation_markdown(items)
    operator_markdown_path = _write_operator_markdown(
        config.operator_markdown_path,
        operator_markdown,
    )
    if operator_markdown_path:
        tool_sequence.append("windows_evidence_review:write_operator_markdown")
    candidate_packets_export_path = _output_path(config.candidate_packets_export_path)
    if candidate_packets_export_path:
        tool_sequence.append("windows_evidence_review:write_candidate_packets")
    export_manifest_path = _output_path(config.export_manifest_path)
    if export_manifest_path:
        tool_sequence.append("windows_evidence_review:write_export_manifest")
    if candidate_packets_export_path:
        _write_candidate_packets(
            candidate_packets_export_path,
            [ranked_candidate.packet for ranked_candidate in ranked.ranked],
        )
    export_manifest = _export_manifest(
        items,
        tool_sequence,
        operator_markdown_path=operator_markdown_path,
        validation_report_markdown_path=validation_report_path,
        candidate_packets_path=candidate_packets_export_path,
        export_manifest_path=export_manifest_path,
    )
    if export_manifest_path:
        _write_export_manifest(export_manifest_path, export_manifest)
    return WindowsEvidenceReviewResult(
        review_items=items,
        ranked_candidates=ranked.ranked,
        validation_report_markdown=report_markdown,
        validation_report_markdown_path=validation_report_path,
        operator_validation_markdown=operator_markdown,
        operator_validation_markdown_path=operator_markdown_path,
        export_manifest=export_manifest,
        export_manifest_path=export_manifest_path,
        loaded_candidate_packet_count=len(loaded_packets),
        candidate_packets_path=loaded_candidate_packets_path,
        evidence_export_manifest_path=config.evidence_export_manifest_path,
        candidate_packets_export_path=candidate_packets_export_path,
        tool_sequence=tool_sequence,
        ready_for_human_review_count=sum(
            1 for item in items if item.decision == "ready_for_human_review"
        ),
        blocked_count=sum(1 for item in items if item.blockers),
        evidence_bundle=_evidence_bundle(
            items,
            tool_sequence,
            notes,
            operator_markdown_path=operator_markdown_path,
            validation_report_markdown_path=validation_report_path,
            candidate_packets_path=candidate_packets_export_path,
            loaded_candidate_packets_path=loaded_candidate_packets_path,
            evidence_export_manifest_path=config.evidence_export_manifest_path,
            loaded_candidate_packet_count=len(loaded_packets),
            export_manifest_path=export_manifest_path,
        ),
        notes=notes,
    )


def _write_operator_markdown(path_text: str | None, markdown: str) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")
    return str(path)


def _load_candidate_packets(
    config: WindowsEvidenceReviewConfig,
) -> tuple[str | None, list[WindowsReviewPacket]]:
    packets: list[WindowsReviewPacket] = []
    loaded_path = None
    if config.candidate_packets_path:
        path = Path(config.candidate_packets_path).expanduser()
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        artifact_packets = _packets_from_raw(raw, path)
        packets.extend(artifact_packets)
        loaded_path = str(path)
    if config.evidence_export_manifest_path:
        path, export_packets = _load_export_manifest_packets(
            Path(config.evidence_export_manifest_path).expanduser()
        )
        packets.extend(export_packets)
        loaded_path = str(path)
    return loaded_path, packets


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


def _output_path(path_text: str | None) -> str | None:
    if not path_text:
        return None
    return str(Path(path_text).expanduser())


def _write_candidate_packets(path_text: str, packets: list[WindowsReviewPacket]) -> str:
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "claim_level": "candidate_packet_export_not_finding",
        "candidate_count": len(packets),
        "candidate_packets": [packet.model_dump(mode="json") for packet in packets],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return str(path)


def _export_manifest(
    items: list[WindowsEvidenceReviewItem],
    tool_sequence: list[str],
    *,
    operator_markdown_path: str | None,
    validation_report_markdown_path: str | None,
    candidate_packets_path: str | None,
    export_manifest_path: str | None,
) -> WindowsEvidenceReviewExportManifest:
    generated = _dedupe(
        [
            operator_markdown_path or "",
            validation_report_markdown_path or "",
            candidate_packets_path or "",
            export_manifest_path or "",
        ]
    )
    return WindowsEvidenceReviewExportManifest(
        candidate_count=len(items),
        ready_for_human_review_count=sum(
            1 for item in items if item.decision == "ready_for_human_review"
        ),
        blocked_count=sum(1 for item in items if item.blockers),
        candidate_ids=[item.candidate_id for item in items],
        operator_markdown_path=operator_markdown_path,
        validation_report_markdown_path=validation_report_markdown_path,
        candidate_packets_path=candidate_packets_path,
        evidence_bundle_claim_level="triage_evidence_bundle_not_finding",
        generated_artifacts=generated,
        tool_sequence=tool_sequence,
    )


def _write_export_manifest(
    path_text: str,
    manifest: WindowsEvidenceReviewExportManifest,
) -> str | None:
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return str(path)


def _review_item(
    ranked: RankedWindowsCandidate,
    *,
    artifact_bundle: WindowsValidationArtifactBundle | None,
    mapping: WindowsCandidateSnapshotMapping | None,
    harness_template: WindowsValidationHarnessTemplate | None,
    substrate_gaps: list[WindowsEvidenceReviewGap],
    project_fact_records: list[ProjectFactRecord],
    project_fact_manifest_checked: bool,
    artifact_freshness: list[WindowsArtifactFreshness],
) -> WindowsEvidenceReviewItem:
    packet = ranked.packet
    project_coverage_gaps = _project_coverage_gaps(
        packet,
        project_fact_records,
        manifest_checked=project_fact_manifest_checked,
    )
    missing_static = _dedupe([*_missing_static_facts(packet), *project_coverage_gaps])
    substrate_gap_text = _substrate_gap_text(packet, substrate_gaps)
    runtime_blockers = _runtime_blockers(
        ranked,
        artifact_bundle=artifact_bundle,
        mapping=mapping,
        harness_template=harness_template,
        artifact_freshness=artifact_freshness,
    )
    artifact_status = artifact_bundle.execution_status if artifact_bundle else None
    validation_state = _validation_state(ranked, artifact_bundle, runtime_blockers)
    blockers = _dedupe(
        [
            *packet.promotion_blockers,
            *missing_static,
            *substrate_gap_text,
            *runtime_blockers,
        ]
    )
    decision = _decision(
        missing_static=missing_static,
        substrate_gaps=substrate_gap_text,
        runtime_blockers=runtime_blockers,
        artifact_bundle=artifact_bundle,
        ranked=ranked,
    )
    return WindowsEvidenceReviewItem(
        rank=ranked.rank,
        candidate_id=packet.candidate_id,
        triage_score=ranked.score,
        triage_priority=_triage_priority(ranked.score),
        validation_state=validation_state,
        decision=decision,
        promotion_allowed=False,
        binary=packet.binary,
        entrypoint=packet.entrypoint,
        sink_symbol=packet.sink_symbol,
        missing_static_facts=missing_static,
        substrate_gaps=substrate_gap_text,
        runtime_blockers=runtime_blockers,
        artifact_status=artifact_status,
        artifact_freshness=artifact_freshness,
        project_coverage_gaps=project_coverage_gaps,
        blockers=blockers,
        next_actions=_next_actions(decision, ranked, artifact_bundle),
        reasons=_dedupe([*ranked.reasons, *_decision_reasons(decision)]),
    )


def _decision(
    *,
    missing_static: list[str],
    substrate_gaps: list[str],
    runtime_blockers: list[str],
    artifact_bundle: WindowsValidationArtifactBundle | None,
    ranked: RankedWindowsCandidate,
) -> EvidenceReviewDecision:
    if missing_static or substrate_gaps or ranked.packet.promotion_blockers:
        return "reject_missing_static_facts"
    if artifact_bundle is not None and not artifact_bundle.ready_for_review:
        return "blocked_runtime_artifacts"
    if runtime_blockers:
        return "blocked_runtime_validation"
    if (
        artifact_bundle is not None
        and artifact_bundle.ready_for_review
        and artifact_bundle.execution_status == "crash_observed"
    ):
        return "ready_for_human_review"
    if ranked.validation_ready:
        return "ready_for_runtime_validation"
    return "needs_more_static_evidence"


def _validation_state(
    ranked: RankedWindowsCandidate,
    artifact_bundle: WindowsValidationArtifactBundle | None,
    runtime_blockers: list[str],
) -> EvidenceReviewValidationState:
    if runtime_blockers:
        return "runtime_blocked"
    if artifact_bundle is not None and artifact_bundle.ready_for_review:
        return "artifacts_ready"
    if (
        ranked.validation_ready
        or ranked.validation_plan is not None
        and ranked.validation_plan.ready_for_validation
    ):
        return "plan_ready"
    return "not_ready"


def _triage_priority(score: float) -> EvidenceReviewTriagePriority:
    if score >= 90.0:
        return "critical"
    if score >= 70.0:
        return "high"
    if score >= 40.0:
        return "medium"
    return "low"


def _missing_static_facts(packet: WindowsReviewPacket) -> list[str]:
    missing: list[str] = []
    if packet.project_facts is None and packet.required_project_facts:
        missing.extend(packet.required_project_facts)
    elif packet.project_facts is not None:
        missing.extend(packet.project_facts.missing_facts)
        for fact in packet.required_project_facts:
            if fact not in packet.project_facts.fact_coverage:
                missing.append(fact)
    if packet.ghidra_delta is not None:
        missing.extend(packet.ghidra_delta.missing_capabilities)
        missing.extend(packet.ghidra_delta.blocking_fact_classes)
    return _dedupe(missing)


def _project_fact_records(
    ctx: MemoryContext,
    config: WindowsEvidenceReviewConfig,
) -> list[ProjectFactRecord]:
    records = list(config.project_fact_records)
    if config.project_fact_manifest_path:
        result = WindowsProjectFactManifestTool().run(
            ctx,
            ctx.kb,
            WindowsProjectFactManifestArgs(
                project_facts_path=config.project_fact_manifest_path,
            ),
        )
        records.extend(result.records)
    return records


def _project_coverage_gaps(
    packet: WindowsReviewPacket,
    records: list[ProjectFactRecord],
    *,
    manifest_checked: bool,
) -> list[str]:
    if not manifest_checked:
        return []
    record = _matching_project_fact_record(packet, records)
    if record is None:
        return [
            "persisted_project_facts: no manifest record for "
            f"{packet.binary} {packet.build or ''}".strip()
        ]
    missing: list[str] = []
    for fact in packet.required_project_facts:
        if fact not in record.fact_coverage:
            missing.append(f"persisted_project_facts missing {fact}")
    for fact in record.missing_facts:
        if fact in packet.required_project_facts:
            missing.append(f"persisted_project_facts missing {fact}")
    if record.project_size_bytes is not None and record.project_size_bytes <= 0:
        missing.append("persisted_project_facts: project file has zero size")
    return _dedupe(missing)


def _matching_project_fact_record(
    packet: WindowsReviewPacket,
    records: list[ProjectFactRecord],
) -> ProjectFactRecord | None:
    target_id = packet.project_facts.target_id if packet.project_facts else None
    build_label = packet.project_facts.build_label if packet.project_facts else None
    if target_id:
        matches = [record for record in records if record.target_id == target_id]
        if build_label:
            exact = [record for record in matches if record.build_label == build_label]
            if exact:
                return exact[0]
        if matches:
            return matches[0]
    binary = packet.binary.lower()
    matches = [record for record in records if record.binary_filename.lower() == binary]
    if build_label:
        exact = [record for record in matches if record.build_label == build_label]
        if exact:
            return exact[0]
    if packet.build:
        exact_build = [
            record for record in matches if record.build_number == packet.build
        ]
        if exact_build:
            return exact_build[0]
    return matches[0] if matches else None


def _substrate_gap_text(
    packet: WindowsReviewPacket,
    gaps: list[WindowsEvidenceReviewGap],
) -> list[str]:
    values = [
        f"{gap.fact_class}: {gap.detail}" for gap in gaps if gap.severity == "blocking"
    ]
    if packet.ghidra_delta is not None:
        values.extend(
            f"ghidra_delta: {gap}" for gap in packet.ghidra_delta.blocking_fact_classes
        )
    return _dedupe(values)


def _freshness_by_candidate(
    bundles: list[WindowsValidationArtifactBundle],
    *,
    max_age_seconds: int | None,
    now: float,
) -> dict[str, list[WindowsArtifactFreshness]]:
    out: dict[str, list[WindowsArtifactFreshness]] = {}
    if max_age_seconds is None:
        return out
    for bundle in bundles:
        for artifact in bundle.artifacts:
            out.setdefault(bundle.candidate_id, []).append(
                _artifact_freshness(
                    bundle.candidate_id,
                    artifact.kind,
                    artifact.path,
                    max_age_seconds=max_age_seconds,
                    now=now,
                )
            )
    return out


def _artifact_freshness(
    candidate_id: str,
    kind: str,
    path_text: str,
    *,
    max_age_seconds: int,
    now: float,
) -> WindowsArtifactFreshness:
    path = Path(path_text)
    if not path.exists():
        return WindowsArtifactFreshness(
            candidate_id=candidate_id,
            path=path_text,
            kind=kind,
            status="not_checked",
            detail=f"artifact freshness not checked for non-local path: {path_text}",
        )
    modified = path.stat().st_mtime
    age = max(0, int(now - modified))
    if age > max_age_seconds:
        return WindowsArtifactFreshness(
            candidate_id=candidate_id,
            path=path_text,
            kind=kind,
            status="stale",
            age_seconds=age,
            last_modified_epoch=modified,
            detail=(
                f"stale artifact: {path_text} age_seconds={age} "
                f"max_age_seconds={max_age_seconds}"
            ),
        )
    return WindowsArtifactFreshness(
        candidate_id=candidate_id,
        path=path_text,
        kind=kind,
        status="fresh",
        age_seconds=age,
        last_modified_epoch=modified,
        detail=(
            f"fresh artifact: {path_text} age_seconds={age} "
            f"max_age_seconds={max_age_seconds}"
        ),
    )


def _runtime_blockers(
    ranked: RankedWindowsCandidate,
    *,
    artifact_bundle: WindowsValidationArtifactBundle | None,
    mapping: WindowsCandidateSnapshotMapping | None,
    harness_template: WindowsValidationHarnessTemplate | None,
    artifact_freshness: list[WindowsArtifactFreshness],
) -> list[str]:
    blockers = list(ranked.validation_blockers)
    if artifact_bundle is not None:
        blockers.extend(artifact_bundle.runtime_blockers)
        blockers.extend(artifact_bundle.missing_required_artifacts)
    if mapping is not None:
        blockers.extend(mapping.mapping_blockers)
        blockers.extend(mapping.runtime_blockers)
    if harness_template is not None:
        blockers.extend(harness_template.blockers)
    blockers.extend(
        freshness.detail
        for freshness in artifact_freshness
        if freshness.status == "stale"
    )
    return _dedupe(blockers)


def _next_actions(
    decision: EvidenceReviewDecision,
    ranked: RankedWindowsCandidate,
    artifact_bundle: WindowsValidationArtifactBundle | None,
) -> list[str]:
    if decision == "reject_missing_static_facts":
        return [
            "repair missing project/functionization facts before validation",
            "rerun evidence review after packet blockers clear",
        ]
    if decision == "blocked_runtime_validation":
        return [
            "fix VM/snapshot/KDNET/harness blockers",
            "regenerate validation plan and snapshot mapping",
        ]
    if decision == "blocked_runtime_artifacts":
        return [
            "complete required runtime artifact paths and SHA256 hashes",
            "rerun artifact bundle import",
        ]
    if decision == "ready_for_human_review":
        return [
            "human-review crash artifacts against stock/current comparison",
            "verify no Ghidra/functionization blockers remain before promotion",
        ]
    if decision == "ready_for_runtime_validation":
        actions = []
        if ranked.validation_plan is not None:
            actions.extend(ranked.validation_plan.operator_steps[:4])
        actions.append("execute harness and record runtime artifact bundle")
        return _dedupe(actions)
    if artifact_bundle is None:
        return ["attach validation plan or runtime artifact bundle"]
    return ["collect more static evidence"]


def _decision_reasons(decision: EvidenceReviewDecision) -> list[str]:
    return {
        "reject_missing_static_facts": ["static evidence is incomplete"],
        "blocked_runtime_validation": ["runtime validation substrate is blocked"],
        "blocked_runtime_artifacts": ["runtime artifacts are incomplete"],
        "ready_for_runtime_validation": ["static packet and VM plan are ready"],
        "ready_for_human_review": ["runtime crash artifacts are ready for review"],
        "needs_more_static_evidence": ["candidate needs more static evidence"],
    }[decision]


def _evidence_bundle(
    items: list[WindowsEvidenceReviewItem],
    tool_sequence: list[str],
    notes: list[str],
    *,
    operator_markdown_path: str | None,
    validation_report_markdown_path: str | None,
    candidate_packets_path: str | None,
    loaded_candidate_packets_path: str | None,
    evidence_export_manifest_path: str | None,
    loaded_candidate_packet_count: int,
    export_manifest_path: str | None,
) -> WindowsEvidenceBundle:
    blockers = _dedupe([blocker for item in items for blocker in item.blockers])
    missing = _dedupe([fact for item in items for fact in item.missing_static_facts])
    project_gaps = _dedupe(
        [gap for item in items for gap in item.project_coverage_gaps]
    )
    stale_artifacts = _dedupe(
        [
            freshness.detail
            for item in items
            for freshness in item.artifact_freshness
            if freshness.status == "stale"
        ]
    )
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "candidate_count": len(items),
                "ready_for_human_review_count": sum(
                    1 for item in items if item.decision == "ready_for_human_review"
                ),
                "blocked_count": sum(1 for item in items if item.blockers),
                "project_coverage_gap_count": len(project_gaps),
                "stale_artifact_count": len(stale_artifacts),
                "operator_markdown_path": operator_markdown_path,
                "validation_report_markdown_path": validation_report_markdown_path,
                "candidate_packets_path": candidate_packets_path,
                "loaded_candidate_packets_path": loaded_candidate_packets_path,
                "evidence_export_manifest_path": evidence_export_manifest_path,
                "loaded_candidate_packet_count": loaded_candidate_packet_count,
                "export_manifest_path": export_manifest_path,
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="candidate",
                source="windows_evidence_review",
                summary=f"{item.candidate_id}: {item.decision}",
                confidence=min(1.0, item.triage_score / 100.0),
                reason_codes=[item.decision, item.validation_state],
                provenance=[item.binary, item.entrypoint, item.sink_symbol],
            )
            for item in items[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[
                "persisted_project_fact_manifest"
                if project_gaps
                else "project_fact_check_not_requested_or_clean",
                "artifact_freshness_timestamps"
                if any(item.artifact_freshness for item in items)
                else "artifact_freshness_not_checked",
            ],
            missing_facts=_dedupe([*missing, *project_gaps]),
            stale_or_blocking_facts=blockers,
        ),
        reason_codes=_dedupe(
            [item.decision for item in items]
            + [item.validation_state for item in items]
        ),
        blockers=blockers,
        next_actions=_dedupe(
            [action for item in items for action in item.next_actions]
        ),
        notes=notes,
    )


def _operator_validation_markdown(items: list[WindowsEvidenceReviewItem]) -> str:
    ready_count = sum(1 for item in items if item.decision == "ready_for_human_review")
    blocked_count = sum(1 for item in items if item.blockers)
    lines = [
        "# Windows Evidence Review",
        "",
        "Claim level: evidence review, not finding promotion.",
        "",
        f"Candidates: {len(items)}",
        f"Ready for human review: {ready_count}",
        f"Blocked: {blocked_count}",
    ]
    stale = [
        freshness
        for item in items
        for freshness in item.artifact_freshness
        if freshness.status == "stale"
    ]
    if stale:
        lines.extend(["", "## Stale Runtime Artifacts"])
        lines.extend(f"- {item.candidate_id}: {item.detail}" for item in stale[:20])
        if len(stale) > 20:
            lines.append(f"- ... {len(stale) - 20} more")
    for item in items[:20]:
        lines.extend(
            [
                "",
                f"## {item.candidate_id}",
                f"- Decision: `{item.decision}`",
                f"- Validation state: `{item.validation_state}`",
                f"- Triage priority: `{item.triage_priority}`",
                f"- Binary: `{item.binary}`",
                f"- Entrypoint: `{item.entrypoint}`",
                f"- Sink: `{item.sink_symbol}`",
            ]
        )
        _append_markdown_list(lines, "Blockers", item.blockers)
        _append_markdown_list(lines, "Missing Static Facts", item.missing_static_facts)
        _append_markdown_list(
            lines, "Project Coverage Gaps", item.project_coverage_gaps
        )
        _append_markdown_list(lines, "Runtime Blockers", item.runtime_blockers)
        if item.artifact_freshness:
            lines.append("- Artifact Freshness:")
            lines.extend(
                (
                    f"  - `{freshness.status}` `{freshness.kind}` "
                    f"`{freshness.path}`: {freshness.detail}"
                )
                for freshness in item.artifact_freshness[:8]
            )
        _append_markdown_list(lines, "Next Actions", item.next_actions)
    if len(items) > 20:
        lines.extend(["", "## Truncated", f"- {len(items) - 20} additional candidates"])
    return "\n".join(lines) + "\n"


def _append_markdown_list(lines: list[str], title: str, values: list[str]) -> None:
    if not values:
        return
    lines.append(f"- {title}:")
    lines.extend(f"  - {value}" for value in values[:8])
    if len(values) > 8:
        lines.append(f"  - ... {len(values) - 8} more")


def _artifact_bundles_by_candidate(
    bundles: list[WindowsValidationArtifactBundle],
) -> dict[str, WindowsValidationArtifactBundle]:
    out: dict[str, WindowsValidationArtifactBundle] = {}
    for bundle in bundles:
        out.setdefault(bundle.candidate_id, bundle)
    return out


def _snapshot_mappings_by_candidate(
    mappings: list[WindowsCandidateSnapshotMapping],
) -> dict[str, WindowsCandidateSnapshotMapping]:
    out: dict[str, WindowsCandidateSnapshotMapping] = {}
    for mapping in mappings:
        out.setdefault(mapping.candidate_id, mapping)
    return out


def _harness_templates_by_candidate(
    templates: list[WindowsValidationHarnessTemplate],
) -> dict[str, WindowsValidationHarnessTemplate]:
    out: dict[str, WindowsValidationHarnessTemplate] = {}
    for template in templates:
        out.setdefault(template.candidate_id, template)
    return out


def _gaps_by_candidate(
    gaps: list[WindowsEvidenceReviewGap],
) -> dict[str, list[WindowsEvidenceReviewGap]]:
    out: dict[str, list[WindowsEvidenceReviewGap]] = {}
    for gap in gaps:
        out.setdefault(gap.candidate_id, []).append(gap)
    return out


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-evidence-review>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-evidence-review>")
    return ctx


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
