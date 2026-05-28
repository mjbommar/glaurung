from __future__ import annotations

import json
import os
from pathlib import Path

from glaurung.llm.agents.windows_evidence_review import (
    WindowsEvidenceReviewConfig,
    WindowsEvidenceReviewGap,
    run_windows_evidence_review,
)
from glaurung.llm.tools.windows_emit_review_packet import (
    WindowsProjectFactContext,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from glaurung.llm.tools.windows_emit_validation_harness_template import (
    WindowsValidationHarnessTemplate,
)
from glaurung.llm.tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from glaurung.llm.tools.windows_project_fact_manifest import (
    ProjectFactCounts,
    ProjectFactRecord,
)
from glaurung.llm.tools.windows_record_candidate_snapshot_mapping import (
    WindowsCandidateSnapshotMapping,
)
from glaurung.llm.tools.windows_record_validation_artifact_bundle import (
    WindowsValidationArtifact,
    WindowsValidationArtifactBundle,
)


def _packet(
    candidate_id: str,
    *,
    project_facts: WindowsProjectFactContext | None,
    promotion_preconditions_met: bool = True,
    promotion_blockers: list[str] | None = None,
) -> WindowsReviewPacket:
    return WindowsReviewPacket(
        candidate_id=candidate_id,
        binary="ntoskrnl.exe",
        build="26100.1",
        entrypoint="nt!NtExample",
        attacker_class="local_unprivileged",
        source_role="output_buffer",
        source_arg="arg1",
        sink_symbol="RtlCopyMemory",
        sink_kind="copy",
        required_gates=["destination_range_valid"],
        proven_gates=[],
        missing_required_gates=[],
        gate_status="missing",
        path=[
            WindowsReviewPathStep(
                function="nt!NtExample",
                symbol="RtlCopyMemory",
                arg_index=0,
                role="destination_buffer",
            )
        ],
        evidence=[
            WindowsReviewEvidence(
                source="unit",
                summary="synthetic packet",
                provenance=["cfg", "asb_pe_sink_metadata"],
            )
        ],
        provenance=["cfg", "asb_pe_sink_metadata"],
        project_facts=project_facts,
        required_project_facts=["function_names", "call_xrefs", "cfg"],
        promotion_preconditions_met=promotion_preconditions_met,
        promotion_blockers=promotion_blockers or [],
        priority="high",
        confidence=0.85,
        confidence_reason="unit",
        next_validation=["build a VM validation plan"],
        false_positive_questions=["is caller context actually low privilege?"],
    )


def _facts(*, complete: bool) -> WindowsProjectFactContext:
    coverage = (
        ["function_names", "call_xrefs", "cfg"] if complete else ["function_names"]
    )
    missing = [] if complete else ["call_xrefs", "cfg"]
    return WindowsProjectFactContext(
        target_id="ntoskrnl",
        build_label="win11-ltsc-v4",
        project_path="/projects/ntoskrnl.glaurung",
        fact_coverage=coverage,
        missing_facts=missing,
        counts={"function_name_count": 10},
    )


def _project_record(*, complete: bool) -> ProjectFactRecord:
    coverage = (
        ["function_names", "call_xrefs", "cfg"] if complete else ["function_names"]
    )
    missing = [] if complete else ["call_xrefs", "cfg"]
    return ProjectFactRecord(
        id="ntoskrnl_project_facts",
        target_id="ntoskrnl",
        build_label="win11-ltsc-v4",
        build_number="26100.1",
        architecture="x64",
        binary_filename="ntoskrnl.exe",
        project_path="/projects/ntoskrnl.glaurung",
        project_sha256="a" * 64,
        project_size_bytes=1024,
        fact_sources=["unit"],
        fact_coverage=coverage,
        missing_facts=missing,
        counts=ProjectFactCounts(function_name_count=10, call_xref_count=3),
    )


def _plan(candidate_id: str, *, ready: bool = True) -> WindowsVmValidationPlan:
    blockers = [] if ready else ["KDNET attach is not validated: not_configured"]
    return WindowsVmValidationPlan(
        candidate_id=candidate_id,
        binary="ntoskrnl.exe",
        build="26100.1",
        validation_id="win11_ltsc_v4_cold_postlogon",
        build_label="win11-ltsc-v4",
        snapshot_name="cold-postlogon",
        image_path="/images/win11-ltsc-v4.qcow2",
        ovmf_vars_path="/images/win11-ltsc-v4.OVMF_VARS.fd",
        qmp_endpoint="127.0.0.1:4447",
        rdp_endpoint="server0:3390",
        kdnet_port=51000,
        kdnet_status="attach_validated" if ready else "not_configured",
        debugger_status="attached_once" if ready else "not_attached",
        kdnet_attach_proof="/evidence/kdnet-attach.log" if ready else None,
        kdnet_last_attach_utc="2026-05-18T20:00:00Z" if ready else None,
        harness_strategy=["exercise syscall harness"],
        validation_requirements=["syscall_table_membership"],
        expected_artifacts=["C:\\Windows\\MEMORY.DMP"],
        stock_current_comparison=["Run stock", "Run current"],
        operator_steps=["Boot VM", "Run harness"],
        blockers=blockers,
        ready_for_validation=ready,
    )


def _mapping(candidate_id: str) -> WindowsCandidateSnapshotMapping:
    return WindowsCandidateSnapshotMapping(
        candidate_id=candidate_id,
        binary="ntoskrnl.exe",
        candidate_build="26100.1",
        candidate_build_label="win11-ltsc-v4",
        validation_id="win11_ltsc_v4_cold_postlogon",
        validation_build_label="win11-ltsc-v4",
        validation_build_number="26100.1",
        snapshot_name="cold-postlogon",
        image_path="/images/win11-ltsc-v4.qcow2",
        ovmf_vars_path="/images/win11-ltsc-v4.OVMF_VARS.fd",
        qmp_endpoint="127.0.0.1:4447",
        rdp_endpoint="server0:3390",
        kdnet_port=51000,
        mapping_confidence="high",
        mapping_evidence=["candidate_id matches validation plan"],
        mapping_blockers=[],
        runtime_blockers=[],
        ready_for_runtime_validation=True,
    )


def _harness(candidate_id: str) -> WindowsValidationHarnessTemplate:
    return WindowsValidationHarnessTemplate(
        candidate_id=candidate_id,
        harness_id=f"win-harness-{candidate_id}",
        binary="ntoskrnl.exe",
        entrypoint="nt!NtExample",
        sink_symbol="RtlCopyMemory",
        harness_strategy=["exercise syscall harness"],
        preconditions=["restore snapshot"],
        stock_steps=["Run stock"],
        current_steps=["Run current"],
        artifact_requirements=["kdnet attach transcript"],
        skeleton_commands=["$CandidateId = 'candidate'"],
        blockers=[],
        ready_to_collect_artifacts=True,
        markdown="# harness\n",
    )


def _artifact_bundle(candidate_id: str) -> WindowsValidationArtifactBundle:
    return WindowsValidationArtifactBundle(
        candidate_id=candidate_id,
        validation_id="win11_ltsc_v4_cold_postlogon",
        execution_status="crash_observed",
        artifact_count=1,
        artifacts=[
            WindowsValidationArtifact(
                kind="crash_dump",
                path="/evidence/MEMORY.DMP",
                sha256="b" * 64,
                summary="bugcheck observed",
            )
        ],
        missing_required_artifacts=[],
        runtime_blockers=[],
        ready_for_review=True,
    )


def _artifact_bundle_for_path(
    candidate_id: str,
    path: Path,
) -> WindowsValidationArtifactBundle:
    bundle = _artifact_bundle(candidate_id)
    return bundle.model_copy(
        update={
            "artifacts": [
                WindowsValidationArtifact(
                    kind="crash_dump",
                    path=str(path),
                    sha256="c" * 64,
                    summary="bugcheck observed",
                )
            ]
        }
    )


def test_windows_evidence_review_rejects_high_priority_packet_with_weak_static_facts() -> (
    None
):
    packet = _packet(
        "weak-static",
        project_facts=_facts(complete=False),
        promotion_preconditions_met=False,
        promotion_blockers=["missing project fact coverage context"],
    )

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            packets=[packet],
            validation_plans=[_plan("weak-static", ready=True)],
            substrate_gaps=[
                WindowsEvidenceReviewGap(
                    candidate_id="weak-static",
                    fact_class="functionization",
                    detail="Ghidra-only start overlaps sink owner",
                )
            ],
        )
    )

    item = result.review_items[0]
    assert item.triage_priority in {"high", "critical"}
    assert item.decision == "reject_missing_static_facts"
    assert item.validation_state == "plan_ready"
    assert item.promotion_allowed is False
    assert "call_xrefs" in item.missing_static_facts
    assert any("functionization" in gap for gap in item.substrate_gaps)
    assert any("repair missing project" in action for action in item.next_actions)
    assert result.ready_for_human_review_count == 0
    assert result.evidence_bundle.claim_level == "triage_evidence_bundle_not_finding"
    assert "# Windows Evidence Review" in result.operator_validation_markdown
    assert "## weak-static" in result.operator_validation_markdown
    assert "repair missing project/functionization facts" in (
        result.operator_validation_markdown
    )


def test_windows_evidence_review_loads_candidate_packet_artifact(
    tmp_path: Path,
) -> None:
    packet = _packet("artifact-packet", project_facts=_facts(complete=True))
    packet_artifact = tmp_path / "candidate-packets.json"
    packet_artifact.write_text(
        json.dumps(
            {
                "claim_level": "candidate_packet_export_not_finding",
                "candidate_count": 1,
                "candidate_packets": [packet.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(candidate_packets_path=str(packet_artifact))
    )

    assert result.loaded_candidate_packet_count == 1
    assert result.candidate_packets_path == str(packet_artifact)
    assert result.review_items[0].candidate_id == "artifact-packet"
    assert "candidate_packet_artifact_loader" in result.tool_sequence
    assert result.evidence_bundle.subject.attributes[
        "loaded_candidate_packets_path"
    ] == str(packet_artifact)


def test_windows_evidence_review_loads_export_manifest_candidate_packets(
    tmp_path: Path,
) -> None:
    packet = _packet("manifest-packet", project_facts=_facts(complete=True))
    packet_artifact = tmp_path / "candidate-packets.json"
    export_manifest = tmp_path / "evidence-export.json"
    packet_artifact.write_text(
        json.dumps({"candidate_packets": [packet.model_dump(mode="json")]}),
        encoding="utf-8",
    )
    export_manifest.write_text(
        json.dumps(
            {
                "claim_level": "evidence_review_export_manifest_not_finding",
                "candidate_count": 1,
                "candidate_ids": ["manifest-packet"],
                "candidate_packets_path": str(packet_artifact),
            }
        ),
        encoding="utf-8",
    )

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            evidence_export_manifest_path=str(export_manifest),
        )
    )

    assert result.loaded_candidate_packet_count == 1
    assert result.candidate_packets_path == str(packet_artifact)
    assert result.evidence_export_manifest_path == str(export_manifest)
    assert result.review_items[0].candidate_id == "manifest-packet"
    assert "evidence_export_manifest_loader" in result.tool_sequence
    assert "evidence_export_candidate_packet_loader" in result.tool_sequence


def test_windows_evidence_review_separates_runtime_blockers_from_triage_priority() -> (
    None
):
    packet = _packet("runtime-blocked", project_facts=_facts(complete=True))

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            packets=[packet],
            validation_plans=[_plan("runtime-blocked", ready=False)],
        )
    )

    item = result.review_items[0]
    assert item.triage_priority in {"high", "critical"}
    assert item.decision == "blocked_runtime_validation"
    assert item.validation_state == "runtime_blocked"
    assert any("KDNET attach" in blocker for blocker in item.runtime_blockers)
    assert result.validation_report_markdown is not None
    assert (
        "Claim level: operator validation handoff, not reproduction."
        in result.validation_report_markdown
    )
    assert "Runtime Blockers" in result.operator_validation_markdown
    assert "KDNET attach is not validated" in result.operator_validation_markdown


def test_windows_evidence_review_writes_operator_and_validation_markdown(
    tmp_path: Path,
) -> None:
    packet = _packet("runtime-blocked", project_facts=_facts(complete=True))
    operator_path = tmp_path / "operator-review.md"
    validation_path = tmp_path / "candidate-validation.md"
    packet_path = tmp_path / "candidate-packets.json"
    export_path = tmp_path / "evidence-export.json"

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            packets=[packet],
            validation_plans=[_plan("runtime-blocked", ready=False)],
            operator_markdown_path=str(operator_path),
            validation_report_markdown_path=str(validation_path),
            candidate_packets_export_path=str(packet_path),
            export_manifest_path=str(export_path),
        )
    )

    assert result.operator_validation_markdown_path == str(operator_path)
    assert result.validation_report_markdown_path == str(validation_path)
    assert result.candidate_packets_export_path == str(packet_path)
    assert result.export_manifest_path == str(export_path)
    assert (
        operator_path.read_text(encoding="utf-8") == result.operator_validation_markdown
    )
    assert (
        validation_path.read_text(encoding="utf-8") == result.validation_report_markdown
    )
    packet_export = json.loads(packet_path.read_text(encoding="utf-8"))
    assert packet_export["candidate_count"] == 1
    assert packet_export["candidate_packets"][0]["candidate_id"] == "runtime-blocked"
    assert "windows_evidence_review:write_operator_markdown" in result.tool_sequence
    assert "windows_candidate_validation_report:write_markdown" in result.tool_sequence
    assert "windows_evidence_review:write_candidate_packets" in result.tool_sequence
    assert "windows_evidence_review:write_export_manifest" in result.tool_sequence
    export = json.loads(export_path.read_text(encoding="utf-8"))
    assert export["operator_markdown_path"] == str(operator_path)
    assert export["validation_report_markdown_path"] == str(validation_path)
    assert export["candidate_packets_path"] == str(packet_path)
    assert export["candidate_ids"] == ["runtime-blocked"]
    assert str(export_path) in export["generated_artifacts"]
    assert str(packet_path) in export["generated_artifacts"]
    assert result.export_manifest.operator_markdown_path == str(operator_path)
    assert result.export_manifest.candidate_packets_path == str(packet_path)
    assert result.evidence_bundle.subject.attributes["operator_markdown_path"] == str(
        operator_path
    )
    assert result.evidence_bundle.subject.attributes["candidate_packets_path"] == str(
        packet_path
    )
    assert result.evidence_bundle.subject.attributes["export_manifest_path"] == str(
        export_path
    )


def test_windows_evidence_review_marks_crash_artifacts_for_human_review_only() -> None:
    packet = _packet("crash-ready", project_facts=_facts(complete=True))

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            packets=[packet],
            validation_plans=[_plan("crash-ready", ready=True)],
            artifact_bundles=[_artifact_bundle("crash-ready")],
            snapshot_mappings=[_mapping("crash-ready")],
            harness_templates=[_harness("crash-ready")],
        )
    )

    item = result.review_items[0]
    assert item.decision == "ready_for_human_review"
    assert item.validation_state == "artifacts_ready"
    assert item.artifact_status == "crash_observed"
    assert item.promotion_allowed is False
    assert result.ready_for_human_review_count == 1
    assert any("human-review crash artifacts" in action for action in item.next_actions)
    assert "ready_for_human_review" in result.evidence_bundle.reason_codes


def test_windows_evidence_review_checks_persisted_project_fact_coverage() -> None:
    packet = _packet("manifest-weak", project_facts=_facts(complete=True))

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            packets=[packet],
            validation_plans=[_plan("manifest-weak", ready=True)],
            project_fact_records=[_project_record(complete=False)],
        )
    )

    item = result.review_items[0]
    assert item.decision == "reject_missing_static_facts"
    assert any(
        "persisted_project_facts missing call_xrefs" in gap
        for gap in item.project_coverage_gaps
    )
    assert "Project Coverage Gaps" in result.operator_validation_markdown
    assert "persisted_project_facts missing call_xrefs" in (
        result.operator_validation_markdown
    )
    assert any("provided_project_fact_records" == tool for tool in result.tool_sequence)
    assert "persisted_project_fact_manifest" in (
        result.evidence_bundle.coverage.fact_coverage
    )


def test_windows_evidence_review_blocks_stale_local_runtime_artifact(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "MEMORY.DMP"
    artifact.write_bytes(b"crash")
    now = 1_800_000_000.0
    old = now - 120
    os.utime(artifact, (old, old))
    packet = _packet("stale-artifact", project_facts=_facts(complete=True))

    result = run_windows_evidence_review(
        WindowsEvidenceReviewConfig(
            packets=[packet],
            validation_plans=[_plan("stale-artifact", ready=True)],
            artifact_bundles=[_artifact_bundle_for_path("stale-artifact", artifact)],
            snapshot_mappings=[_mapping("stale-artifact")],
            harness_templates=[_harness("stale-artifact")],
            max_artifact_age_seconds=60,
            current_time_epoch=now,
        )
    )

    item = result.review_items[0]
    assert item.decision == "blocked_runtime_validation"
    assert item.validation_state == "runtime_blocked"
    assert any(freshness.status == "stale" for freshness in item.artifact_freshness)
    assert any("stale artifact" in blocker for blocker in item.runtime_blockers)
    assert "## Stale Runtime Artifacts" in result.operator_validation_markdown
    assert "stale artifact" in result.operator_validation_markdown
    assert str(artifact) in result.operator_validation_markdown
    assert "local_artifact_freshness_check" in result.tool_sequence
    assert "artifact_freshness_timestamps" in (
        result.evidence_bundle.coverage.fact_coverage
    )
