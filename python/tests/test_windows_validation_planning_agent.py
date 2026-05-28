from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, cast

import glaurung as g
import pytest

from glaurung.llm.agents.windows_validation_planning import (
    WindowsValidationBuildCorpusPacketScanConfig,
    WindowsValidationPlanningBatchConfig,
    WindowsValidationPlanningConfig,
    run_windows_validation_planning_batch,
    run_windows_validation_planning,
)
from glaurung.llm.tools.windows_build_corpus import WindowsBuildCorpusArgs
from glaurung.llm.tools.windows_emit_review_packet import (
    WindowsComponentProfileContext,
    WindowsProjectFactContext,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from glaurung.llm.tools.windows_record_validation_artifact_bundle import (
    WindowsValidationArtifact,
)
from glaurung.llm.tools.windows_project_sink_call_packets import (
    WindowsProjectSinkCallPacketsArgs,
)
from glaurung.llm.tools.windows_vulnerability_seed_packets import (
    WindowsVulnerabilitySeedPacketsArgs,
)
from glaurung.llm.tools.windows_operation_backlog_packets import (
    WindowsOperationBacklogPacketsArgs,
)
from glaurung.llm.tools.windows_patch_diff_packets import (
    WindowsPatchDiffPacketsArgs,
)


_SWITCHY_V1 = Path("samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2")
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


class _Addr:
    def __init__(self, value: int) -> None:
        self.value = value


class _Insn:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Addr(va)
        self.mnemonic = mnemonic
        self.operands = operands


def _write_inventory(tmp_path: Path) -> Path:
    path = tmp_path / "pe-validation-inventory.yaml"
    path.write_text(
        r"""
- id: win11_ltsc_v4_cold_postlogon
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  sku: Win11 IoT Enterprise LTSC 2024 Evaluation
  snapshot_name: cold-postlogon
  baseline_kind: canonical_fuzz
  image_path: /images/win11-ltsc-v4.qcow2
  ovmf_vars_path: /images/win11-ltsc-v4.OVMF_VARS.fd
  qmp_endpoint: 127.0.0.1:4447
  rdp_endpoint: server0:3390
  kdnet_port: 51000
  kdnet_status: attach_validated
  debugger_status: attached_once
  kdnet_attach_proof: /evidence/kdnet-attach.log
  kdnet_last_attach_utc: "2026-05-18T20:00:00Z"
  boot_script: boot-win11-test.sh
  expected_artifacts:
    - /images/win11-test-serial.log
    - C:\Windows\MEMORY.DMP
  stock_current_comparison:
    - Run stock build once.
    - Run current build once.
""",
        encoding="utf-8",
    )
    return path


def _write_recipes(tmp_path: Path) -> Path:
    path = tmp_path / "pe-validation-harness-recipes.yaml"
    path.write_text(
        r"""
- id: cldflt_placeholder_policy_recipe
  profile_id: cldflt_cloud_filter_policy
  target_id: cldflt
  component: cldflt.sys
  surfaces: [cloud_filter, registry]
  trigger_kind: cloud_filter_placeholder_policy_sequence
  setup_steps:
    - Prepare provider root.
  stock_commands:
    - powershell -File run-cldflt.ps1 -Mode Stock
  current_commands:
    - powershell -File run-cldflt.ps1 -Mode Current
  artifact_requirements:
    - Registry export.
  known_blockers: []
  operator_notes:
    - Preserve caller token.
""",
        encoding="utf-8",
    )
    return path


def _write_sink_project(tmp_path: Path) -> Path:
    project = tmp_path / "driver.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
CREATE TABLE xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    kind TEXT,
    src_va INTEGER,
    src_function_va INTEGER,
    dst_va INTEGER
);
CREATE TABLE function_names (
    binary_id INTEGER,
    entry_va INTEGER,
    canonical TEXT,
    demangled TEXT
);
CREATE TABLE basic_blocks (
    binary_id INTEGER,
    function_va INTEGER,
    block_id TEXT,
    start_va INTEGER,
    end_va INTEGER
);
CREATE TABLE cfg_edges (
    binary_id INTEGER,
    function_va INTEGER,
    src_block_id TEXT,
    dst_block_id TEXT
);
"""
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x4000, "ProbeForWrite"),
                (0x5000, "RtlCopyMemory"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, 'call', ?, ?, ?)",
            [
                (1, 0x1100, 0x1000, 0x4000),
                (2, 0x1200, 0x1000, 0x5000),
            ],
        )
        conn.executemany(
            "INSERT INTO basic_blocks VALUES (1, ?, ?, ?, ?)",
            [
                (0x1000, "entry", 0x1000, 0x1100),
                (0x1000, "gate", 0x1100, 0x1180),
                (0x1000, "sink", 0x1180, 0x1280),
            ],
        )
        conn.executemany(
            "INSERT INTO cfg_edges VALUES (1, ?, ?, ?)",
            [
                (0x1000, "entry", "gate"),
                (0x1000, "gate", "sink"),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def _write_project_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZdriver")
    return binary


def _write_build_corpus_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "pe-build-corpus.yaml"
    path.write_text(
        """
- id: driver
  filename: driver.sys
  binary_kind: driver
  priority: high
  scan_roles: [ioctl_dispatch]
  surfaces: [ioctl]
  architectures: [x64]
  corpus_globs: ["driver.sys"]
  project_globs: ["driver.glaurung"]
  notes: Synthetic validation target.
""",
        encoding="utf-8",
    )
    return path


def _write_project_sinks(tmp_path: Path) -> Path:
    path = tmp_path / "pe-sinks.yaml"
    path.write_text(
        """
- id: rtl_copy_memory
  symbols: [RtlCopyMemory, memcpy]
  sink_kind: copy
  effects: [writes_destination_range, reads_source_range]
  arg_roles:
    0: destination_buffer
    1: source_buffer
    2: byte_count
  required_gates: [destination_range_valid, byte_count_bounded]
""",
        encoding="utf-8",
    )
    return path


def _write_project_gates(tmp_path: Path) -> Path:
    path = tmp_path / "pe-gates.yaml"
    path.write_text(
        """
- id: probeforwrite
  symbols: [ProbeForWrite]
  gate_kind: user_pointer
  proves: [user_pointer_write_range_valid]
  required_conditions: [call_dominates_write_sink]
  invalid_when: [length_is_zero]
""",
        encoding="utf-8",
    )
    return path


def _write_vulnerability_seeds(tmp_path: Path) -> Path:
    path = tmp_path / "pe-vulnerability-seeds.yaml"
    path.write_text(
        """
- id: mini_policy_seed
  public_ids: [CVE-2020-17103, MiniPlasma]
  title: Cloud filter policy authorization seed
  target_id: cldflt
  component: cldflt.sys
  functions: [HsmOsBlockPlaceholderAccess]
  surfaces: [cloud_filter, registry]
  attacker_classes: [windows-local-user]
  invariant_family: authorization
  primitive: privileged_registry_operation_without_caller_gate
  source_roles: [registry_policy_value]
  expected_gates: [caller_identity_or_impersonation_gate]
  expected_sinks: [privileged_registry_key_create_or_set]
  diff_signals: [added_authorization_check_before_registry_operation]
  validation_requirements: [prove caller security context]
  references: []
""",
        encoding="utf-8",
    )
    return path


def _write_operation_backlog(tmp_path: Path) -> Path:
    path = tmp_path / "pe-operation-classification-backlog.yaml"
    path.write_text(
        """
- id: backlog_copy_driver
  target_id: driver
  component: driver.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: snapshot-driver
  symbol: RtlCopyMemory
  observed_callsite_count: 7
  caller_function_count: 2
  resolution_kind_counts: {import: 7}
  sample_callers: [DriverDispatch]
  triage_category: memory_copy
  candidate_operation_kinds: [copy]
  likely_security_relevance: high
  required_capabilities: [source_arg_roles, destination_range_gate]
  recommended_next_actions:
    - classify destination/source/length argument roles
    - prove required gates before packet promotion
  notes: Classifier backlog entry, not a finding.
""",
        encoding="utf-8",
    )
    return path


def _write_project_facts(tmp_path: Path, project: Path) -> Path:
    path = tmp_path / "pe-project-facts.yaml"
    path.write_text(
        f"""
- id: driver_project
  target_id: driver
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: driver.sys
  project_path: {project}
  project_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  project_size_bytes: 4096
  fact_sources: [unit]
  fact_coverage: [function_names, call_xrefs, cfg, cfg_dominance]
  missing_facts: []
  counts:
    function_name_count: 3
    xref_count: 2
    call_xref_count: 2
    basic_block_count: 3
    cfg_edge_count: 2
    cfg_dominance_count: 3
""",
        encoding="utf-8",
    )
    return path


def _packet() -> WindowsReviewPacket:
    return WindowsReviewPacket(
        candidate_id="candidate-1",
        binary="cldflt.sys",
        build="26100.1742",
        entrypoint="HsmOsBlockPlaceholderAccess",
        attacker_class="windows-local-user",
        source_role="registry_policy_value",
        source_arg="caller_arg1",
        sink_symbol="ZwSetValueKey",
        sink_kind="registry",
        required_gates=["caller_identity_or_impersonation_gate"],
        proven_gates=["caller_identity_or_impersonation_gate"],
        missing_required_gates=[],
        gate_status="dominated",
        path=[
            WindowsReviewPathStep(
                function="HsmOsBlockPlaceholderAccess",
                symbol="ZwSetValueKey",
                arg_index=1,
                role="registry_policy_value",
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
        component_profile=WindowsComponentProfileContext(
            profile_id="cldflt_cloud_filter_policy",
            target_id="cldflt",
            component="cldflt.sys",
            entrypoint_kinds=["cloud_filter_callback"],
            required_gates=["registry_key_acl_or_policy_authorization"],
            validation_requirements=["pre_post_build_guard_comparison"],
            harness_strategy=(
                "Exercise placeholder creation and registry policy sequence "
                "from low-privilege user."
            ),
            evidence_packet_fields=["vm_validation_plan"],
        ),
        project_facts=WindowsProjectFactContext(
            target_id="cldflt",
            build_label="win11-ltsc-v4",
            project_path="/projects/cldflt.glaurung",
            fact_coverage=["function_names", "call_xrefs", "cfg"],
            missing_facts=[],
            counts={"function_name_count": 10, "call_xref_count": 7},
        ),
        required_project_facts=["function_names", "call_xrefs", "cfg"],
        promotion_preconditions_met=True,
        priority="high",
        confidence=0.8,
        confidence_reason="unit",
        next_validation=["build a VM validation plan"],
        false_positive_questions=["is caller context actually low privilege?"],
    )


def test_windows_validation_planning_emits_runtime_handoff_without_reproduction(
    tmp_path: Path,
) -> None:
    result = run_windows_validation_planning(
        WindowsValidationPlanningConfig(
            candidate_packet=_packet(),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            harness_recipes_path=str(_write_recipes(tmp_path)),
            surface_id="cloud_filter",
            trigger_kind="cloud_filter_placeholder_policy_sequence",
        )
    )

    assert result.claim_level == "validation_plan_not_reproduction"
    assert result.workflow_state == "validation_plan_not_reproduction"
    assert result.validation_plan.ready_for_validation is True
    assert result.validation_plan.snapshot_name == "cold-postlogon"
    assert result.validation_plan.kdnet_attach_proof == "/evidence/kdnet-attach.log"
    assert result.harness_recipe is not None
    assert result.harness_template.ready_to_collect_artifacts is True
    assert any(
        "Registry export" in item
        for item in result.harness_template.artifact_requirements
    )
    assert any(
        "Run stock build once" in item
        for item in result.validation_plan.stock_current_comparison
    )
    assert any("run-cldflt.ps1" in item for item in result.harness_template.stock_steps)
    assert result.artifact_bundle is None
    assert result.snapshot_mapping.ready_for_runtime_validation is True
    assert result.candidate_grounding.source == "glaurung_project"
    assert result.candidate_grounding.project_path == "/projects/cldflt.glaurung"
    assert result.candidate_grounding.validation_inventory_path == str(
        _write_inventory(tmp_path)
    )
    assert result.candidate_grounding.blockers == []
    assert "candidate_packet_grounding_check" in result.tool_sequence
    assert "candidate_grounding:glaurung_project" in (
        result.evidence_bundle.coverage.fact_coverage
    )
    assert result.ready_for_review is False
    assert result.evidence_bundle.claim_level == "validation_plan_not_reproduction"
    assert result.evidence_bundle.coverage.runtime_artifact_count == 0


def test_windows_validation_planning_maps_incomplete_runtime_artifacts_as_blocked(
    tmp_path: Path,
) -> None:
    result = run_windows_validation_planning(
        WindowsValidationPlanningConfig(
            candidate_packet=_packet(),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            execution_status="partial",
            artifacts=[
                WindowsValidationArtifact(
                    kind="kdnet_attach_log",
                    path="/evidence/kdnet-attach.log",
                    required=True,
                )
            ],
        )
    )

    assert result.claim_level == "runtime_artifact_bundle_not_finding"
    assert result.artifact_bundle is not None
    assert result.artifact_bundle.ready_for_review is False
    assert (
        "kdnet_attach_log: missing sha256"
        in result.artifact_bundle.missing_required_artifacts
    )
    assert any(
        "validation execution is not complete" in item for item in result.blockers
    )
    assert result.snapshot_mapping.ready_for_runtime_validation is False
    assert result.evidence_bundle.claim_level == "runtime_artifact_bundle_not_finding"


def test_windows_validation_planning_keeps_crash_observed_as_review_state(
    tmp_path: Path,
) -> None:
    crash_dump = tmp_path / "MEMORY.DMP"
    crash_dump.write_bytes(b"synthetic dump")

    result = run_windows_validation_planning(
        WindowsValidationPlanningConfig(
            candidate_packet=_packet(),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            execution_status="crash_observed",
            artifacts=[
                WindowsValidationArtifact(
                    kind="crash_dump",
                    path=str(crash_dump),
                    required=True,
                    summary="bugcheck observed during current run",
                )
            ],
            hash_existing_paths=True,
            require_existing_paths=True,
        )
    )

    assert result.claim_level == "reproduced_issue_state_requires_human_review"
    assert result.workflow_state == "reproduced_issue_state_requires_human_review"
    assert result.artifact_bundle is not None
    assert result.artifact_bundle.ready_for_review is True
    assert result.artifact_bundle.artifacts[0].sha256 is not None
    assert result.ready_for_review is True
    assert result.evidence_bundle.claim_level == "runtime_artifact_bundle_not_finding"
    assert (
        "reproduced_issue_state_requires_human_review"
        in result.evidence_bundle.reason_codes
    )


def test_windows_validation_planning_blocks_when_project_grounding_required(
    tmp_path: Path,
) -> None:
    packet = _packet().model_copy(update={"project_facts": None})

    result = run_windows_validation_planning(
        WindowsValidationPlanningConfig(
            candidate_packet=packet,
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=True,
        )
    )

    assert result.candidate_grounding.source == "asb_validation_inventory"
    assert "candidate packet lacks .glaurung project facts" in result.blockers
    assert "candidate packet lacks .glaurung project facts" in (
        result.evidence_bundle.coverage.missing_facts
    )


def test_windows_validation_planning_batch_runs_multiple_grounded_candidates(
    tmp_path: Path,
) -> None:
    grounded = _packet()
    manual = _packet().model_copy(
        update={"candidate_id": "candidate-manual", "project_facts": None}
    )

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            candidate_packets=[grounded, manual],
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=True,
            max_candidates=4,
        )
    )

    assert result.claim_level == "validation_batch_not_reproduction"
    assert result.candidate_count == 2
    assert result.planned_count == 2
    assert result.ready_for_runtime_validation_count == 1
    assert result.blocked_count == 1
    assert result.results[0].candidate_grounding.source == "glaurung_project"
    assert result.results[1].candidate_grounding.source == "asb_validation_inventory"
    assert "candidate packet lacks .glaurung project facts" in result.blockers
    assert "windows_validation_planning_batch" in result.tool_sequence
    assert "candidate_grounding:glaurung_project" in (
        result.evidence_bundle.coverage.fact_coverage
    )
    assert "candidate_grounding:asb_validation_inventory" in (
        result.evidence_bundle.coverage.fact_coverage
    )


def test_windows_validation_planning_batch_loads_candidate_packet_artifact(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "candidate-packets.json"
    grounded = _packet()
    second = _packet().model_copy(update={"candidate_id": "candidate-2"})
    artifact.write_text(
        json.dumps(
            {
                "packets": [
                    {"packet": grounded.model_dump(mode="json")},
                    second.model_dump(mode="json"),
                ]
            }
        ),
        encoding="utf-8",
    )

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            candidate_packets_path=str(artifact),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            max_candidates=8,
        )
    )

    assert result.candidate_count == 2
    assert result.loaded_candidate_packet_count == 2
    assert result.candidate_packets_path == str(artifact)
    assert result.planned_count == 2
    assert "candidate_packet_artifact_loader" in result.tool_sequence
    assert result.results[0].validation_plan.candidate_id == "candidate-1"
    assert result.results[1].validation_plan.candidate_id == "candidate-2"
    assert result.evidence_bundle.subject.attributes["candidate_count"] == 2


def test_windows_validation_planning_batch_writes_candidate_packet_export(
    tmp_path: Path,
) -> None:
    export_path = tmp_path / "validation-candidate-packets.json"

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            candidate_packets=[_packet()],
            candidate_packets_export_path=str(export_path),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            max_candidates=4,
        )
    )

    raw = json.loads(export_path.read_text(encoding="utf-8"))
    assert result.candidate_packets_export_path == str(export_path)
    assert raw["claim_level"] == "validation_candidate_packet_export_not_finding"
    assert raw["candidate_count"] == 1
    assert raw["candidate_packets"][0]["candidate_id"] == "candidate-1"
    assert (
        "windows_validation_planning_batch:write_candidate_packets"
        in result.tool_sequence
    )
    assert result.evidence_bundle.subject.attributes[
        "candidate_packets_export_path"
    ] == str(export_path)


def test_windows_validation_planning_batch_loads_evidence_export_manifest(
    tmp_path: Path,
) -> None:
    packet_artifact = tmp_path / "candidate-packets.json"
    export_manifest = tmp_path / "evidence-export.json"
    grounded = _packet()
    packet_artifact.write_text(
        json.dumps(
            {
                "claim_level": "candidate_packet_export_not_finding",
                "candidate_count": 1,
                "candidate_packets": [grounded.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )
    export_manifest.write_text(
        json.dumps(
            {
                "claim_level": "evidence_review_export_manifest_not_finding",
                "candidate_count": 1,
                "candidate_ids": ["candidate-1"],
                "candidate_packets_path": str(packet_artifact),
                "generated_artifacts": [str(packet_artifact)],
            }
        ),
        encoding="utf-8",
    )

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            evidence_export_manifest_path=str(export_manifest),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=True,
            max_candidates=4,
        )
    )

    assert result.candidate_count == 1
    assert result.loaded_candidate_packet_count == 1
    assert result.evidence_export_candidate_packet_count == 1
    assert result.evidence_export_manifest_path == str(export_manifest)
    assert result.planned_count == 1
    assert "evidence_export_manifest_loader" in result.tool_sequence
    assert "evidence_export_candidate_packet_loader" in result.tool_sequence
    assert result.results[0].candidate_grounding.source == "glaurung_project"
    assert result.evidence_bundle.subject.attributes[
        "evidence_export_manifest_path"
    ] == str(export_manifest)
    assert result.evidence_bundle.subject.attributes[
        "evidence_export_candidate_packets_path"
    ] == str(packet_artifact)


def test_windows_validation_planning_batch_invokes_project_packet_tool(
    tmp_path: Path,
) -> None:
    project = _write_sink_project(tmp_path)

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            project_sink_call_packets=WindowsProjectSinkCallPacketsArgs(
                project_path=str(project),
                binary="driver.sys",
                build="26100.1742",
                attacker_class="windows-local-user",
                source_role="buffer",
                source_arg="arg1",
                call_symbol="RtlCopyMemory",
                refine_gates=True,
                sinks_path=str(_write_project_sinks(tmp_path)),
                gates_path=str(_write_project_gates(tmp_path)),
                project_facts_path=str(_write_project_facts(tmp_path, project)),
                manifest_target_id="driver",
                manifest_build_label="win11-ltsc-v4",
                max_packets=4,
            ),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=True,
            max_candidates=4,
        )
    )

    assert result.candidate_count == 1
    assert result.project_emitted_candidate_packet_count == 1
    assert result.project_sink_call_packets_path == str(project)
    assert result.planned_count == 1
    assert "windows_project_sink_call_packets" in result.tool_sequence
    assert result.results[0].candidate_grounding.source == "glaurung_project"
    assert result.results[0].candidate_grounding.project_path == str(project)
    assert result.results[0].validation_plan.binary == "driver.sys"
    assert result.evidence_bundle.subject.attributes[
        "project_sink_call_packets_path"
    ] == str(project)


def test_windows_validation_planning_batch_invokes_vulnerability_seed_packets(
    tmp_path: Path,
) -> None:
    seeds = _write_vulnerability_seeds(tmp_path)

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            vulnerability_seed_packets=WindowsVulnerabilitySeedPacketsArgs(
                seeds_path=str(seeds),
                target_id="cldflt",
                max_packets=4,
            ),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=False,
            max_candidates=4,
        )
    )

    assert result.candidate_count == 1
    assert result.vulnerability_seed_packet_count == 1
    assert result.vulnerability_seed_manifest_path == str(seeds)
    assert result.project_emitted_candidate_packet_count == 0
    assert result.planned_count == 1
    assert "windows_vulnerability_seed_packets" in result.tool_sequence
    packet = result.candidate_packets[0]
    assert packet.diff_context is not None
    assert packet.diff_context.seed_id == "mini_policy_seed"
    assert packet.source_refinement_status == "inferred"
    assert result.results[0].candidate_grounding.source == "asb_validation_inventory"
    assert result.evidence_bundle.subject.attributes[
        "vulnerability_seed_manifest_path"
    ] == str(seeds)
    assert (
        result.evidence_bundle.subject.attributes["vulnerability_seed_packet_count"]
        == 1
    )


def test_windows_validation_planning_batch_invokes_operation_backlog_packets(
    tmp_path: Path,
) -> None:
    backlog = _write_operation_backlog(tmp_path)

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            operation_backlog_packets=WindowsOperationBacklogPacketsArgs(
                backlog_path=str(backlog),
                target_id="driver",
                max_packets=4,
            ),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=False,
            max_candidates=4,
        )
    )

    assert result.candidate_count == 1
    assert result.operation_backlog_packet_count == 1
    assert result.operation_backlog_path == str(backlog)
    assert result.planned_count == 1
    assert "windows_operation_backlog_packets" in result.tool_sequence
    packet = result.candidate_packets[0]
    assert packet.candidate_id == "backlog-backlog_copy_driver-rtlcopymemory"
    assert packet.source_refinement_status == "missing"
    assert packet.sink_symbol == "RtlCopyMemory"
    assert "destination_range_gate" in packet.required_gates
    assert (
        result.evidence_bundle.subject.attributes["operation_backlog_packet_count"]
        == 1
    )


def test_windows_validation_planning_batch_invokes_patch_diff_packets(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            patch_diff_packets=WindowsPatchDiffPacketsArgs(
                binary_a=str(a),
                binary_b=str(b),
                max_diff_rows=16,
                max_items=4,
                max_packets=2,
            ),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=False,
            max_candidates=4,
        )
    )

    assert result.candidate_count >= 1
    assert result.patch_diff_packet_count >= 1
    assert result.planned_count >= 1
    assert "windows_patch_diff_packets" in result.tool_sequence
    packet = result.candidate_packets[0]
    assert packet.candidate_id.startswith("patchdiff-")
    assert packet.diff_context is not None
    assert packet.source_refinement_status == "missing"
    assert (
        result.evidence_bundle.subject.attributes["patch_diff_packet_count"]
        == result.patch_diff_packet_count
    )


def test_windows_validation_planning_batch_resolves_project_packets_from_build_corpus(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = _write_sink_project(tmp_path)
    binary = _write_project_binary(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1008, "mov", ["r8d", "0x20"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            build_corpus_project_sink_call_packets=(
                WindowsValidationBuildCorpusPacketScanConfig(
                    build_corpus=WindowsBuildCorpusArgs(
                        manifest_path=str(_write_build_corpus_manifest(tmp_path)),
                        corpus_root=str(tmp_path),
                        project_root=str(tmp_path),
                        target_id="driver",
                    ),
                    build="26100.1742",
                    attacker_class="windows-local-user",
                    source_role="buffer",
                    source_arg="arg1",
                    call_symbol="RtlCopyMemory",
                    refine_gates=True,
                    sinks_path=str(_write_project_sinks(tmp_path)),
                    gates_path=str(_write_project_gates(tmp_path)),
                    project_facts_path=str(_write_project_facts(tmp_path, project)),
                    manifest_build_label="win11-ltsc-v4",
                    max_packets=4,
                )
            ),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=True,
            max_candidates=4,
        )
    )

    assert result.candidate_count == 1
    assert result.project_emitted_candidate_packet_count == 1
    assert result.build_corpus_project_packet_count == 1
    assert result.build_corpus_project_batch_count == 1
    assert result.build_corpus_target_count == 1
    assert result.build_corpus_resolved_project_path == str(project)
    assert result.build_corpus_resolved_binary_path == str(binary)
    assert result.planned_count == 1
    assert "windows_build_corpus:project_sink_call_packets" in result.tool_sequence
    assert "windows_project_sink_call_packets" in result.tool_sequence
    assert result.results[0].candidate_grounding.source == "glaurung_project"
    assert result.results[0].candidate_grounding.project_path == str(project)
    assert result.evidence_bundle.subject.attributes[
        "build_corpus_resolved_project_path"
    ] == str(project)
    assert result.evidence_bundle.subject.attributes[
        "build_corpus_resolved_binary_path"
    ] == str(binary)


def test_windows_validation_planning_batch_runs_multiple_build_corpus_packet_scans(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = _write_sink_project(tmp_path)
    _write_project_binary(tmp_path)
    manifest = _write_build_corpus_manifest(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1008, "mov", ["r8d", "0x20"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    scan = WindowsValidationBuildCorpusPacketScanConfig(
        build_corpus=WindowsBuildCorpusArgs(
            manifest_path=str(manifest),
            corpus_root=str(tmp_path),
            project_root=str(tmp_path),
            target_id="driver",
        ),
        build="26100.1742",
        attacker_class="windows-local-user",
        source_role="buffer",
        source_arg="arg1",
        call_symbol="RtlCopyMemory",
        refine_gates=True,
        sinks_path=str(_write_project_sinks(tmp_path)),
        gates_path=str(_write_project_gates(tmp_path)),
        project_facts_path=str(_write_project_facts(tmp_path, project)),
        manifest_build_label="win11-ltsc-v4",
        max_packets=4,
    )

    result = run_windows_validation_planning_batch(
        WindowsValidationPlanningBatchConfig(
            build_corpus_project_sink_call_packet_batches=[scan, scan],
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_project_grounding=True,
            max_candidates=4,
        )
    )

    assert result.candidate_count == 2
    assert result.project_emitted_candidate_packet_count == 2
    assert result.build_corpus_project_packet_count == 2
    assert result.build_corpus_project_batch_count == 2
    assert result.build_corpus_target_count == 2
    assert result.planned_count == 2
    assert "windows_build_corpus:project_sink_call_packets" in result.tool_sequence
    assert "windows_project_sink_call_packets" in result.tool_sequence
    assert all(
        item.candidate_grounding.project_path == str(project) for item in result.results
    )
    assert (
        result.evidence_bundle.subject.attributes["build_corpus_project_batch_count"]
        == 2
    )
