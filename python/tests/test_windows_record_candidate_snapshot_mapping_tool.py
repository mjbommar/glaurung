from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_emit_review_packet import (
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from glaurung.llm.tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from glaurung.llm.tools.windows_record_candidate_snapshot_mapping import build_tool
from glaurung.llm.tools.windows_record_validation_artifact_bundle import (
    WindowsValidationArtifact,
    WindowsValidationArtifactBundle,
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _packet(
    candidate_id: str = "candidate-1",
    *,
    build_label: str | None = "win11-ltsc-v4",
) -> WindowsReviewPacket:
    project_facts = (
        {
            "target_id": "cldflt",
            "build_label": build_label,
            "project_path": "/projects/cldflt.glaurung",
            "fact_coverage": ["function_names", "call_xrefs"],
            "missing_facts": [],
            "counts": {"function_name_count": 10},
        }
        if build_label is not None
        else None
    )
    return WindowsReviewPacket(
        candidate_id=candidate_id,
        binary="cldflt.sys",
        build="26100.1742",
        entrypoint="HsmOsBlockPlaceholderAccess",
        attacker_class="windows-local-user",
        source_role="registry_policy_value",
        source_arg="caller_arg1",
        sink_symbol="ZwSetValueKey",
        sink_kind="registry",
        required_gates=["caller_identity_or_impersonation_gate"],
        proven_gates=[],
        missing_required_gates=["caller_identity_or_impersonation_gate"],
        gate_status="missing",
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
        project_facts=project_facts,
        required_project_facts=["function_names", "call_xrefs"],
        promotion_preconditions_met=True,
        priority="high",
        confidence=0.8,
        confidence_reason="unit",
        next_validation=["build a VM validation plan"],
        false_positive_questions=["is caller context actually low privilege?"],
    )


def _plan(candidate_id: str = "candidate-1", *, blockers: list[str] | None = None):
    return WindowsVmValidationPlan(
        candidate_id=candidate_id,
        binary="cldflt.sys",
        build="26100.1742",
        validation_id="win11_ltsc_v4_cold_postlogon",
        build_label="win11-ltsc-v4",
        snapshot_name="cold-postlogon",
        image_path="/images/win11-ltsc-v4.qcow2",
        ovmf_vars_path="/images/win11-ltsc-v4.OVMF_VARS.fd",
        qmp_endpoint="127.0.0.1:4447",
        rdp_endpoint="server0:3390",
        kdnet_port=51000,
        kdnet_status="attach_validated",
        debugger_status="attached_once",
        kdnet_attach_proof="/evidence/kdnet-attach.log",
        kdnet_last_attach_utc="2026-05-18T20:00:00Z",
        harness_strategy=["exercise placeholder policy sequence"],
        validation_requirements=["pre_post_build_guard_comparison"],
        expected_artifacts=["C:\\Windows\\MEMORY.DMP"],
        stock_current_comparison=["Run stock", "Run current"],
        operator_steps=["Boot VM", "Run harness", "Capture dump"],
        blockers=blockers or [],
        ready_for_validation=not blockers,
    )


def _bundle() -> WindowsValidationArtifactBundle:
    return WindowsValidationArtifactBundle(
        candidate_id="candidate-1",
        validation_id="win11_ltsc_v4_cold_postlogon",
        execution_status="executed",
        artifact_count=1,
        artifacts=[
            WindowsValidationArtifact(
                kind="kdnet_attach_log",
                path="/evidence/kdnet-attach.log",
                sha256="a" * 64,
            )
        ],
        missing_required_artifacts=[],
        runtime_blockers=[],
        ready_for_review=True,
    )


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
  boot_script: boot.sh
  expected_artifacts:
    - /images/win11-test-serial.log
  stock_current_comparison:
    - Run stock.
    - Run current.
""",
        encoding="utf-8",
    )
    return path


def test_windows_record_candidate_snapshot_mapping_ready_with_inventory_and_bundle(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_packet=_packet(),
            validation_plan=_plan(),
            artifact_bundle=_bundle(),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_artifact_bundle=True,
            add_to_kb=True,
        ),
    )

    mapping = result.mapping
    assert mapping.claim_level == "candidate_snapshot_mapping_not_reproduction"
    assert mapping.validation_build_number == "26100.1742"
    assert mapping.candidate_build_label == "win11-ltsc-v4"
    assert mapping.mapping_confidence == "high"
    assert mapping.ready_for_runtime_validation is True
    assert mapping.mapping_blockers == []
    assert mapping.runtime_blockers == []
    assert any("candidate_id matches" in item for item in mapping.mapping_evidence)
    assert any("inventory build_label matches" in item for item in mapping.mapping_evidence)
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_record_candidate_snapshot_mapping"
        and node.props["ready_for_runtime_validation"] is True
        for node in ctx.kb.nodes()
    )


def test_windows_record_candidate_snapshot_mapping_blocks_mismatches(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_packet=_packet(candidate_id="candidate-1", build_label="wrong-build"),
            validation_plan=_plan(candidate_id="other-candidate"),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            require_artifact_bundle=True,
        ),
    )

    mapping = result.mapping
    assert mapping.mapping_confidence == "blocked"
    assert mapping.ready_for_runtime_validation is False
    assert any("candidate_id mismatch" in blocker for blocker in mapping.mapping_blockers)
    assert any("build label mismatch" in blocker for blocker in mapping.mapping_blockers)
    assert any("ready artifact bundle is required" in blocker for blocker in mapping.mapping_blockers)


def test_windows_record_candidate_snapshot_mapping_keeps_runtime_blockers_separate(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_packet=_packet(),
            validation_plan=_plan(blockers=["KDNET attach is not validated"]),
            validation_inventory_path=str(_write_inventory(tmp_path)),
        ),
    )

    mapping = result.mapping
    assert mapping.mapping_confidence == "mapped_static_runtime_blocked"
    assert mapping.mapping_blockers == []
    assert mapping.runtime_blockers == ["KDNET attach is not validated"]
    assert mapping.ready_for_runtime_validation is False


def test_memory_agent_registers_windows_record_candidate_snapshot_mapping() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")
    assert "windows_record_candidate_snapshot_mapping" in agent._function_toolset.tools
