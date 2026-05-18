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
from glaurung.llm.tools.windows_emit_validation_harness_template import build_tool
from glaurung.llm.tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from glaurung.llm.tools.windows_record_candidate_snapshot_mapping import (
    WindowsCandidateSnapshotMapping,
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


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
        component_profile={
            "profile_id": "cldflt_cloud_filter_policy",
            "target_id": "cldflt",
            "component": "cldflt.sys",
            "entrypoint_kinds": ["cloud_filter_callback"],
            "required_gates": ["registry_key_acl_or_policy_authorization"],
            "validation_requirements": ["pre_post_build_guard_comparison"],
            "harness_strategy": (
                "Exercise placeholder creation and registry policy sequence "
                "from low-privilege user."
            ),
            "evidence_packet_fields": ["vm_validation_plan"],
        },
        required_project_facts=["function_names", "call_xrefs"],
        promotion_preconditions_met=True,
        priority="high",
        confidence=0.8,
        confidence_reason="unit",
        next_validation=["build a VM validation plan"],
        false_positive_questions=["is caller context actually low privilege?"],
    )


def _plan(blockers: list[str] | None = None) -> WindowsVmValidationPlan:
    return WindowsVmValidationPlan(
        candidate_id="candidate-1",
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


def _mapping() -> WindowsCandidateSnapshotMapping:
    return WindowsCandidateSnapshotMapping(
        candidate_id="candidate-1",
        binary="cldflt.sys",
        candidate_build="26100.1742",
        candidate_build_label="win11-ltsc-v4",
        validation_id="win11_ltsc_v4_cold_postlogon",
        validation_build_label="win11-ltsc-v4",
        validation_build_number="26100.1742",
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


def test_windows_emit_validation_harness_template_writes_operator_scaffold(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    output_dir = tmp_path / "harness"

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_packet=_packet(),
            validation_plan=_plan(),
            snapshot_mapping=_mapping(),
            output_dir=str(output_dir),
            add_to_kb=True,
        ),
    )

    template = result.template
    assert template.claim_level == "harness_template_not_execution"
    assert template.ready_to_collect_artifacts is True
    assert template.blockers == []
    assert template.harness_id == "win-harness-candidate-1"
    assert any("placeholder policy sequence" in item for item in template.harness_strategy)
    assert any("C:\\Windows\\MEMORY.DMP" in item for item in template.artifact_requirements)
    assert "$CandidateId = 'candidate-1'" in template.skeleton_commands
    assert "# Windows Validation Harness Template: candidate-1" in template.markdown
    assert (output_dir / "README.md").read_text(encoding="utf-8") == template.markdown
    assert "TODO: run component-specific trigger" in (
        output_dir / "run-validation-template.ps1"
    ).read_text(encoding="utf-8")
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_emit_validation_harness_template"
        and node.props["ready_to_collect_artifacts"] is True
        for node in ctx.kb.nodes()
    )


def test_windows_emit_validation_harness_template_surfaces_plan_and_mapping_blockers(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    mapping = _mapping().model_copy(
        update={
            "mapping_blockers": ["candidate build label mismatch"],
            "runtime_blockers": ["KDNET attach is not validated"],
            "ready_for_runtime_validation": False,
        }
    )

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_packet=_packet(),
            validation_plan=_plan(blockers=["debugger attach proof is missing"]),
            snapshot_mapping=mapping,
        ),
    )

    template = result.template
    assert template.ready_to_collect_artifacts is False
    assert any("VM validation plan has blockers" in blocker for blocker in template.blockers)
    assert any("candidate snapshot mapping has blockers" in blocker for blocker in template.blockers)
    assert any("runtime blockers" in blocker for blocker in template.blockers)
    assert "Ready to collect artifacts: no" in template.markdown


def test_windows_emit_validation_harness_template_requires_plan(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(candidate_packet=_packet()),
    )

    assert result.template.ready_to_collect_artifacts is False
    assert "VM validation plan is missing" in result.template.blockers


def test_memory_agent_registers_windows_emit_validation_harness_template() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")
    assert "windows_emit_validation_harness_template" in agent._function_toolset.tools
