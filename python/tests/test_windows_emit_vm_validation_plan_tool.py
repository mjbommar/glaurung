from __future__ import annotations

from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_emit_review_packet import (
    build_tool as build_review_packet_tool,
)
from glaurung.llm.tools.windows_emit_vm_validation_plan import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


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
  kdnet_status: guest_configured_host_forward_missing
  debugger_status: not_attached
  boot_script: tools/windows/win11-fuzz/scripts/boot-win11-test.sh
  expected_artifacts:
    - /images/win11-test-serial.log
    - C:\Windows\MEMORY.DMP
  stock_current_comparison:
    - Run baseline build once.
    - Run current build once.
  notes: KDNET host forward is intentionally absent in this unit fixture.
- id: win11_25h2_v1_cold_postlogon
  build_label: win11-25h2-v1
  build_number: "26200.6584"
  architecture: x64
  sku: Win11 25H2 Enterprise Evaluation
  snapshot_name: cold-postlogon
  baseline_kind: secondary_fuzz
  image_path: /images/win11-25h2-v1.qcow2
  ovmf_vars_path: /images/win11-25h2-v1.OVMF_VARS.fd
  qmp_endpoint: 127.0.0.1:4446
  rdp_endpoint: server0:3391
  kdnet_port: 51001
  kdnet_status: attach_validated
  debugger_status: attached_once
  boot_script: tools/windows/win11-fuzz/scripts/boot-win11-25h2-test.sh
  expected_artifacts:
    - /images/win11-25h2-test-serial.log
    - C:\Windows\MEMORY.DMP
  stock_current_comparison:
    - Run baseline build once.
    - Run current build once.
  notes: Unit fixture with validated debug attach.
""",
        encoding="utf-8",
    )
    return path


def _packet(ctx: MemoryContext):
    review_tool = build_review_packet_tool()
    result = review_tool.run(
        ctx,
        ctx.kb,
        review_tool.input_model(
            binary="cldflt.sys",
            build="26100.1742",
            entrypoint="HsmOsBlockPlaceholderAccess",
            attacker_class="windows-local-user",
            source_role="registry_policy_value",
            source_arg="caller_arg1",
            sink_symbol="ZwSetValueKey",
            sink_kind="registry",
            required_gates=["caller_identity_or_impersonation_gate"],
            gate_status="missing",
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
            project_facts={
                "target_id": "cldflt",
                "build_label": "win11-ltsc-v4",
                "project_path": "/projects/cldflt.glaurung",
                "fact_coverage": ["function_names", "call_xrefs", "cfg"],
                "missing_facts": [],
                "counts": {"function_name_count": 10, "call_xref_count": 7},
            },
        ),
    )
    return result.packet


def test_windows_emit_vm_validation_plan_surfaces_runtime_blockers(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_packet=_packet(ctx),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            add_to_kb=True,
        ),
    )

    plan = result.plan
    assert result.selected_by == "build_label"
    assert plan.claim_level == "validation_plan_not_reproduction"
    assert plan.validation_id == "win11_ltsc_v4_cold_postlogon"
    assert plan.snapshot_name == "cold-postlogon"
    assert plan.qmp_endpoint == "127.0.0.1:4447"
    assert plan.kdnet_status == "guest_configured_host_forward_missing"
    assert plan.ready_for_validation is False
    assert any("KDNET attach is not validated" in blocker for blocker in plan.blockers)
    assert any("host UDP forward" in blocker for blocker in plan.blockers)
    assert any("static packet promotion blockers remain" in blocker for blocker in plan.blockers)
    assert any("Exercise placeholder creation" in step for step in plan.operator_steps)
    assert any("MEMORY.DMP" in artifact for artifact in plan.expected_artifacts)
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_emit_vm_validation_plan"
        for node in ctx.kb.nodes()
    )


def test_windows_emit_vm_validation_plan_can_use_explicit_ready_substrate(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_packet=_packet(ctx),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            validation_id="win11_25h2_v1_cold_postlogon",
            require_kdnet_attach=True,
        ),
    )

    plan = result.plan
    assert result.selected_by == "validation_id"
    assert plan.validation_id == "win11_25h2_v1_cold_postlogon"
    assert not any("KDNET attach is not validated" in blocker for blocker in plan.blockers)
    assert not any("debugger attach proof is missing" in blocker for blocker in plan.blockers)
    assert any("static packet promotion blockers remain" in blocker for blocker in plan.blockers)


def test_memory_agent_registers_windows_emit_vm_validation_plan() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")
    assert "windows_emit_vm_validation_plan" in agent._function_toolset.tools
