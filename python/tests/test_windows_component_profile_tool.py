from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_component_profile import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_profiles(tmp_path: Path) -> Path:
    profiles = tmp_path / "pe-component-profiles.yaml"
    profiles.write_text(
        """
- id: cldflt_cloud_filter_policy
  target_id: cldflt
  component: cldflt.sys
  priority: critical
  surfaces: [cloud_filter, file_system_filter, registry]
  attacker_classes: [windows-local-user, windows-appcontainer]
  entrypoints:
    - kind: cloud_filter_callback
      symbols: [HsmOsBlockPlaceholderAccess, CfAbortHydration]
      source_roles: [file_operation_sequence, registry_policy_value]
      notes: Cloud Files placeholder policy path.
  required_gates: [caller_identity_or_impersonation_gate, registry_key_acl_or_policy_authorization]
  validation_requirements: [filter_manager_registration_map, pre_post_build_guard_comparison]
  harness_strategy: [Run Cloud Files placeholder sequence from low-privilege user.]
  initial_rules: [privileged_registry_or_policy_operation_without_effective_caller_gate]
  evidence_packet_fields: [pdb_identity, callback_registration, vm_validation_plan]
- id: tcpip_network_parser_state
  target_id: tcpip
  component: tcpip.sys
  priority: critical
  surfaces: [network, local_socket]
  attacker_classes: [windows-network, windows-local-user]
  entrypoints:
    - kind: packet_parser
      symbols: [Tcp, Udp, Ip]
      source_roles: [packet_field, option_length]
  required_gates: [packet_length_bounded, state_transition_lock_or_reference]
  validation_requirements: [listening_protocol_or_packet_path]
  harness_strategy: [Inject malformed packets in a network-capable snapshot.]
  initial_rules: [packet_option_length_mismatch]
  evidence_packet_fields: [packet_path, field_offset_and_length]
""",
        encoding="utf-8",
    )
    return profiles


def test_windows_component_profile_filters_cloud_filter_profile(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            profiles_path=str(_write_profiles(tmp_path)),
            surface_id="cloud_filter",
            attacker_class="windows-appcontainer",
        ),
    )

    assert result.profile_count_total == 2
    assert [profile.id for profile in result.profiles] == ["cldflt_cloud_filter_policy"]
    profile = result.profiles[0]
    assert profile.component == "cldflt.sys"
    assert profile.entrypoints[0].kind == "cloud_filter_callback"
    assert "caller_identity_or_impersonation_gate" in profile.required_gates
    assert "vm_validation_plan" in profile.evidence_packet_fields
    assert "routing and validation plans" in result.notes[0]


def test_windows_component_profile_filters_rule_and_adds_evidence(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            profiles_path=str(_write_profiles(tmp_path)),
            initial_rule="packet_option_length_mismatch",
            add_to_kb=True,
        ),
    )

    assert [profile.target_id for profile in result.profiles] == ["tcpip"]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_component_profile"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_component_profile() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_component_profile" in agent._function_toolset.tools
