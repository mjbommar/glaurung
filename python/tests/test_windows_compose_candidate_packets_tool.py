from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_compose_candidate_packets import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_metadata(tmp_path: Path) -> tuple[Path, Path]:
    gates = tmp_path / "pe-gates.yaml"
    gates.write_text(
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
    sinks = tmp_path / "pe-sinks.yaml"
    sinks.write_text(
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
    return gates, sinks


def test_windows_compose_candidate_packets_builds_intra_packet(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary="ntoskrnl.exe",
            build="26100.1",
            entrypoint="nt!NtExample",
            attacker_class="local_unprivileged",
            source_role="output_buffer",
            source_name="dst",
            caller_pseudocode="""
void NtExample(void *dst, void *src, ULONG len) {
    ProbeForWrite(dst, len, 1);
    RtlCopyMemory(dst, src, len);
}
""",
            gates_path=str(gates),
            sinks_path=str(sinks),
            gate_kind="user_pointer",
            sink_kind="copy",
            pdb_identity={
                "target_id": "ntoskrnl",
                "expected_pdb_name": "ntkrnlmp.pdb",
                "cache_status": "cached",
                "fact_coverage": ["pdb_public_symbols"],
            },
            component_profile={
                "profile_id": "ntoskrnl-core",
                "target_id": "ntoskrnl",
                "component": "kernel",
                "required_gates": ["user_pointer_captured"],
                "validation_requirements": ["vm_bugcheck_or_reject"],
                "harness_strategy": "syscall harness in checked VM",
            },
            diff_context={
                "seed_id": "copy-gate-regression",
                "changed_functions": ["nt!NtExample"],
                "diff_signals": ["added probe"],
            },
            project_facts={
                "target_id": "ntoskrnl",
                "build_label": "unit-test",
                "project_path": "/projects/ntoskrnl.glaurung",
                "fact_coverage": ["function_names", "call_xrefs"],
                "counts": {"function_name_count": 10, "call_xref_count": 3},
            },
            required_project_facts=["function_names", "call_xrefs"],
            ghidra_delta={
                "target_id": "ntoskrnl",
                "component": "ntoskrnl.exe",
                "current_capabilities": ["call_argument_flow"],
            },
            add_to_kb=True,
        ),
    )

    assert result.flow_count >= 1
    assert result.gate_assessment_count == 1
    assert len(result.packets) == 1
    packet = result.packets[0].packet
    assert packet.claim_level == "candidate_not_finding"
    assert packet.sink_symbol == "RtlCopyMemory"
    assert packet.gate_status == "gate_before_sink"
    assert packet.path[0].role == "destination_buffer"
    assert packet.pdb_identity is not None
    assert packet.pdb_identity.expected_pdb_name == "ntkrnlmp.pdb"
    assert packet.component_profile is not None
    assert packet.component_profile.profile_id == "ntoskrnl-core"
    assert packet.diff_context is not None
    assert packet.diff_context.seed_id == "copy-gate-regression"
    assert packet.project_facts is not None
    assert packet.required_project_facts == ["function_names", "call_xrefs"]
    assert packet.ghidra_delta is not None
    assert packet.promotion_preconditions_met is True
    assert "user_pointer_captured" in packet.required_gates
    assert any(e.source == "windows_trace_arg_flow" for e in packet.evidence)
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_compose_candidate_packets"
        for node in ctx.kb.nodes()
    )


def test_windows_compose_candidate_packets_builds_onehop_packet(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary="driver.sys",
            entrypoint="Dispatch",
            attacker_class="appcontainer",
            source_role="output_buffer",
            source_name="user_out",
            caller_pseudocode="""
NTSTATUS Dispatch(void *user_out, ULONG len) {
    ProbeForWrite(user_out, len, 1);
    return Helper(user_out, len);
}
""",
            helpers=[
                {
                    "name": "Helper",
                    "pseudocode": """
NTSTATUS Helper(void *out, ULONG len) {
    RtlCopyMemory(out, GlobalBuffer, len);
    return STATUS_SUCCESS;
}
""",
                }
            ],
            gates_path=str(gates),
            sinks_path=str(sinks),
        ),
    )

    assert result.flow_count == 1
    assert len(result.packets) == 1
    composition = result.packets[0]
    assert composition.flow_kind == "onehop"
    assert composition.gate_assessment is not None
    assert composition.packet.gate_status == "gate_before_sink"
    assert composition.packet.path[0].symbol == "Helper"
    assert composition.packet.path[1].symbol == "RtlCopyMemory"
    assert any(e.source == "windows_trace_onehop_flow" for e in composition.packet.evidence)


def test_memory_agent_registers_windows_compose_candidate_packets() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_compose_candidate_packets" in agent._function_toolset.tools
