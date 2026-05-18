from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_compose_source_gate_sink_packet import build_tool


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


def _cfg(bypass: bool) -> list[dict]:
    entry_successors = ["gate", "bypass"] if bypass else ["gate"]
    sink_predecessors = ["gate", "bypass"] if bypass else ["gate"]
    blocks = [
        {
            "id": "entry",
            "start_va": 0x1000,
            "end_va": 0x1020,
            "successor_ids": entry_successors,
        },
        {
            "id": "gate",
            "start_va": 0x2000,
            "end_va": 0x2020,
            "successor_ids": ["sink"],
            "predecessor_ids": ["entry"],
        },
        {
            "id": "sink",
            "start_va": 0x3000,
            "end_va": 0x3020,
            "predecessor_ids": sink_predecessors,
        },
    ]
    if bypass:
        blocks.append(
            {
                "id": "bypass",
                "start_va": 0x2500,
                "end_va": 0x2520,
                "successor_ids": ["sink"],
                "predecessor_ids": ["entry"],
            }
        )
    return blocks


def test_windows_compose_source_gate_sink_packet_emits_candidate(
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
            build="26100.1",
            entrypoint="DriverDispatch",
            attacker_class="local_unprivileged",
            source_role="buffer",
            source_name="user_buffer",
            sink_symbol="RtlCopyMemory",
            sink_arg_index=1,
            gate_symbol="ProbeForWrite",
            gate_va=0x2010,
            sink_va=0x3010,
            pseudocode="""
void DriverDispatch(void *dst, void *user_buffer, ULONG len) {
    void *captured = user_buffer;
    RtlCopyMemory(dst, captured, len);
}
""",
            cfg_blocks=_cfg(bypass=True),
            gates_path=str(gates),
            sinks_path=str(sinks),
            project_facts={
                "target_id": "driver",
                "build_label": "unit-test",
                "project_path": "/projects/driver.glaurung",
                "fact_coverage": ["function_names", "call_xrefs", "cfg", "cfg_dominance"],
                "missing_facts": ["data_labels"],
                "counts": {
                    "function_name_count": 2,
                    "call_xref_count": 1,
                    "basic_block_count": 3,
                    "cfg_edge_count": 3,
                    "cfg_dominance_count": 3,
                },
            },
            ghidra_delta={
                "target_id": "driver",
                "component": "driver.sys",
                "blocking_fact_classes": ["call_argument_flow"],
            },
            add_to_kb=True,
        ),
    )

    assert result.operand_status == "alias"
    assert result.gate_status == "not_dominated"
    assert result.packet.claim_level == "candidate_not_finding"
    assert result.packet.gate_status == "not_dominated"
    assert result.packet.proven_gates == ["destination_range_valid"]
    assert result.packet.gate_proof_sources == {
        "destination_range_valid": "user_pointer_write_range_valid"
    }
    assert result.packet.missing_required_gates == [
        "byte_count_bounded",
    ]
    assert result.packet.sink_kind == "copy"
    assert result.packet.source_arg == "user_buffer"
    assert result.packet.project_facts is not None
    assert result.packet.project_facts.counts["cfg_edge_count"] == 3
    assert result.packet.required_project_facts == [
        "function_names",
        "call_xrefs",
        "cfg",
        "cfg_dominance",
    ]
    assert result.packet.ghidra_delta is not None
    assert result.packet.ghidra_delta.blocking_fact_classes == ["call_argument_flow"]
    assert result.packet.promotion_preconditions_met is False
    assert any("blocking Ghidra-parity gaps" in item for item in result.packet.promotion_blockers)
    assert any(
        evidence.source == "windows_source_sink_operand_match"
        for evidence in result.packet.evidence
    )
    assert any(
        evidence.source == "windows_cfg_gate_to_sink"
        for evidence in result.packet.evidence
    )
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_compose_source_gate_sink_packet"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_compose_source_gate_sink_packet() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_compose_source_gate_sink_packet" in agent._function_toolset.tools
