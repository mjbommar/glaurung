from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_diff_security_relevant_facts import build_tool


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


def test_windows_diff_security_relevant_facts_reports_added_gate_and_constant(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            gates_path=str(gates),
            sinks_path=str(sinks),
            before_pseudocode="""
NTSTATUS Handler(void *out, void *src, ULONG len) {
    Helper(out);
    RtlCopyMemory(out, src, 128);
    return STATUS_SUCCESS;
}
""",
            after_pseudocode="""
NTSTATUS Handler(void *out, void *src, ULONG len) {
    if (len > 64) {
        return STATUS_BUFFER_OVERFLOW;
    }
    ProbeForWrite(out, len, 1);
    RtlCopyMemory(out, src, 256);
    return STATUS_BUFFER_OVERFLOW;
}
""",
            add_to_kb=True,
        ),
    )

    assert result.before.sinks[0].operation.id == "rtl_copy_memory"
    assert result.after.gates[0].gate.id == "probeforwrite"
    assert any(
        delta.direction == "added"
        and delta.fact_kind == "gate"
        and delta.item_id == "probeforwrite"
        for delta in result.deltas
    )
    assert any(
        delta.direction == "removed"
        and delta.fact_kind == "helper_call"
        and delta.item_id == "Helper"
        for delta in result.deltas
    )
    assert any(
        delta.direction == "added"
        and delta.fact_kind == "constant"
        and delta.item_id == "256"
        for delta in result.deltas
    )
    assert any(
        delta.direction == "removed"
        and delta.fact_kind == "constant"
        and delta.item_id == "128"
        for delta in result.deltas
    )
    assert any(
        delta.direction == "added"
        and delta.fact_kind == "path_condition"
        and delta.item_id.endswith("len > 64")
        for delta in result.deltas
    )
    assert result.after.path_conditions
    assert result.similarity < 1.0
    assert "security fact diff uses pseudocode" in result.notes[-1]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_diff_security_relevant_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_diff_security_relevant_facts_handles_missing_inputs(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(gates_path=str(gates), sinks_path=str(sinks)),
    )

    assert result.before.line_count == 0
    assert result.after.line_count == 0
    assert result.deltas == []
    assert "no before_pseudocode or before_function_va supplied" in result.notes
    assert "no after_pseudocode or after_function_va supplied" in result.notes


def test_memory_agent_registers_windows_diff_security_relevant_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_diff_security_relevant_facts" in agent._function_toolset.tools
