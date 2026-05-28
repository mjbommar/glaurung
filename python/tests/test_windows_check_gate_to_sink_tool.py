from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_check_gate_to_sink import build_tool


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


def test_windows_check_gate_to_sink_reports_gate_before_sink(
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
            gate_kind="user_pointer",
            sink_kind="copy",
            pseudocode="""
void Handler(void *dst, void *src, ULONG len) {
    ProbeForWrite(dst, len, 1);
    RtlCopyMemory(dst, src, len);
}
""",
            add_to_kb=True,
        ),
    )

    assert result.gate_call_count == 1
    assert result.sink_call_count == 1
    assert result.assessments[0].status == "gate_before_sink"
    assert result.assessments[0].gate is not None
    assert result.assessments[0].gate.gate.id == "probeforwrite"
    assert "ordering is not dominance" in result.assessments[0].reason
    assert "line-order evidence only" in result.notes[-1]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_check_gate_to_sink"
        for node in ctx.kb.nodes()
    )


def test_windows_check_gate_to_sink_reports_missing_gate(tmp_path: Path) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            gates_path=str(gates),
            sinks_path=str(sinks),
            gate_symbol="ProbeForWrite",
            sink_symbol="RtlCopyMemory",
            pseudocode="""
void Handler(void *dst, void *src, ULONG len) {
    RtlCopyMemory(dst, src, len);
}
""",
        ),
    )

    assert result.gate_call_count == 0
    assert result.sink_call_count == 1
    assert result.assessments[0].status == "missing"
    assert result.assessments[0].gate is None


def test_windows_check_gate_to_sink_reports_gate_after_sink(tmp_path: Path) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            gates_path=str(gates),
            sinks_path=str(sinks),
            pseudocode="""
void Handler(void *dst, void *src, ULONG len) {
    RtlCopyMemory(dst, src, len);
    ProbeForWrite(dst, len, 1);
}
""",
        ),
    )

    assert result.assessments[0].status == "gate_after_sink"
    assert result.assessments[0].gate is not None
    assert result.assessments[0].gate.call.line > result.assessments[0].sink.call.line


def test_memory_agent_registers_windows_check_gate_to_sink() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_check_gate_to_sink" in agent._function_toolset.tools
