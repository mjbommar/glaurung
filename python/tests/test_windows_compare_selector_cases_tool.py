from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_compare_selector_cases import build_tool


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


def test_windows_compare_selector_cases_reports_case_differences(
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
            selector="infoClass",
            gate_kind="user_pointer",
            sink_kind="copy",
            pseudocode="""
NTSTATUS NtExample(ULONG infoClass, void *out, ULONG len) {
    switch (infoClass) {
    case 1:
        ProbeForWrite(out, len, 1);
        RtlCopyMemory(out, SourceA, len);
        break;
    case 2:
        RtlCopyMemory(out, SourceB, len);
        break;
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
}
""",
            add_to_kb=True,
        ),
    )

    assert result.selector_expression == "infoClass"
    assert [case.label for case in result.cases] == ["case 1", "case 2", "default"]
    assert result.cases[0].operation_ids == ["rtl_copy_memory"]
    assert result.cases[0].gate_ids == ["probeforwrite"]
    assert result.cases[1].operation_ids == ["rtl_copy_memory"]
    assert result.cases[1].gate_ids == []
    assert any(
        diff.kind == "gate_missing_in_cases"
        and diff.item_id == "probeforwrite"
        and "case 2" in diff.missing_cases
        for diff in result.differences
    )
    assert any(
        diff.kind == "sink_without_gate"
        and diff.item_id == "rtl_copy_memory"
        and diff.present_cases == ["case 2"]
        for diff in result.differences
    )
    assert "selector comparison uses pseudocode" in result.notes[-1]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_compare_selector_cases"
        for node in ctx.kb.nodes()
    )


def test_windows_compare_selector_cases_handles_absent_switch(tmp_path: Path) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            gates_path=str(gates),
            sinks_path=str(sinks),
            pseudocode="void Helper(void *out) { RtlCopyMemory(out, Src, 4); }",
        ),
    )

    assert result.selector_expression is None
    assert result.cases == []
    assert result.differences == []
    assert "no switch/case blocks found" in result.notes


def test_memory_agent_registers_windows_compare_selector_cases() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_compare_selector_cases" in agent._function_toolset.tools
