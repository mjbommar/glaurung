from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_source_sink_operand_match import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_sinks(tmp_path: Path) -> Path:
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
    return sinks


def test_windows_source_sink_operand_match_reports_alias(
    tmp_path: Path,
) -> None:
    sinks = _write_sinks(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sinks_path=str(sinks),
            source_arg_index=1,
            sink_symbol="RtlCopyMemory",
            sink_arg_index=1,
            pseudocode="""
NTSTATUS Handler(void *dst, void *user_buffer, ULONG len) {
    void *captured = user_buffer;
    RtlCopyMemory(dst, captured, len);
    return STATUS_SUCCESS;
}
""",
            add_to_kb=True,
        ),
    )

    assert result.source_name == "user_buffer"
    assert result.status == "alias"
    assert result.matched_name == "captured"
    assert result.sink is not None
    assert result.sink.arg_role == "source_buffer"
    assert result.sink.operation is not None
    assert result.sink.operation.id == "rtl_copy_memory"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_source_sink_operand_match"
        for node in ctx.kb.nodes()
    )


def test_windows_source_sink_operand_match_reports_transformed(
    tmp_path: Path,
) -> None:
    sinks = _write_sinks(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sinks_path=str(sinks),
            source_name="len",
            sink_symbol="RtlCopyMemory",
            sink_arg_index=2,
            pseudocode="""
void Handler(void *dst, void *src, ULONG len) {
    RtlCopyMemory(dst, src, len + 4);
}
""",
        ),
    )

    assert result.status == "transformed"
    assert result.matched_name == "len"
    assert result.sink is not None
    assert result.sink.arg_role == "byte_count"


def test_windows_source_sink_operand_match_reports_mismatch(
    tmp_path: Path,
) -> None:
    sinks = _write_sinks(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sinks_path=str(sinks),
            source_name="user_buffer",
            sink_symbol="RtlCopyMemory",
            sink_arg_index=1,
            pseudocode="""
void Handler(void *dst, void *user_buffer, void *kernel_buffer, ULONG len) {
    RtlCopyMemory(dst, kernel_buffer, len);
}
""",
        ),
    )

    assert result.status == "mismatch"
    assert result.matched_name is None
    assert "does not reference traced source" in result.reason


def test_memory_agent_registers_windows_source_sink_operand_match() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_source_sink_operand_match" in agent._function_toolset.tools
