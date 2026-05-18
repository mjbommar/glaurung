from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_summarize_helper_side_effects import build_tool


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
- id: ex_free_pool
  symbols: [ExFreePool, ExFreePoolWithTag]
  sink_kind: free
  effects: [frees_allocation]
  arg_roles:
    0: allocation_pointer
  required_gates: [allocation_owned]
""",
        encoding="utf-8",
    )
    return sinks


def test_windows_summarize_helper_side_effects_maps_params_to_copy(
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
            pseudocode="""
NTSTATUS Helper(void *out, void *src, ULONG len) {
    void *dst = out;
    RtlCopyMemory(dst, src, len);
    return STATUS_SUCCESS;
}
""",
            add_to_kb=True,
        ),
    )

    assert result.helper_name == "Helper"
    assert [param.name for param in result.parameters] == ["out", "src", "len"]
    assert len(result.side_effects) == 1
    effect = result.side_effects[0]
    assert effect.operation.id == "rtl_copy_memory"
    assert "destination_buffer=helper_arg0:out" in effect.summary
    assert "source_buffer=helper_arg1:src" in effect.summary
    assert "byte_count=helper_arg2:len" in effect.summary
    assert effect.parameter_impacts[0].parameter.name == "out"
    assert effect.parameter_impacts[0].call_arg_role == "destination_buffer"
    assert "side-effect summary uses pseudocode" in result.notes[-1]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_summarize_helper_side_effects"
        for node in ctx.kb.nodes()
    )


def test_windows_summarize_helper_side_effects_filters_kind(
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
            sink_kind="free",
            helper_name="Cleanup",
            pseudocode="""
void Cleanup(void *ptr, void *out, ULONG len) {
    RtlCopyMemory(out, GlobalBuffer, len);
    ExFreePoolWithTag(ptr, 'tseT');
}
""",
        ),
    )

    assert result.helper_name == "Cleanup"
    assert len(result.side_effects) == 1
    effect = result.side_effects[0]
    assert effect.operation.id == "ex_free_pool"
    assert effect.parameter_impacts[0].parameter.name == "ptr"
    assert effect.parameter_impacts[0].call_arg_role == "allocation_pointer"


def test_memory_agent_registers_windows_summarize_helper_side_effects() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_summarize_helper_side_effects" in agent._function_toolset.tools
