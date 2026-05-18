from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_callsite_operand_facts import build_tool


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
  effects: [releases_pool_memory, invalidates_pointer]
  arg_roles:
    0: object_pointer
  required_gates: [ownership_established, no_later_use]
""",
        encoding="utf-8",
    )
    return sinks


def test_windows_callsite_operand_facts_attaches_operation_roles(
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
NTSTATUS Handler(void *dst, void *src, ULONG len) {
    RtlCopyMemory(dst, src, len); // callsite: 0x140001234
    ExFreePool((void *)dst);
    return STATUS_SUCCESS;
}
""",
            operation_only=True,
            add_to_kb=True,
        ),
    )

    assert result.pseudocode_source == "supplied_pseudocode"
    assert result.scanned_call_count >= 2
    assert [site.operation.id for site in result.callsites if site.operation] == [
        "rtl_copy_memory",
        "ex_free_pool",
    ]
    copy = result.callsites[0]
    assert copy.symbol == "RtlCopyMemory"
    assert copy.callsite_va == 0x140001234
    assert [arg.role for arg in copy.arguments] == [
        "destination_buffer",
        "source_buffer",
        "byte_count",
    ]
    assert copy.arguments[2].expression == "len"
    assert copy.arguments[2].normalized_expression == "len"
    assert copy.operation is not None
    assert "byte_count_bounded" in copy.operation.required_gates
    free = result.callsites[1]
    assert free.arguments[0].expression == "(void *)dst"
    assert free.arguments[0].normalized_expression == "dst"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_callsite_operand_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_callsite_operand_facts_filters_by_symbol(tmp_path: Path) -> None:
    sinks = _write_sinks(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sinks_path=str(sinks),
            call_symbol="nt!RtlCopyMemory",
            pseudocode="""
RtlCopyMemory(dst, src, len);
ExFreePool(dst);
""",
        ),
    )

    assert [site.symbol for site in result.callsites] == ["RtlCopyMemory"]
    assert result.callsites[0].matched_symbol == "RtlCopyMemory"
    assert result.callsites[0].arguments[1].role == "source_buffer"


def test_windows_callsite_operand_facts_can_return_unclassified_calls(
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
Helper(dst, len);
RtlCopyMemory(dst, src, len);
""",
        ),
    )

    assert [site.symbol for site in result.callsites] == ["Helper", "RtlCopyMemory"]
    assert result.callsites[0].operation is None
    assert result.callsites[0].arguments[1].role is None
    assert result.callsites[1].operation is not None


def test_memory_agent_registers_windows_callsite_operand_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_callsite_operand_facts" in agent._function_toolset.tools
