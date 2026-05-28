from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_list_operation_sinks import build_tool


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
- id: io_complete_request
  symbols: [IoCompleteRequest]
  sink_kind: completion
  effects: [completes_irp, transfers_irp_ownership]
  arg_roles:
    0: irp
    1: priority_boost
  required_gates: [no_later_irp_access]
""",
        encoding="utf-8",
    )
    return sinks


def test_windows_list_operation_sinks_from_supplied_pseudocode(
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
NTSTATUS example(void *dst, void *src, ULONG len) {
    RtlCopyMemory(dst, src, len);
    if (len == 0) {
        ExFreePool(dst);
    }
    return STATUS_SUCCESS;
}
""",
            add_to_kb=True,
        ),
    )

    assert result.pseudocode_source == "supplied_pseudocode"
    assert result.scanned_call_count >= 3
    assert [sink.operation.id for sink in result.sinks] == [
        "rtl_copy_memory",
        "ex_free_pool",
    ]
    assert result.sinks[0].line == 3
    assert result.sinks[0].operation.arg_roles[2].role == "byte_count"
    assert "byte_count_bounded" in result.sinks[0].operation.required_gates
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_list_operation_sinks"
        for node in ctx.kb.nodes()
    )


def test_windows_list_operation_sinks_filters_by_kind(tmp_path: Path) -> None:
    sinks = _write_sinks(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sinks_path=str(sinks),
            pseudocode="""
IoCompleteRequest(Irp, IO_NO_INCREMENT);
ExFreePoolWithTag(buffer, 'tag');
""",
            sink_kind="completion",
        ),
    )

    assert [sink.operation.id for sink in result.sinks] == ["io_complete_request"]
    assert result.sinks[0].matched_text == "IoCompleteRequest"
    assert "transfers_irp_ownership" in result.sinks[0].operation.effects


def test_memory_agent_registers_windows_list_operation_sinks() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_list_operation_sinks" in agent._function_toolset.tools
