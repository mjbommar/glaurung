from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_trace_onehop_flow import HelperPseudocode, build_tool


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
  symbols: [ExFreePool]
  sink_kind: free
  effects: [releases_pool_memory]
  arg_roles:
    0: object_pointer
  required_gates: [ownership_established]
""",
        encoding="utf-8",
    )
    return sinks


def test_windows_trace_onehop_flow_tracks_caller_arg_into_helper_sink(
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
            caller_pseudocode="""
NTSTATUS Handler(void *dst, void *user_buffer, ULONG len) {
    void *captured = user_buffer;
    CopyOut(dst, captured, len);
    return STATUS_SUCCESS;
}
""",
            helpers=[
                HelperPseudocode(
                    name="CopyOut",
                    pseudocode="""
void CopyOut(void *dst, void *input, ULONG len) {
    void *tmp = input;
    RtlCopyMemory(dst, tmp, len);
}
""",
                )
            ],
            add_to_kb=True,
        ),
    )

    assert result.source_name == "user_buffer"
    assert [(alias.name, alias.source) for alias in result.caller_aliases] == [
        ("captured", "user_buffer")
    ]
    assert result.scanned_caller_call_count >= 1
    assert len(result.flows) == 1
    flow = result.flows[0]
    assert flow.helper == "CopyOut"
    assert flow.caller_arg_index == 1
    assert flow.caller_expression == "captured"
    assert flow.helper_source_name == "input"
    assert [(alias.name, alias.source) for alias in flow.helper_aliases] == [
        ("tmp", "input")
    ]
    assert flow.sink_flow.callee == "RtlCopyMemory"
    assert flow.sink_flow.callee_arg_index == 1
    assert flow.sink_flow.operation is not None
    assert flow.sink_flow.operation.id == "rtl_copy_memory"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_trace_onehop_flow"
        for node in ctx.kb.nodes()
    )


def test_windows_trace_onehop_flow_accepts_explicit_source_name(
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
            source_name="irp",
            caller_pseudocode="""
void Dispatch(void *irp) {
    Cleanup(irp);
}
""",
            helpers=[
                HelperPseudocode(
                    name="Cleanup",
                    pseudocode="""
void Cleanup(void *request) {
    ExFreePool(request);
}
""",
                )
            ],
        ),
    )

    assert len(result.flows) == 1
    assert result.flows[0].helper_source_name == "request"
    assert result.flows[0].sink_flow.operation is not None
    assert result.flows[0].sink_flow.operation.id == "ex_free_pool"


def test_memory_agent_registers_windows_trace_onehop_flow() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_trace_onehop_flow" in agent._function_toolset.tools
