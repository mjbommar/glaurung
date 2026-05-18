from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_operation_metadata import build_tool


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


def test_windows_operation_metadata_filters_by_symbol_and_adds_evidence(
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
            symbol="RtlCopyMemory",
            add_to_kb=True,
        ),
    )

    assert result.operation_count_total == 2
    assert [op.id for op in result.operations] == ["rtl_copy_memory"]
    assert result.operations[0].sink_kind == "copy"
    assert result.operations[0].arg_roles[2].role == "byte_count"
    assert "byte_count_bounded" in result.operations[0].required_gates
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_operation_metadata"
        for node in ctx.kb.nodes()
    )


def test_windows_operation_metadata_filters_by_kind(tmp_path: Path) -> None:
    sinks = _write_sinks(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(sinks_path=str(sinks), sink_kind="completion"),
    )

    assert [op.id for op in result.operations] == ["io_complete_request"]
    assert "transfers_irp_ownership" in result.operations[0].effects
    assert result.operations[0].arg_roles[0].role == "irp"


def test_memory_agent_registers_windows_operation_metadata() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_operation_metadata" in agent._function_toolset.tools
