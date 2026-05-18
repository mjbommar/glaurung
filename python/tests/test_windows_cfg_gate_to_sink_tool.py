from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_cfg_gate_to_sink import build_tool


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


def _cfg(bypass: bool = False) -> list[dict]:
    entry_successors = ["gate", "sink"] if bypass else ["gate"]
    sink_predecessors = ["gate", "entry"] if bypass else ["gate"]
    return [
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


def test_windows_cfg_gate_to_sink_reports_dominated_gate(tmp_path: Path) -> None:
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
            gate_va=0x2010,
            sink_va=0x3010,
            cfg_blocks=_cfg(),
            add_to_kb=True,
        ),
    )

    assert result.status == "dominated"
    assert result.suggested_packet_gate_status == "dominated"
    assert result.gate.gate is not None
    assert result.gate.gate.id == "probeforwrite"
    assert result.sink.operation is not None
    assert result.sink.operation.id == "rtl_copy_memory"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_cfg_gate_to_sink"
        for node in ctx.kb.nodes()
    )


def test_windows_cfg_gate_to_sink_reports_not_dominated_gate(
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
            gate_symbol="ProbeForWrite",
            sink_symbol="RtlCopyMemory",
            gate_va=0x2010,
            sink_va=0x3010,
            cfg_blocks=_cfg(bypass=True),
        ),
    )

    assert result.status == "not_dominated"
    assert result.suggested_packet_gate_status == "not_dominated"
    assert "does not pass through gate block" in result.reason


def test_windows_cfg_gate_to_sink_reports_missing_metadata(tmp_path: Path) -> None:
    gates, sinks = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            gates_path=str(gates),
            sinks_path=str(sinks),
            gate_symbol="MissingGate",
            sink_symbol="RtlCopyMemory",
            gate_va=0x2010,
            sink_va=0x3010,
            cfg_blocks=_cfg(),
        ),
    )

    assert result.status == "missing_metadata"
    assert result.suggested_packet_gate_status == "unknown"
    assert "MissingGate" in result.reason


def test_memory_agent_registers_windows_cfg_gate_to_sink() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_cfg_gate_to_sink" in agent._function_toolset.tools
