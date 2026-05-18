from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_operation_gate_summary import build_tool


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


def _write_gates(tmp_path: Path) -> Path:
    gates = tmp_path / "pe-gates.yaml"
    gates.write_text(
        """
- id: probeforwrite
  symbols: [ProbeForWrite]
  gate_kind: user_pointer
  proves: [user_pointer_write_range_valid]
  invalid_when: [length_is_zero]
  required_conditions: [call_dominates_write_sink]
""",
        encoding="utf-8",
    )
    return gates


def _write_project(tmp_path: Path) -> Path:
    project = tmp_path / "driver.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
CREATE TABLE xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    kind TEXT,
    src_va INTEGER,
    src_function_va INTEGER,
    dst_va INTEGER
);
CREATE TABLE function_names (
    binary_id INTEGER,
    entry_va INTEGER,
    canonical TEXT,
    demangled TEXT
);
CREATE TABLE basic_blocks (
    binary_id INTEGER,
    function_va INTEGER,
    block_id TEXT,
    start_va INTEGER,
    end_va INTEGER
);
CREATE TABLE cfg_edges (
    binary_id INTEGER,
    function_va INTEGER,
    src_block_id TEXT,
    dst_block_id TEXT
);
"""
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x2000, "OtherDispatch"),
                (0x4000, "ProbeForWrite"),
                (0x5000, "RtlCopyMemory"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, 'call', ?, ?, ?)",
            [
                (1, 0x1100, 0x1000, 0x4000),
                (2, 0x1200, 0x1000, 0x5000),
                (3, 0x2100, 0x2000, 0x5000),
            ],
        )
        conn.executemany(
            "INSERT INTO basic_blocks VALUES (1, ?, ?, ?, ?)",
            [
                (0x1000, "entry", 0x1000, 0x1100),
                (0x1000, "gate", 0x1100, 0x1180),
                (0x1000, "sink", 0x1180, 0x1280),
                (0x2000, "entry2", 0x2000, 0x2200),
            ],
        )
        conn.executemany(
            "INSERT INTO cfg_edges VALUES (1, ?, ?, ?)",
            [
                (0x1000, "entry", "gate"),
                (0x1000, "gate", "sink"),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_operation_gate_summary_aggregates_gate_coverage(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            binary="driver.sys",
            build="unit-test",
            sinks_path=str(_write_sinks(tmp_path)),
            gates_path=str(_write_gates(tmp_path)),
            add_to_kb=True,
        ),
    )

    assert result.packet_count == 2
    assert result.operation_gate_group_count == 1
    assert result.gate_refinement_count == 1
    assert result.gate_missing_required_count == 1
    group = result.groups[0]
    assert group.sink_kind == "copy"
    assert group.sink_symbol == "RtlCopyMemory"
    assert group.packet_count == 2
    assert group.fully_proven_packet_count == 0
    assert group.partially_proven_packet_count == 1
    assert group.unproven_packet_count == 1
    assert group.gate_status_counts == {"unknown": 2}
    assert group.required_gates == ["destination_range_valid", "byte_count_bounded"]
    assert group.proven_gates == ["destination_range_valid"]
    assert group.missing_required_gates == [
        "byte_count_bounded",
        "destination_range_valid",
    ]
    assert [sample.sink_symbol for sample in group.sample_packets] == [
        "RtlCopyMemory",
        "RtlCopyMemory",
    ]
    assert "project_operation_gate_summary" in result.coverage
    assert "operation_missing_required_gate_summary" in result.coverage
    assert "source_reachability" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_operation_gate_summary"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_project_operation_gate_summary() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_operation_gate_summary" in agent._function_toolset.tools
