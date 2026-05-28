from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_operation_source_summary import build_tool


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


def _write_sources(tmp_path: Path) -> Path:
    sources = tmp_path / "pe-sources.yaml"
    sources.write_text(
        """
- id: driver_dispatch_user_buffer
  surface: ioctl
  symbols: [DriverDispatch]
  attacker_class: windows-local-user
  roles:
    - index: 0
      role: buffer
""",
        encoding="utf-8",
    )
    return sources


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
"""
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x2000, "OtherDispatch"),
                (0x5000, "RtlCopyMemory"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, 'call', ?, ?, ?)",
            [
                (1, 0x1200, 0x1000, 0x5000),
                (2, 0x2200, 0x2000, 0x5000),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_operation_source_summary_aggregates_inferred_sources(
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
            sources_path=str(_write_sources(tmp_path)),
            add_to_kb=True,
        ),
    )

    assert result.packet_count == 2
    assert result.operation_source_group_count == 1
    assert result.source_role_inference_count == 1
    assert result.source_value_match_count == 0
    assert result.source_refinement_status_counts == {"inferred": 1, "missing": 1}
    group = result.groups[0]
    assert group.sink_kind == "copy"
    assert group.sink_symbol == "RtlCopyMemory"
    assert group.packet_count == 2
    assert group.source_refinement_status_counts == {"inferred": 1, "missing": 1}
    assert group.matched_packet_count == 0
    assert group.inferred_packet_count == 1
    assert group.missing_packet_count == 1
    assert group.source_roles == ["buffer"]
    assert any(
        "no local sink argument snapshot available" in blocker
        for blocker in group.source_refinement_blockers
    )
    assert "project_operation_source_summary" in result.coverage
    assert "operation_source_role_inference_summary" in result.coverage
    assert "operation_source_value_match_summary" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_operation_source_summary"
        for node in ctx.kb.nodes()
    )


def test_windows_project_operation_source_summary_aggregates_matched_sources(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")

    def fake_disassemble_window_at(_path, start_va, **_kwargs):
        if start_va == 0x1000:
            return [
                _Insn(0x1000, "mov", ["rdx", "rcx"]),
                _Insn(0x1200, "call", ["0x5000"]),
            ]
        return []

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            binary_path=str(binary),
            binary="driver.sys",
            build="unit-test",
            sinks_path=str(_write_sinks(tmp_path)),
            sources_path=str(_write_sources(tmp_path)),
            function_va=0x1000,
        ),
    )

    assert result.packet_count == 1
    assert result.source_role_inference_count == 1
    assert result.source_value_match_count == 1
    assert result.source_refinement_status_counts == {"matched": 1}
    group = result.groups[0]
    assert group.matched_packet_count == 1
    assert group.inferred_packet_count == 0
    assert group.missing_packet_count == 0
    assert group.source_roles == ["buffer"]
    assert group.source_args == ["caller_arg0"]
    assert "operation_source_value_match_summary" in result.coverage


def test_memory_agent_registers_windows_project_operation_source_summary() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_operation_source_summary" in agent._function_toolset.tools


class _Addr:
    def __init__(self, value: int) -> None:
        self.value = value


class _Insn:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Addr(va)
        self.mnemonic = mnemonic
        self.operands = operands
