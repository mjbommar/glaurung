from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_helper_argument_summary import build_tool


class _Addr:
    def __init__(self, value: int) -> None:
        self.value = value


class _Insn:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Addr(va)
        self.mnemonic = mnemonic
        self.operands = operands


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_project(tmp_path: Path) -> Path:
    project = tmp_path / "driver.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
CREATE TABLE binaries (
    binary_id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL,
    first_path TEXT,
    format TEXT,
    arch TEXT,
    bits INTEGER,
    size_bytes INTEGER,
    discovered_at INTEGER
);
CREATE TABLE function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    demangled TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    src_va INTEGER NOT NULL,
    dst_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    src_function_va INTEGER,
    indexed_at INTEGER
);
"""
        )
        conn.execute(
            "INSERT INTO binaries VALUES (1, 'sha256', 'driver.sys', 'PE', 'x86_64', 64, 16, 0)"
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x2000, "CopyHelper"),
                (0x5000, "RtlCopyMemory"),
                (0x6000, "RtlMoveMemory"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, ?, ?, ?, ?, 0)",
            [
                (1, 0x1100, 0x2000, "call", 0x1000),
                (2, 0x2100, 0x5000, "call", 0x2000),
                (3, 0x2120, 0x6000, "call", 0x2000),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def _write_sinks(tmp_path: Path) -> Path:
    sinks = tmp_path / "pe-sinks.yaml"
    sinks.write_text(
        """
- id: rtl_copy_memory
  symbols: [RtlCopyMemory, RtlMoveMemory]
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


def test_windows_project_helper_argument_summary_aggregates_sink_uses(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    def fake_disassemble_window_at(_path, start_va, **_kwargs):
        if start_va == 0x1000:
            return [
                _Insn(0x1000, "mov", ["rcx", "rdi"]),
                _Insn(0x1004, "mov", ["rdx", "rsi"]),
                _Insn(0x1100, "call", ["0x2000"]),
            ]
        if start_va == 0x2000:
            return [
                _Insn(0x2000, "mov", ["rcx", "r8"]),
                _Insn(0x2004, "mov", ["rdx", "rdx"]),
                _Insn(0x2008, "mov", ["r8", "0x40"]),
                _Insn(0x2100, "call", ["0x5000"]),
                _Insn(0x2110, "mov", ["rcx", "r9"]),
                _Insn(0x2114, "mov", ["rdx", "rdx"]),
                _Insn(0x2118, "mov", ["r8", "0x20"]),
                _Insn(0x2120, "call", ["0x6000"]),
            ]
        return []

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(_write_project(tmp_path)),
            sinks_path=str(_write_sinks(tmp_path)),
            caller_function_name="DriverDispatch",
            source_arg_index=1,
            add_to_kb=True,
        ),
    )

    assert result.scanned_flow_count == 2
    assert result.summary_count == 1
    summary = result.summaries[0]
    assert summary.caller_name == "DriverDispatch"
    assert summary.helper_name == "CopyHelper"
    assert summary.helper_arg_index == 1
    assert summary.helper_arg_register == "rdx"
    assert summary.caller_arg_expression == "rsi"
    assert summary.matched_sink_count == 2
    assert summary.sink_symbols == ["RtlCopyMemory", "RtlMoveMemory"]
    assert summary.sink_kinds == ["copy"]
    assert summary.sink_arg_roles == ["source_buffer"]
    assert summary.sink_callsite_vas == [0x2100, 0x2120]
    assert summary.sink_effects == ["writes_destination_range", "reads_source_range"]
    assert summary.required_gates == ["destination_range_valid", "byte_count_bounded"]
    assert "helper_argument_sink_use_summary" in result.coverage
    assert "helper_arg_required_gate_summary" in result.coverage
    assert "general_helper_side_effect_summaries" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_helper_argument_summary"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_project_helper_argument_summary() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_helper_argument_summary" in agent._function_toolset.tools
