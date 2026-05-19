from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_return_value_use_snapshot import build_tool


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
    project = tmp_path / "sample.glaurung"
    conn = sqlite3.connect(project)
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
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
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
        "INSERT INTO binaries VALUES (1, 'abc', 'sample.sys', 'PE', 'x86_64', 64, 1, 0)"
    )
    conn.executemany(
        "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, ?, ?)",
        [
            (1, 0x1000, "cldflt!Caller", "pdb", None, None),
            (1, 0x2000, "cldflt!Callee", "pdb", None, None),
        ],
    )
    conn.execute(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        (1, 1, 0x1014, 0x2000, "call", 0x1000),
    )
    conn.commit()
    conn.close()
    return project


def test_windows_project_return_value_use_snapshot_recovers_check_and_branch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1014, "call", ["0x2000"]),
            _Insn(0x1019, "test", ["rax", "rax"]),
            _Insn(0x101C, "je", ["0x1030"]),
            _Insn(0x1020, "mov", ["rcx", "rax"]),
        ]

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            callsite_va=0x1014,
            add_to_kb=True,
        ),
    )

    assert result.caller_name == "cldflt!Caller"
    assert result.callee_name == "cldflt!Callee"
    assert result.callsite_text == "call 0x2000"
    assert result.first_use_kind == "null_or_status_check"
    assert result.uses[0].instruction_va == 0x1019
    assert result.uses[0].branch_va == 0x101C
    assert result.uses[0].branch_text == "je 0x1030"
    assert "return_value_check" in result.coverage
    assert "adjacent_branch_relation" in result.coverage
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_return_value_use_snapshot"
        for node in ctx.kb.nodes()
    )


def test_windows_project_return_value_use_snapshot_tracks_argument_use(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1014, "call", ["0x2000"]),
            _Insn(0x1019, "mov", ["rcx", "rax"]),
            _Insn(0x101D, "call", ["0x3000"]),
        ]

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            callsite_va=0x1014,
        ),
    )

    assert [use.use_kind for use in result.uses] == [
        "stored_to_register",
        "passed_as_argument",
    ]
    assert result.uses[0].expression == "rcx"
    assert result.uses[1].argument_role == "arg0"
    assert "return_value_store" in result.coverage
    assert "return_value_argument_use" in result.coverage


def test_windows_project_return_value_use_snapshot_reports_clobber(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1014, "call", ["0x2000"]),
            _Insn(0x1019, "xor", ["eax", "eax"]),
        ]

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            callsite_va=0x1014,
        ),
    )

    assert result.first_use_kind == "clobbered_by_zeroing"
    assert result.uses[0].instruction_text == "xor eax, eax"
    assert "return_value_clobber" in result.coverage


def test_memory_agent_registers_windows_project_return_value_use_snapshot() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_return_value_use_snapshot" in agent._function_toolset.tools
