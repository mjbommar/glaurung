from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_call_argument_snapshot import build_tool


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


def test_windows_project_call_argument_snapshot_recovers_register_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "lea", ["rdx", "[rbp - 0x40]"]),
            _Insn(0x1008, "xor", ["r8d", "r8d"]),
            _Insn(0x100C, "mov", ["r9", "0x20"]),
            _Insn(0x1014, "call", ["0x2000"]),
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
    assert [(arg.register_name, arg.expression) for arg in result.arguments] == [
        ("rcx", "rdi"),
        ("rdx", "[rbp - 0x40]"),
        ("r8", "0"),
        ("r9", "0x20"),
    ]
    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[1].alias_kind == "stack_local_address"
    assert "windows_x64_register_arguments" in result.coverage
    assert "stack_local_address_arguments" in result.coverage
    assert "stack_arguments" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_call_argument_snapshot"
        for node in ctx.kb.nodes()
    )


def test_windows_project_call_argument_snapshot_recovers_stack_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["qword ptr [rsp + 0x20]", "rax"]),
            _Insn(0x1008, "mov", ["dword ptr [rsp+28h]", "0x40"]),
            _Insn(0x100C, "mov", ["qword ptr [rsp + 0x18]", "0xdead"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    stack_args = [arg for arg in result.arguments if arg.location == "stack"]
    stack_arg_rows = [
        (arg.index, arg.register_name, arg.stack_offset, arg.expression)
        for arg in stack_args
    ]
    assert stack_arg_rows == [
        (4, "stack+0x20", 0x20, "rax"),
        (5, "stack+0x28", 0x28, "0x40"),
    ]
    assert "windows_x64_stack_arguments" in result.coverage
    assert "stack_arguments" not in result.missing_capabilities


def test_windows_project_call_argument_snapshot_resolves_simple_aliases(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rax", "[rbp - 0x40]"]),
            _Insn(0x1004, "mov", ["r10", "0x80"]),
            _Insn(0x1008, "mov", ["rcx", "rax"]),
            _Insn(0x100C, "mov", ["qword ptr [rsp + 0x20]", "r10"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[0].expression == "[rbp - 0x40]"
    assert by_index[0].source_text == "mov rcx, rax"
    assert by_index[0].alias_depth == 1
    assert by_index[0].alias_kind == "register"
    assert by_index[4].expression == "0x80"
    assert by_index[4].source_text == "mov qword ptr [rsp + 0x20], r10"
    assert by_index[4].alias_depth == 1
    assert by_index[4].alias_kind == "register"
    assert "simple_register_aliases" in result.coverage
    assert "full_alias_tracking" in result.missing_capabilities


def test_windows_project_call_argument_snapshot_recovers_spill_reload(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rax", "[rdi + 0x30]"]),
            _Insn(0x1004, "mov", ["qword ptr [rbp - 0x40]", "rax"]),
            _Insn(0x1008, "mov", ["rcx", "qword ptr [rbp-40h]"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[0].expression == "[rdi + 0x30]"
    assert by_index[0].source_text == "mov rcx, qword ptr [rbp-40h]"
    assert by_index[0].alias_depth == 2
    assert by_index[0].alias_kind == "frame_slot"
    assert "simple_spill_reload_aliases" in result.coverage
    assert "full_alias_tracking" in result.missing_capabilities


def test_windows_project_call_argument_snapshot_resolves_memory_load_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rax", "qword ptr [rcx + 0x20]"]),
            _Insn(0x1004, "mov", ["rdx", "rax"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[1].expression == "load([caller_arg0 + 0x20])"
    assert by_index[1].source_text == "mov rdx, rax"
    assert by_index[1].alias_depth == 2
    assert by_index[1].alias_kind == "memory_load"
    assert "memory_load_arguments" in result.coverage


def test_windows_project_call_argument_snapshot_resolves_incoming_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rdx", "rcx"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[1].expression == "caller_arg0"
    assert by_index[1].source_text == "mov rdx, rcx"
    assert by_index[1].alias_depth == 1
    assert by_index[1].alias_kind == "incoming_arg"
    assert "incoming_argument_aliases" in result.coverage


def test_windows_project_call_argument_snapshot_resolves_derived_address_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["rdx", "[rcx + 0x20]"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[1].expression == "[caller_arg0 + 0x20]"
    assert by_index[1].source_text == "lea rdx, [rcx + 0x20]"
    assert by_index[1].alias_depth == 1
    assert by_index[1].alias_kind == "derived_address"
    assert "derived_address_arguments" in result.coverage


def test_windows_project_call_argument_snapshot_labels_global_address_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["rcx", "[rip + 0x1234]"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[0].expression == "global([rip + 0x1234])"
    assert by_index[0].source_text == "lea rcx, [rip + 0x1234]"
    assert by_index[0].alias_depth == 0
    assert by_index[0].alias_kind == "global_address"
    assert "global_address_arguments" in result.coverage


def test_windows_project_call_argument_snapshot_joins_global_data_xrefs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)
    conn = sqlite3.connect(project)
    conn.execute(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        (2, 1, 0x1000, 0x3000, "data_read", 0x1000),
    )
    conn.commit()
    conn.close()

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["rcx", "[rip + 0x1234]"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[0].expression == "global([rip + 0x1234])"
    assert by_index[0].data_target_va == 0x3000
    assert by_index[0].data_target_kind == "data_read"
    assert "project_data_xref_targets" in result.coverage


def test_windows_project_call_argument_snapshot_preserves_clobbered_address_base(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "add", ["rcx", "0x10"]),
            _Insn(0x1004, "lea", ["rdx", "[rcx + 0x20]"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[1].expression == "[rcx + 0x20]"
    assert by_index[1].source_text == "lea rdx, [rcx + 0x20]"
    assert by_index[1].alias_depth == 0
    assert by_index[1].alias_kind is None
    assert "derived_address_arguments" not in result.coverage


def test_windows_project_call_argument_snapshot_invalidates_clobbered_incoming_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "add", ["rcx", "0x10"]),
            _Insn(0x1004, "mov", ["rdx", "rcx"]),
            _Insn(0x1014, "call", ["0x2000"]),
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

    by_index = {arg.index: arg for arg in result.arguments}
    assert by_index[1].expression == "rcx"
    assert by_index[1].source_text == "mov rdx, rcx"
    assert by_index[1].alias_depth == 0
    assert by_index[1].alias_kind is None
    assert "incoming_argument_aliases" not in result.coverage


def test_memory_agent_registers_windows_project_call_argument_snapshot() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_call_argument_snapshot" in agent._function_toolset.tools
