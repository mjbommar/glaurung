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
CREATE TABLE data_labels (
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    name TEXT NOT NULL,
    c_type TEXT,
    size INTEGER,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].value_role == "local_pointer"
    assert by_index[2].value_role == "zero_or_null"
    assert by_index[3].value_role == "integer_constant"
    assert "windows_x64_register_arguments" in result.coverage
    assert "stack_local_address_arguments" in result.coverage
    assert "argument_value_roles" in result.coverage
    assert "stack_arguments" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_call_argument_snapshot"
        for node in ctx.kb.nodes()
    )


def test_windows_project_call_argument_snapshot_resolves_rsp_stack_local_address(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "sub", ["rsp", "0x80"]),
            _Insn(0x1004, "lea", ["rdx", "[rsp + 0x30]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].expression == "stack_local([rsp + 0x30])"
    assert by_index[1].source_text == "lea rdx, [rsp + 0x30]"
    assert by_index[1].alias_kind == "stack_local_address"
    assert by_index[1].value_role == "local_pointer"
    assert "stack_local_address_arguments" in result.coverage


def test_windows_project_call_argument_snapshot_does_not_mark_home_space_local(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["rdx", "[rsp + 0x20]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].expression == "[rsp + 0x20]"
    assert by_index[1].alias_kind is None
    assert "stack_local_address_arguments" not in result.coverage


def test_windows_project_call_argument_snapshot_can_persist_project_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "xor", ["r9d", "r9d"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            callsite_va=0x1014,
            persist_to_project=True,
        ),
    )

    assert "project_persisted_callsite_arguments" in result.coverage
    conn = sqlite3.connect(project)
    try:
        rows = conn.execute(
            "SELECT callsite_va, argument_index, register_name, expression, value_role "
            "FROM callsite_argument_facts ORDER BY argument_index"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [
        (0x1014, 0, "rcx", "rdi", None),
        (0x1014, 3, "r9", "0", "zero_or_null"),
    ]


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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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


def test_windows_project_call_argument_snapshot_recovers_rsp_spill_reload(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "sub", ["rsp", "0x80"]),
            _Insn(0x1004, "mov", ["rax", "qword ptr [rcx + 0x20]"]),
            _Insn(0x1008, "mov", ["qword ptr [rsp + 0x10]", "rax"]),
            _Insn(0x100C, "mov", ["rdx", "qword ptr [rsp + 0x10]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].source_text == "mov rdx, qword ptr [rsp + 0x10]"
    assert by_index[1].alias_depth == 3
    assert by_index[1].alias_kind == "frame_slot"
    assert "simple_spill_reload_aliases" in result.coverage
    assert "memory_load_arguments" not in result.coverage


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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].value_role == "field_derived"
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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].value_role == "caller_argument"
    assert "incoming_argument_aliases" in result.coverage


def test_windows_project_call_argument_snapshot_resolves_incoming_stack_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "sub", ["rsp", "0x40"]),
            _Insn(0x1004, "mov", ["rax", "qword ptr [rsp + 0x68]"]),
            _Insn(0x1008, "mov", ["rcx", "rax"]),
            _Insn(0x100C, "mov", ["rdx", "qword ptr [rsp + 0x70]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[0].expression == "caller_arg4"
    assert by_index[0].source_text == "mov rcx, rax"
    assert by_index[0].alias_depth == 2
    assert by_index[0].alias_kind == "incoming_stack_arg"
    assert by_index[0].value_role == "caller_argument"
    assert by_index[1].expression == "caller_arg5"
    assert by_index[1].source_text == "mov rdx, qword ptr [rsp + 0x70]"
    assert by_index[1].alias_depth == 1
    assert by_index[1].alias_kind == "incoming_stack_arg"
    assert "incoming_stack_argument_aliases" in result.coverage


def test_windows_project_call_argument_snapshot_forwards_incoming_stack_arg_to_stack(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "sub", ["rsp", "0x40"]),
            _Insn(0x1004, "mov", ["rax", "qword ptr [rsp + 0x68]"]),
            _Insn(0x1008, "mov", ["qword ptr [rsp + 0x20]", "rax"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[4].location == "stack"
    assert by_index[4].stack_offset == 0x20
    assert by_index[4].expression == "caller_arg4"
    assert by_index[4].alias_depth == 2
    assert by_index[4].alias_kind == "incoming_stack_arg"
    assert by_index[4].value_role == "caller_argument"
    assert "windows_x64_stack_arguments" in result.coverage
    assert "incoming_stack_argument_aliases" in result.coverage


def test_windows_project_call_argument_snapshot_does_not_forward_clobbered_stack_arg(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "sub", ["rsp", "0x40"]),
            _Insn(0x1004, "mov", ["qword ptr [rsp + 0x68]", "rax"]),
            _Insn(0x1008, "mov", ["rcx", "qword ptr [rsp + 0x68]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[0].expression == "qword ptr [rsp + 0x68]"
    assert by_index[0].alias_kind is None
    assert "incoming_stack_argument_aliases" not in result.coverage


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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].value_role == "field_derived"
    assert "derived_address_arguments" in result.coverage


def test_windows_project_call_argument_snapshot_recovers_constant_arithmetic_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["r8d", "4"]),
            _Insn(0x1004, "shl", ["r8d", "1"]),
            _Insn(0x1008, "add", ["r8d", "2"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[2].expression == "0xa"
    assert by_index[2].source_text == "add r8d, 2"
    assert by_index[2].alias_kind == "arithmetic"
    assert by_index[2].value_role == "integer_constant"
    assert "arithmetic_argument_expressions" in result.coverage


def test_windows_project_call_argument_snapshot_recovers_caller_arg_arithmetic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rdx", "rcx"]),
            _Insn(0x1004, "add", ["rdx", "0x20"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].expression == "(caller_arg0 + 0x20)"
    assert by_index[1].source_text == "add rdx, 0x20"
    assert by_index[1].alias_depth == 2
    assert by_index[1].alias_kind == "arithmetic"
    assert by_index[1].value_role == "computed_value"
    assert "arithmetic_argument_expressions" in result.coverage


def test_windows_project_call_argument_snapshot_resolves_indexed_lea_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["r8", "[rcx + rdx*4 + 0x10]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[2].expression == "[caller_arg0 + (caller_arg1 * 0x4) + 0x10]"
    assert by_index[2].source_text == "lea r8, [rcx + rdx*4 + 0x10]"
    assert by_index[2].alias_depth == 1
    assert by_index[2].alias_kind == "derived_address"
    assert by_index[2].value_role == "field_derived"
    assert "derived_address_arguments" in result.coverage


def test_windows_project_call_argument_snapshot_resolves_self_scaled_lea_args(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["r8", "[rdx + rdx*2]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[2].expression == "[caller_arg1 + (caller_arg1 * 0x2)]"
    assert by_index[2].source_text == "lea r8, [rdx + rdx*2]"
    assert by_index[2].alias_kind == "derived_address"


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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[0].value_role == "global_pointer"
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
    conn.execute(
        "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, 0)",
        (1, 0x3000, "cldflt!g_TestTable", "GUID[]", 16, "unit_test"),
    )
    conn.commit()
    conn.close()

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["rcx", "[rip + 0x1234]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[0].data_target_name == "cldflt!g_TestTable"
    assert by_index[0].data_target_type == "GUID[]"
    assert by_index[0].data_target_size == 16
    assert by_index[0].value_role == "global_pointer"
    assert "project_data_xref_targets" in result.coverage
    assert "project_data_label_targets" in result.coverage


def test_windows_project_call_argument_snapshot_uses_data_label_role_hints(
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
    conn.execute(
        "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, 0)",
        (1, 0x3000, "cldflt!g_RegistryPath", "UNICODE_STRING", 16, "unit_test"),
    )
    conn.commit()
    conn.close()

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "lea", ["rcx", "[rip + 0x1234]"]),
            _Insn(0x1014, "call", ["0x2000"]),
        ]

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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

    assert result.arguments[0].value_role == "path"
    assert "path or name" in (result.arguments[0].value_role_reason or "")
    assert "argument_value_roles" in result.coverage


def test_windows_project_call_argument_snapshot_recovers_arithmetic_address_base(
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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].expression == "[(caller_arg0 + 0x10) + 0x20]"
    assert by_index[1].source_text == "lea rdx, [rcx + 0x20]"
    assert by_index[1].alias_depth == 2
    assert by_index[1].alias_kind == "derived_address"
    assert by_index[1].value_role == "field_derived"
    assert "derived_address_arguments" in result.coverage


def test_windows_project_call_argument_snapshot_recovers_arithmetic_incoming_args(
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

    monkeypatch.setattr(
        getattr(g, "disasm"), "disassemble_window_at", fake_disassemble_window_at
    )
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
    assert by_index[1].expression == "(caller_arg0 + 0x10)"
    assert by_index[1].source_text == "mov rdx, rcx"
    assert by_index[1].alias_depth == 2
    assert by_index[1].alias_kind == "arithmetic"
    assert by_index[1].value_role == "computed_value"
    assert "arithmetic_argument_expressions" in result.coverage


def test_memory_agent_registers_windows_project_call_argument_snapshot() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_call_argument_snapshot" in agent._function_toolset.tools
