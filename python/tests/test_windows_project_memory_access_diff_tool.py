from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_memory_access_diff import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "driver.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path, name: str, *, variant: str) -> Path:
    project = tmp_path / f"{name}.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
CREATE TABLE binaries (
    binary_id INTEGER PRIMARY KEY,
    first_path TEXT
);
CREATE TABLE function_names (
    binary_id INTEGER,
    entry_va INTEGER,
    canonical TEXT,
    aliases_json TEXT DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE memory_operand_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    function_name TEXT,
    instruction_va INTEGER NOT NULL,
    instruction_text TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operand_index INTEGER NOT NULL,
    operand_text TEXT NOT NULL,
    access_kind TEXT NOT NULL,
    width_bytes INTEGER,
    address_expression TEXT NOT NULL,
    base_register TEXT,
    index_register TEXT,
    scale INTEGER,
    displacement INTEGER NOT NULL DEFAULT 0,
    role_hint TEXT NOT NULL,
    base_object TEXT,
    base_object_kind TEXT,
    base_object_type TEXT,
    base_object_role TEXT,
    field_offset INTEGER NOT NULL DEFAULT 0,
    likely_field_name TEXT,
    likely_type_name TEXT,
    data_target_va INTEGER,
    data_target_kind TEXT,
    data_target_name TEXT,
    data_target_type TEXT,
    data_target_size INTEGER,
    confidence REAL NOT NULL,
    set_by TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, instruction_va, operand_index)
);
"""
        )
        conn.execute("INSERT INTO binaries VALUES (?, ?)", (1, f"{name}.sys"))
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!Dispatch", "[]", "pdb", 0, None, None),
                (1, 0x140002000, "driver!Helper", "[]", "pdb", 0, None, None),
            ],
        )
        if variant == "before":
            rows = [
                _mem(
                    0x140001000,
                    "driver!Dispatch",
                    0x140001020,
                    "mov [rcx+18h], rdx",
                    "mov",
                    "[rcx+18h]",
                    "write",
                    8,
                    "rcx+0x18",
                    "Irp",
                    "user_pointer",
                    "PIRP",
                    "irp",
                    0x18,
                    "UserBuffer",
                    "IRP",
                    None,
                    None,
                    None,
                    None,
                ),
                _mem(
                    0x140001000,
                    "driver!Dispatch",
                    0x140001030,
                    "mov eax, [rcx+30h]",
                    "mov",
                    "[rcx+30h]",
                    "read",
                    4,
                    "rcx+0x30",
                    "IoStack",
                    "stack_local",
                    "IO_STACK_LOCATION",
                    "io_stack",
                    0x30,
                    "InputBufferLength",
                    "IO_STACK_LOCATION",
                    None,
                    None,
                    None,
                    None,
                ),
                _mem(
                    0x140002000,
                    "driver!Helper",
                    0x140002010,
                    "cmp byte ptr [rip+2000h], 0",
                    "cmp",
                    "[rip+2000h]",
                    "read",
                    1,
                    "rip+0x2000",
                    "driver!ConfigFlag",
                    "global",
                    "BOOLEAN",
                    "config",
                    0,
                    "ConfigFlag",
                    "GLOBAL",
                    0x140020000,
                    "global",
                    "driver!ConfigFlag",
                    "BOOLEAN",
                ),
            ]
        else:
            rows = [
                _mem(
                    0x140001000,
                    "driver!Dispatch",
                    0x140001028,
                    "mov [rcx+18h], r8",
                    "mov",
                    "[rcx+18h]",
                    "write",
                    8,
                    "rcx+0x18",
                    "Irp",
                    "user_pointer",
                    "PIRP",
                    "irp",
                    0x18,
                    "UserBuffer",
                    "IRP",
                    None,
                    None,
                    None,
                    None,
                ),
                _mem(
                    0x140001000,
                    "driver!Dispatch",
                    0x140001038,
                    "mov rax, [rcx+30h]",
                    "mov",
                    "[rcx+30h]",
                    "read",
                    8,
                    "rcx+0x30",
                    "IoStack",
                    "stack_local",
                    "IO_STACK_LOCATION",
                    "io_stack",
                    0x30,
                    "InputBufferLength",
                    "IO_STACK_LOCATION",
                    None,
                    None,
                    None,
                    None,
                ),
                _mem(
                    0x140002000,
                    "driver!Helper",
                    0x140002020,
                    "mov [rip+3000h], rax",
                    "mov",
                    "[rip+3000h]",
                    "write",
                    8,
                    "rip+0x3000",
                    "driver!CallbackTable",
                    "global",
                    "void *[4]",
                    "callback_table",
                    0,
                    "CallbackTable",
                    "PDRIVER_DISPATCH",
                    0x140030000,
                    "global",
                    "driver!CallbackTable",
                    "PDRIVER_DISPATCH[4]",
                ),
            ]
        conn.executemany(
            "INSERT INTO memory_operand_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    return project


def _mem(
    function_va: int,
    function_name: str,
    instruction_va: int,
    instruction_text: str,
    mnemonic: str,
    operand_text: str,
    access_kind: str,
    width_bytes: int,
    address_expression: str,
    base_object: str,
    base_object_kind: str,
    base_object_type: str,
    base_object_role: str,
    field_offset: int,
    likely_field_name: str,
    likely_type_name: str,
    data_target_va: int | None,
    data_target_kind: str | None,
    data_target_name: str | None,
    data_target_type: str | None,
) -> tuple[object, ...]:
    return (
        1,
        function_va,
        function_name,
        instruction_va,
        instruction_text,
        mnemonic,
        0,
        operand_text,
        access_kind,
        width_bytes,
        address_expression,
        None,
        None,
        None,
        field_offset,
        "memory",
        base_object,
        base_object_kind,
        base_object_type,
        base_object_role,
        field_offset,
        likely_field_name,
        likely_type_name,
        data_target_va,
        data_target_kind,
        data_target_name,
        data_target_type,
        None,
        0.86,
        "test",
        0,
    )


def test_windows_project_memory_access_diff_reports_field_and_global_deltas(
    tmp_path: Path,
) -> None:
    before = _project(tmp_path, "before", variant="before")
    after = _project(tmp_path, "after", variant="after")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            before_project_path=str(before),
            after_project_path=str(after),
            add_to_kb=True,
        ),
    )

    assert result.before_access_count == 3
    assert result.after_access_count == 3
    assert result.changed_count == 2
    assert result.added_count == 1
    assert result.removed_count == 1
    assert "memory_access_deltas" in result.coverage
    assert "memory_write_deltas" in result.coverage
    assert "field_access_deltas" in result.coverage

    user_write = next(
        delta for delta in result.deltas if delta.likely_field_name == "UserBuffer"
    )
    assert user_write.status == "changed"
    assert "instructions" in user_write.changed_fields
    assert "user_or_request_memory_delta" in user_write.security_relevance
    assert "memory_write_delta" in user_write.security_relevance

    length_read = next(
        delta
        for delta in result.deltas
        if delta.likely_field_name == "InputBufferLength"
    )
    assert length_read.status == "changed"
    assert "width_bytes" in length_read.changed_fields
    assert "length_or_bounds_memory_delta" in length_read.security_relevance

    callback = next(
        delta
        for delta in result.deltas
        if delta.data_target_name == "driver!CallbackTable"
    )
    assert callback.status == "added"
    assert "function_pointer_memory_delta" in callback.security_relevance

    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_memory_access_diff"
        for node in ctx.kb.nodes()
    )


def test_windows_project_memory_access_diff_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    before = _project(tmp_path, "before", variant="before")
    after = _project(tmp_path, "after", variant="after")

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-memory-access-diff",
            "--before-project-path",
            str(before),
            "--after-project-path",
            str(after),
            "--query",
            "writes",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["changed_count"] == 1
    assert output["added_count"] == 1
    assert {delta["access_kind"] for delta in output["deltas"]} == {"write"}


def test_memory_agent_registers_windows_project_memory_access_diff() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_memory_access_diff" in agent._function_toolset.tools
