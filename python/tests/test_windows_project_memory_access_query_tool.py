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
from glaurung.llm.tools.windows_project_memory_access_query import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "driver.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path) -> Path:
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
        conn.execute(
            "INSERT INTO binaries VALUES (1, 'sha256', 'driver.sys', 'PE', 'x86_64', 64, 16, 0)"
        )
        rows = [
            (
                1,
                0x1000,
                "driver!Dispatch",
                0x1010,
                "mov rax, qword ptr [rcx + 0x20]",
                "mov",
                1,
                "qword ptr [rcx + 0x20]",
                "read",
                8,
                "[rcx + 0x20]",
                "rcx",
                None,
                None,
                0x20,
                "user_pointer",
                "Irp",
                "user_pointer",
                "PIRP",
                "irp",
                0x20,
                "SystemBuffer",
                "IRP",
                None,
                None,
                None,
                None,
                None,
                0.94,
                "unit",
                0,
            ),
            (
                1,
                0x1000,
                "driver!Dispatch",
                0x1020,
                "mov dword ptr [rbp - 0x10], eax",
                "mov",
                0,
                "dword ptr [rbp - 0x10]",
                "write",
                4,
                "[rbp - 0x10]",
                "rbp",
                None,
                None,
                -0x10,
                "stack_local",
                "var_10",
                "stack_local",
                "ULONG",
                None,
                -0x10,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                0.76,
                "unit",
                0,
            ),
            (
                1,
                0x1100,
                "driver!Validate",
                0x1110,
                "add qword ptr [rsp + 0x20], 1",
                "add",
                0,
                "qword ptr [rsp + 0x20]",
                "read_write",
                8,
                "[rsp + 0x20]",
                "rsp",
                None,
                None,
                0x20,
                "stack_argument",
                "arg_20",
                "stack_argument",
                "ULONG_PTR",
                None,
                0x20,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                0.71,
                "unit",
                0,
            ),
            (
                1,
                0x1200,
                "driver!TableUser",
                0x1210,
                "cmp byte ptr [rip + 0x1234], 0",
                "cmp",
                0,
                "byte ptr [rip + 0x1234]",
                "read",
                1,
                "[rip + 0x1234]",
                "rip",
                None,
                None,
                0x1234,
                "global_data",
                "g_DispatchTable",
                "global",
                "UCHAR[]",
                None,
                0,
                None,
                None,
                0x140020000,
                "data_read",
                "driver!g_DispatchTable",
                "UCHAR[]",
                0x80,
                0.88,
                "unit",
                0,
            ),
        ]
        conn.executemany(
            """
INSERT INTO memory_operand_facts
(binary_id, function_va, function_name, instruction_va, instruction_text,
 mnemonic, operand_index, operand_text, access_kind, width_bytes,
 address_expression, base_register, index_register, scale, displacement,
 role_hint, base_object, base_object_kind, base_object_type, base_object_role,
 field_offset, likely_field_name, likely_type_name, data_target_va,
 data_target_kind, data_target_name, data_target_type, data_target_size,
 confidence, set_by, set_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?)
""",
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_memory_access_query_finds_field_reads(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_project(tmp_path)),
            query="reads",
            likely_type_name="IRP",
            likely_field_name="SystemBuffer",
            add_to_kb=True,
        ),
    )

    assert result.total_count == 1
    assert result.returned_count == 1
    row = result.rows[0]
    assert row.function_name == "driver!Dispatch"
    assert row.access_kind == "read"
    assert row.width_bytes == 8
    assert row.base_object_kind == "user_pointer"
    assert row.likely_type_name == "IRP"
    assert row.likely_field_name == "SystemBuffer"
    assert result.summary_by_field == {"IRP.SystemBuffer": 1}
    assert "memory_reads" in result.coverage
    assert "field_or_offset_facts" in result.coverage
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_memory_access_query"
        for node in ctx.kb.nodes()
    )


def test_windows_project_memory_access_query_finds_writes_and_global_targets(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    project = _project(tmp_path)

    writes = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(project_path=str(project), query="writes"),
    )

    assert writes.total_count == 2
    assert writes.summary_by_access_kind == {"read_write": 1, "write": 1}
    assert "memory_writes" in writes.coverage

    globals_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project),
            data_target_name_contains="dispatchtable",
        ),
    )

    assert globals_result.total_count == 1
    assert globals_result.rows[0].data_target_va == 0x140020000
    assert globals_result.rows[0].data_target_name == "driver!g_DispatchTable"
    assert globals_result.summary_by_data_target == {"driver!g_DispatchTable": 1}
    assert "data_target_facts" in globals_result.coverage


def test_windows_project_memory_access_query_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    rc = GlaurungCLI().run(
        [
            "windows",
            "project-memory-access-query",
            "--project-path",
            str(_project(tmp_path)),
            "--query",
            "writes",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["total_count"] == 2
    assert output["summary_by_access_kind"] == {"read_write": 1, "write": 1}


def test_memory_agent_registers_windows_project_memory_access_query() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_memory_access_query" in agent._function_toolset.tools
