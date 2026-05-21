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
from glaurung.llm.tools.windows_project_data_table_facts import build_tool


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
CREATE TABLE data_labels (
    binary_id INTEGER,
    va INTEGER,
    name TEXT,
    c_type TEXT,
    size INTEGER,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
);
CREATE TABLE xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    src_va INTEGER,
    dst_va INTEGER,
    kind TEXT,
    src_function_va INTEGER,
    indexed_at INTEGER
);
CREATE TABLE function_chunk_facts (
    chunk_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    identity_key TEXT,
    owner_entry_va INTEGER,
    chunk_start_va INTEGER,
    chunk_end_va INTEGER,
    chunk_size INTEGER,
    chunk_kind TEXT,
    relation_kind TEXT,
    target_va INTEGER,
    target_name TEXT,
    source TEXT,
    confidence REAL,
    name TEXT,
    detail_json TEXT,
    indexed_at INTEGER
);
"""
        )
        conn.execute(
            "INSERT INTO binaries VALUES (?, ?, ?)", (1, "sha256", "driver.sys")
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!DriverEntry", "[]", "pdb", 0, None, None),
                (1, 0x140002000, "driver!DeviceControl", "[]", "pdb", 0, None, None),
                (1, 0x140003000, "driver!CallbackUser", "[]", "pdb", 0, None, None),
                (1, 0x180001000, "nt!ZwClose", "[]", "pdb", 0, None, None),
                (
                    1,
                    0x180002000,
                    "nt!ZwCreateFile",
                    "[]",
                    "pdb",
                    0,
                    None,
                    None,
                ),
            ],
        )
        conn.executemany(
            "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    0x140020000,
                    "driver!MajorFunction",
                    "PDRIVER_DISPATCH[28]",
                    28 * 8,
                    "pdb",
                    0,
                ),
                (
                    1,
                    0x140021000,
                    "driver!g_Callbacks",
                    "PFN_CALLBACK[4]",
                    4 * 8,
                    "manual",
                    0,
                ),
                (
                    1,
                    0x140022000,
                    "driver!??_7Device@@6B@",
                    "void *[3]",
                    3 * 8,
                    "pdb",
                    0,
                ),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    1,
                    0x140001020,
                    0x140020000,
                    "data_write",
                    0x140001000,
                    0,
                ),
                (
                    2,
                    1,
                    0x140002030,
                    0x140020030,
                    "data_read",
                    0x140002000,
                    0,
                ),
                (
                    3,
                    1,
                    0x140003010,
                    0x140021008,
                    "data_read",
                    0x140003000,
                    0,
                ),
            ],
        )
        conn.executemany(
            "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    1,
                    "iat-zwclose",
                    0x140010000,
                    0x140010000,
                    0x140010006,
                    6,
                    "import_thunk",
                    "import_thunk",
                    0x180001000,
                    "nt!ZwClose",
                    "function_name",
                    0.76,
                    "driver!__imp_ZwClose",
                    "{}",
                    0,
                ),
                (
                    2,
                    1,
                    "iat-zwcreate",
                    0x140010006,
                    0x140010006,
                    0x14001000C,
                    6,
                    "import_thunk",
                    "import_thunk",
                    0x180002000,
                    "nt!ZwCreateFile",
                    "function_name",
                    0.76,
                    "driver!__imp_ZwCreateFile",
                    "{}",
                    0,
                ),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_data_table_facts_recovers_core_table_kinds(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(project_path=str(_project(tmp_path)), add_to_kb=True),
    )

    assert result.returned_count >= 4
    assert result.summary_by_kind["dispatch_table"] == 1
    assert result.summary_by_kind["callback_array"] == 1
    assert result.summary_by_kind["vtable"] == 1
    assert result.summary_by_kind["import_thunk_table"] == 1
    assert "data_table_candidates" in result.coverage
    assert "dispatch_table_candidates" in result.coverage
    assert "import_thunk_table_candidates" in result.coverage

    dispatch = next(
        table for table in result.tables if table.table_kind == "dispatch_table"
    )
    assert dispatch.entry_count == 28
    assert dispatch.slot_size == 8
    assert dispatch.read_xref_count == 1
    assert dispatch.write_xref_count == 1
    assert "driver!DriverEntry" in dispatch.source_function_names
    assert any(entry.index == 6 for entry in dispatch.entries)
    assert "dispatch_table" in dispatch.security_relevance

    thunk = next(
        table for table in result.tables if table.table_kind == "import_thunk_table"
    )
    assert thunk.entry_count == 2
    assert thunk.entries[0].target_name == "nt!ZwClose"
    assert "import_thunk_table" in thunk.security_relevance

    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_data_table_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_project_data_table_facts_filters_callback_tables(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_project(tmp_path)),
            table_kind="callback_array",
            name_contains="callbacks",
        ),
    )

    assert result.returned_count == 1
    table = result.tables[0]
    assert table.table_kind == "callback_array"
    assert table.name == "driver!g_Callbacks"
    assert table.entry_count == 4


def test_windows_project_data_table_facts_cli_json(tmp_path: Path, capsys) -> None:
    rc = GlaurungCLI().run(
        [
            "windows",
            "project-data-tables",
            "--project-path",
            str(_project(tmp_path)),
            "--table-kind",
            "import_thunk_table",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["returned_count"] == 1
    assert output["tables"][0]["table_kind"] == "import_thunk_table"


def test_memory_agent_registers_windows_project_data_table_facts() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_data_table_facts" in agent._function_toolset.tools
