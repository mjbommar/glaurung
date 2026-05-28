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
from glaurung.llm.tools.windows_project_data_table_diff import build_tool


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
        conn.execute("INSERT INTO binaries VALUES (?, ?, ?)", (1, "sha256", name))
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!DriverEntry", "[]", "pdb", 0, None, None),
                (1, 0x140002000, "driver!DeviceControl", "[]", "pdb", 0, None, None),
                (1, 0x140003000, "driver!TableUser", "[]", "pdb", 0, None, None),
            ],
        )
        if variant == "before":
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
                        "driver!SelectorTable",
                        "ULONG[8]",
                        8 * 4,
                        "manual",
                        0,
                    ),
                ],
            )
            conn.executemany(
                "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, 1, 0x140001020, 0x140020000, "data_write", 0x140001000, 0),
                    (2, 1, 0x140002030, 0x140020030, "data_read", 0x140002000, 0),
                ],
            )
            thunk_target = "nt!ZwClose"
            thunk_target_va = 0x180001000
        else:
            conn.executemany(
                "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        1,
                        0x140020000,
                        "driver!MajorFunction",
                        "PDRIVER_DISPATCH[32]",
                        32 * 8,
                        "pdb",
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
                    (1, 1, 0x140001020, 0x140020000, "data_write", 0x140001000, 0),
                    (2, 1, 0x140002030, 0x140020038, "data_read", 0x140002000, 0),
                    (3, 1, 0x140003010, 0x140020040, "data_read", 0x140003000, 0),
                ],
            )
            thunk_target = "nt!ZwOpenProcess"
            thunk_target_va = 0x180002000
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
                    thunk_target_va,
                    thunk_target,
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
                    0x180003000,
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


def test_windows_project_data_table_diff_reports_table_deltas(
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

    assert result.before_table_count == 3
    assert result.after_table_count == 3
    assert result.changed_count == 2
    assert result.added_count == 1
    assert result.removed_count == 1
    assert "data_table_deltas" in result.coverage
    assert "dispatch_table_deltas" in result.coverage
    assert "table_target_deltas" in result.coverage

    dispatch = next(
        delta for delta in result.deltas if delta.name == "driver!MajorFunction"
    )
    assert dispatch.status == "changed"
    assert "entry_count" in dispatch.changed_fields
    assert "entry_targets" in dispatch.changed_fields
    assert "table_entry_count_delta" in dispatch.security_relevance
    assert "table_target_delta" in dispatch.security_relevance

    thunk = next(
        delta for delta in result.deltas if delta.name == "driver!__imp_ZwClose"
    )
    assert thunk.status == "changed"
    assert "entry_targets" in thunk.changed_fields
    assert "import_thunk_table" in thunk.security_relevance

    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_data_table_diff"
        for node in ctx.kb.nodes()
    )


def test_windows_project_data_table_diff_cli_json(tmp_path: Path, capsys) -> None:
    before = _project(tmp_path, "before", variant="before")
    after = _project(tmp_path, "after", variant="after")

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-data-table-diff",
            "--before-project-path",
            str(before),
            "--after-project-path",
            str(after),
            "--table-kind",
            "dispatch_table",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["changed_count"] == 1
    assert output["deltas"][0]["name"] == "driver!MajorFunction"
    assert "table_layout_delta" in output["deltas"][0]["security_relevance"]


def test_memory_agent_registers_windows_project_data_table_diff() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_data_table_diff" in agent._function_toolset.tools
