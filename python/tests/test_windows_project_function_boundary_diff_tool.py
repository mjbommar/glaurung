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
from glaurung.llm.tools.windows_project_function_boundary_diff import build_tool


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
CREATE TABLE function_boundaries (
    boundary_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    entry_va INTEGER,
    end_va INTEGER,
    size INTEGER,
    source TEXT,
    confidence REAL,
    name TEXT,
    detail_json TEXT
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
        if variant == "before":
            conn.executemany(
                "INSERT INTO function_boundaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        1,
                        1,
                        0x140001000,
                        0x140001100,
                        0x100,
                        "pdata",
                        0.90,
                        "driver!Dispatch",
                        '{"section": ".text"}',
                    ),
                    (
                        2,
                        1,
                        0x140002000,
                        0x140002040,
                        0x40,
                        "pdb_symbol_adjacency",
                        0.82,
                        "driver!RemovedHelper",
                        "{}",
                    ),
                ],
            )
            conn.executemany(
                "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        1,
                        1,
                        "dispatch-thunk",
                        0x140001000,
                        0x140001080,
                        0x140001086,
                        6,
                        "import_thunk",
                        "import_thunk",
                        0x180001000,
                        "ZwClose",
                        "function_name",
                        0.74,
                        "driver!Dispatch$thunk",
                        "{}",
                        0,
                    ),
                    (
                        2,
                        1,
                        "old-tail",
                        0x140001000,
                        0x1400010C0,
                        0x1400010F0,
                        0x30,
                        "shared_tail_candidate",
                        "tailcall_to",
                        0x140003000,
                        "driver!OldTail",
                        "tail_jump",
                        0.62,
                        "driver!Dispatch$tail",
                        "{}",
                        0,
                    ),
                ],
            )
        else:
            conn.executemany(
                "INSERT INTO function_boundaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        1,
                        1,
                        0x140001000,
                        0x140001120,
                        0x120,
                        "pdata",
                        0.88,
                        "driver!Dispatch",
                        '{"section": ".text"}',
                    ),
                    (
                        3,
                        1,
                        0x140004000,
                        0x140004030,
                        0x30,
                        "pdb_symbol_adjacency",
                        0.80,
                        "driver!AddedProbe",
                        "{}",
                    ),
                ],
            )
            conn.executemany(
                "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        1,
                        1,
                        "dispatch-thunk",
                        0x140001000,
                        0x140001080,
                        0x140001086,
                        6,
                        "import_thunk",
                        "import_thunk",
                        0x180002000,
                        "ZwQueryInformationProcess",
                        "function_name",
                        0.76,
                        "driver!Dispatch$thunk",
                        "{}",
                        0,
                    ),
                    (
                        3,
                        1,
                        "dispatch-catch",
                        0x140001000,
                        0x140001040,
                        0x140001070,
                        0x30,
                        "exception_funclet_candidate",
                        "exception_child",
                        None,
                        None,
                        "pdb_public_inside_pdata",
                        0.58,
                        "driver!Dispatch$catch$0",
                        "{}",
                        0,
                    ),
                ],
            )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_function_boundary_diff_reports_range_and_chunk_deltas(
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

    assert result.before_boundary_count == 2
    assert result.after_boundary_count == 2
    assert result.before_chunk_count == 2
    assert result.after_chunk_count == 2
    assert result.changed_count == 2
    assert result.added_count == 2
    assert result.removed_count == 2
    assert "function_boundaries" in result.coverage
    assert "function_chunk_facts" in result.coverage
    assert "boundary_deltas" in result.coverage
    assert "chunk_deltas" in result.coverage
    assert "thunk_tailcall_deltas" in result.coverage
    assert "funclet_deltas" in result.coverage

    dispatch = next(
        delta
        for delta in result.deltas
        if delta.record_kind == "function_boundary" and delta.name == "driver!Dispatch"
    )
    assert dispatch.status == "changed"
    assert "size" in dispatch.changed_fields
    assert "function_range_delta" in dispatch.security_relevance
    assert "changed_size" in dispatch.reason_codes

    thunk = next(
        delta for delta in result.deltas if "dispatch-thunk" in delta.identity_key
    )
    assert thunk.status == "changed"
    assert "target_va" in thunk.changed_fields
    assert "thunk_delta" in thunk.security_relevance
    assert "chunk_relation_delta" in thunk.security_relevance
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_function_boundary_diff"
        for node in ctx.kb.nodes()
    )


def test_windows_project_function_boundary_diff_cli_json(
    tmp_path: Path, capsys
) -> None:
    before = _project(tmp_path, "before", variant="before")
    after = _project(tmp_path, "after", variant="after")

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-function-boundary-diff",
            "--before-project-path",
            str(before),
            "--after-project-path",
            str(after),
            "--function-name-contains",
            "dispatch",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["changed_count"] == 2
    assert output["added_count"] == 1
    assert output["removed_count"] == 1
    assert any(
        delta["record_kind"] == "function_chunk"
        and "exception_funclet_delta" in delta["security_relevance"]
        for delta in output["deltas"]
    )


def test_memory_agent_registers_windows_project_function_boundary_diff() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_function_boundary_diff" in agent._function_toolset.tools
