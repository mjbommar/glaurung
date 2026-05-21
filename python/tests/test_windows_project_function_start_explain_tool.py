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
from glaurung.llm.tools.windows_project_function_start_explain import build_tool


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
                path TEXT
            );
            CREATE TABLE function_names (
                binary_id INTEGER,
                entry_va INTEGER,
                canonical TEXT,
                aliases_json TEXT DEFAULT '[]',
                set_by TEXT,
                set_at INTEGER,
                demangled TEXT,
                flavor TEXT
            );
            CREATE TABLE comments (
                binary_id INTEGER,
                va INTEGER,
                body TEXT,
                set_by TEXT,
                set_at INTEGER
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
        conn.execute("INSERT INTO binaries VALUES (?, ?)", (1, "driver.sys"))
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!Dispatch", "[]", "pdb", 0, None, None),
                (1, 0x140002000, "driver!Caller", "[]", "pdb", 0, None, None),
                (
                    1,
                    0x140003000,
                    "driver!__imp_ZwClose",
                    "[]",
                    "pdb",
                    0,
                    None,
                    None,
                ),
                (
                    1,
                    0x140001040,
                    "driver!Dispatch$catch$0",
                    "[]",
                    "pdb",
                    0,
                    None,
                    None,
                ),
            ],
        )
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
                    0.9,
                    "driver!Dispatch",
                    '{"section": ".text"}',
                ),
                (
                    2,
                    1,
                    0x140003000,
                    0x140003006,
                    6,
                    "pdb_symbol_adjacency",
                    0.82,
                    "driver!__imp_ZwClose",
                    '{"range_source": "symbol_adjacency"}',
                ),
            ],
        )
        conn.executemany(
            "INSERT INTO function_chunk_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    1,
                    1,
                    "dispatch-pdata",
                    0x140001000,
                    0x140001000,
                    0x140001100,
                    0x100,
                    "pdata_body",
                    "owns",
                    None,
                    None,
                    "pdata",
                    0.9,
                    "driver!Dispatch",
                    "{}",
                    0,
                ),
                (
                    2,
                    1,
                    "import-thunk",
                    0x140003000,
                    0x140003000,
                    0x140003006,
                    6,
                    "import_thunk",
                    "import_thunk",
                    None,
                    "ZwClose",
                    "function_name",
                    0.74,
                    "driver!__imp_ZwClose",
                    "{}",
                    0,
                ),
                (
                    3,
                    1,
                    "catch",
                    0x140001000,
                    0x140001040,
                    0x140001080,
                    0x40,
                    "exception_funclet_candidate",
                    "exception_child",
                    None,
                    None,
                    "pdb_public_inside_pdata",
                    0.58,
                    "driver!Dispatch$catch$0",
                    '{"containing_pdata_start": "0x140001000"}',
                    0,
                ),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 1, 0x140002030, 0x140001000, "call", 0x140002000, 0),
                (2, 1, 0x140003000, 0x180001000, "jump", 0x140003000, 0),
                (3, 1, 0x140001050, 0x140003000, "call", 0x140001000, 0),
            ],
        )
        conn.execute(
            "INSERT INTO comments VALUES (?, ?, ?, ?, ?)",
            (1, 0x140001000, "manual boundary reviewed", "manual", 0),
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_function_start_explain_strict_function(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = _project(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project),
            symbol="Dispatch",
            add_to_kb=True,
        ),
    )

    assert result.final_state == "strict_function"
    assert result.confidence == "high"
    assert result.target.va == 0x140001000
    assert result.names[0].canonical == "driver!Dispatch"
    assert result.exact_boundaries[0].source == "pdata"
    assert result.refs_to[0].kind == "call"
    assert "boundary:pdata" in result.reason_codes
    assert "incoming_call_xref" in result.reason_codes
    assert "comments" in result.coverage
    assert result.recommended_action == "keep_function_start"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_function_start_explain"
        for node in ctx.kb.nodes()
    )


def test_windows_project_function_start_explain_thunk_and_funclet(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = _project(tmp_path)
    tool = build_tool()

    thunk = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(project_path=str(project), symbol="__imp_ZwClose"),
    )

    assert thunk.final_state == "thunk"
    assert "chunk:import_thunk" in thunk.reason_codes
    assert thunk.recommended_action == "preserve_import_thunk_and_resolve_target"

    funclet = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(project_path=str(project), address="0x140001040"),
    )

    assert funclet.final_state == "chunk_or_funclet"
    assert "contained_by_boundary" in funclet.reason_codes
    assert "chunk:exception_funclet_candidate" in funclet.reason_codes
    assert (
        funclet.recommended_action
        == "review_body_split_funclet_or_shared_tail_relation"
    )


def test_windows_project_function_start_explain_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    project = _project(tmp_path)

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-function-start-explain",
            "--project-path",
            str(project),
            "--symbol",
            "Dispatch",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["final_state"] == "strict_function"
    assert output["target"]["address"] == "0x140001000"
    assert "exact_boundary" in output["coverage"]


def test_memory_agent_registers_windows_project_function_start_explain() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_function_start_explain" in agent._function_toolset.tools
