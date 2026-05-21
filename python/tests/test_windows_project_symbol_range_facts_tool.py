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
from glaurung.llm.tools.windows_project_symbol_range_facts import build_tool


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
CREATE TABLE function_boundaries (
    boundary_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    entry_va INTEGER,
    end_va INTEGER,
    size INTEGER,
    source TEXT,
    confidence REAL,
    name TEXT,
    detail_json TEXT,
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
        conn.execute("INSERT INTO binaries VALUES (?, ?)", (1, "driver.sys"))
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!Dispatch", "[]", "pdb", 0, None, None),
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
                (1, 0x140001080, "driver!Helper", "[]", "pdb", 0, None, None),
                (
                    1,
                    0x140002000,
                    "driver!SymbolAdjacent",
                    "[]",
                    "pdb",
                    0,
                    None,
                    None,
                ),
                (
                    1,
                    0x140002080,
                    "driver!Unbounded",
                    "[]",
                    "manual",
                    0,
                    None,
                    None,
                ),
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
            ],
        )
        conn.executemany(
            "INSERT INTO function_boundaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    0,
                ),
                (
                    2,
                    1,
                    0x140001040,
                    0x140001080,
                    0x40,
                    "pdb_public_inside_pdata",
                    0.58,
                    "driver!Dispatch$catch$0",
                    (
                        '{"range_source": "symbol_adjacency_inside_pdata", '
                        '"containing_pdata_start": "0x140001000"}'
                    ),
                    0,
                ),
                (
                    3,
                    1,
                    0x140001080,
                    0x140001100,
                    0x80,
                    "pdb_public_inside_pdata",
                    0.58,
                    "driver!Helper",
                    (
                        '{"range_source": "containing_pdata_end", '
                        '"containing_pdata_start": "0x140001000"}'
                    ),
                    0,
                ),
                (
                    4,
                    1,
                    0x140002000,
                    0x140002080,
                    0x80,
                    "pdb_symbol_adjacency",
                    0.82,
                    "driver!SymbolAdjacent",
                    (
                        '{"range_source": "symbol_adjacency", '
                        '"next_symbol_va": "0x140002080"}'
                    ),
                    0,
                ),
                (
                    5,
                    1,
                    0x140002080,
                    None,
                    None,
                    "function_name",
                    0.72,
                    "driver!Unbounded",
                    "{}",
                    0,
                ),
                (
                    6,
                    1,
                    0x140003000,
                    0x140003006,
                    6,
                    "pdb_symbol_adjacency",
                    0.82,
                    "driver!__imp_ZwClose",
                    '{"range_source": "symbol_adjacency"}',
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
                    0.90,
                    "driver!Dispatch",
                    "{}",
                    0,
                ),
                (
                    2,
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
                    "{}",
                    0,
                ),
                (
                    3,
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
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_symbol_range_facts_reports_range_quality(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(project_path=str(project), add_to_kb=True),
    )

    assert result.symbol_count == 6
    assert result.ranged_count == 5
    assert result.unbounded_count == 1
    assert result.exact_pdata_count == 1
    assert result.inside_pdata_count == 2
    assert result.adjacency_count == 2
    assert "function_names_present" in result.coverage
    assert "exact_pdata_ranges" in result.coverage
    assert "symbol_adjacency_ranges" in result.coverage
    assert "inside_pdata_symbol_ranges" in result.coverage

    dispatch = next(fact for fact in result.facts if fact.name == "driver!Dispatch")
    assert dispatch.range_status == "pdata_exact"
    assert dispatch.pdata_relation == "exact"
    assert "exact_pdata_boundary" in dispatch.reason_codes

    catch = next(fact for fact in result.facts if "$catch" in fact.name)
    assert catch.range_status == "inside_pdata"
    assert catch.pdata_relation == "inside"
    assert "split_body_or_funclet_review" in catch.security_relevance
    assert "exception_funclet" in catch.security_relevance

    adjacent = next(
        fact for fact in result.facts if fact.name.endswith("SymbolAdjacent")
    )
    assert adjacent.range_status == "symbol_adjacency"
    assert adjacent.next_symbol_name == "driver!Unbounded"
    assert "range_ends_at_next_symbol" in adjacent.reason_codes

    unbounded = next(fact for fact in result.facts if fact.name.endswith("Unbounded"))
    assert unbounded.range_status == "unbounded_symbol"
    assert "function_range_missing" in unbounded.security_relevance

    thunk = next(fact for fact in result.facts if "__imp_ZwClose" in fact.name)
    assert "import_thunk" in thunk.chunk_kinds
    assert "thunk_range" in thunk.security_relevance

    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_symbol_range_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_project_symbol_range_facts_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    project = _project(tmp_path)

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-symbol-ranges",
            "--project-path",
            str(project),
            "--range-status",
            "inside_pdata",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["filtered_count"] == 2
    assert {row["range_status"] for row in output["facts"]} == {"inside_pdata"}


def test_memory_agent_registers_windows_project_symbol_range_facts() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_symbol_range_facts" in agent._function_toolset.tools
