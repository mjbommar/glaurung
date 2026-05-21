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
from glaurung.llm.tools.windows_project_xref_query import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "driver.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "sample.glaurung"
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
            CREATE TABLE data_labels (
                binary_id INTEGER,
                va INTEGER,
                name TEXT,
                c_type TEXT,
                size INTEGER,
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
            """
        )
        conn.execute("INSERT INTO binaries VALUES (?, ?)", (1, "driver.sys"))
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!Dispatch", "[]", "pdb", 0, None, None),
                (1, 0x140002000, "driver!Validate", "[]", "pdb", 0, None, None),
                (1, 0x140003000, "driver!Sink", "[]", "pdb", 0, None, None),
            ],
        )
        conn.execute(
            "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, ?)",
            (1, 0x140100000, "g_DispatchTable", "void **", 0x80, "manual", 0),
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 1, 0x140001050, 0x140002000, "call", 0x140001000, 0),
                (2, 1, 0x140002080, 0x140003000, "call", 0x140002000, 0),
                (3, 1, 0x140001090, 0x140100000, "data_read", 0x140001000, 0),
                (4, 1, 0x1400020A0, 0x140100000, "data_write", 0x140002000, 0),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_xref_query_callers_and_callees(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = _project(tmp_path)
    tool = build_tool()

    callers = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project),
            query="callers",
            symbol="Validate",
            add_to_kb=True,
        ),
    )

    assert callers.target.va == 0x140002000
    assert callers.target.target_kind == "function"
    assert callers.total_count == 1
    assert callers.rows[0].relation == "caller"
    assert callers.rows[0].src_function_name == "driver!Dispatch"
    assert callers.rows[0].dst_function_name == "driver!Validate"
    assert "call_xrefs" in callers.coverage
    assert callers.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_project_xref_query"
        for node in ctx.kb.nodes()
    )

    callees = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project),
            query="callees",
            symbol="Validate",
        ),
    )

    assert callees.total_count == 1
    assert callees.rows[0].relation == "callee"
    assert callees.rows[0].dst_function_name == "driver!Sink"


def test_windows_project_xref_query_reads_and_writes_to_data_label(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = _project(tmp_path)
    tool = build_tool()

    writes = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project),
            query="writes_to",
            symbol="g_DispatchTable",
        ),
    )

    assert writes.target.target_kind == "data"
    assert writes.target.c_type == "void **"
    assert writes.total_count == 1
    assert writes.rows[0].kind == "data_write"
    assert writes.rows[0].relation == "writer"
    assert writes.rows[0].src_function_name == "driver!Validate"
    assert writes.rows[0].dst_data_label == "g_DispatchTable"
    assert "data_write_xrefs" in writes.coverage

    reads = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project),
            query="reads_from",
            va=0x140100000,
        ),
    )

    assert reads.total_count == 1
    assert reads.rows[0].kind == "data_read"
    assert reads.rows[0].relation == "reader"
    assert "data_read_xrefs" in reads.coverage


def test_windows_project_xref_query_reports_unresolved_target(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = _project(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(project_path=str(project), symbol="MissingSymbol"),
    )

    assert result.target.va is None
    assert result.rows == []
    assert "target_resolution" in result.missing_capabilities


def test_windows_project_xref_query_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    project = _project(tmp_path)

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-xrefs",
            "--project-path",
            str(project),
            "--query",
            "writes_to",
            "--symbol",
            "g_DispatchTable",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["target"]["target_kind"] == "data"
    assert output["target"]["name"] == "g_DispatchTable"
    assert output["total_count"] == 1
    assert output["rows"][0]["relation"] == "writer"
    assert output["rows"][0]["src_function_name"] == "driver!Validate"


def test_memory_agent_registers_windows_project_xref_query() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_xref_query" in agent._function_toolset.tools
