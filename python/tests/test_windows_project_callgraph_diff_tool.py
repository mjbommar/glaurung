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
from glaurung.llm.tools.windows_project_callgraph_diff import build_tool


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
        conn.execute("INSERT INTO binaries VALUES (?, ?)", (1, f"{name}.sys"))
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!Dispatch", "[]", "pdb", 0, None, None),
                (1, 0x140002000, "driver!Helper", "[]", "pdb", 0, None, None),
                (1, 0x140002800, "driver!NewCaller", "[]", "pdb", 0, None, None),
                (1, 0x140003000, "nt!ProbeForRead", "[]", "pdb", 0, None, None),
                (1, 0x140003100, "nt!ProbeForWrite", "[]", "pdb", 0, None, None),
                (1, 0x140003200, "nt!RtlCopyMemory", "[]", "pdb", 0, None, None),
                (1, 0x140003300, "nt!ZwOpenProcess", "[]", "pdb", 0, None, None),
                (1, 0x140004000, "driver!OldHelper", "[]", "pdb", 0, None, None),
                (1, 0x140005000, "driver!SharedTail", "[]", "pdb", 0, None, None),
            ],
        )
        if variant == "before":
            rows = [
                (1, 1, 0x140001010, 0x140003000, "call", 0x140001000, 0),
                (2, 1, 0x140001020, 0x140003200, "call", 0x140001000, 0),
                (3, 1, 0x140002010, 0x140004000, "call", 0x140002000, 0),
                (4, 1, 0x140001050, 0x140005000, "jump", 0x140001000, 0),
            ]
        else:
            rows = [
                (1, 1, 0x140001018, 0x140003100, "call", 0x140001000, 0),
                (2, 1, 0x140001028, 0x140003200, "call", 0x140001000, 0),
                (3, 1, 0x140002820, 0x140003300, "call", 0x140002800, 0),
                (4, 1, 0x140001050, 0x140005000, "jump", 0x140001000, 0),
            ]
        conn.executemany("INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_callgraph_diff_reports_edge_deltas(tmp_path: Path) -> None:
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

    assert result.before_edge_count == 4
    assert result.after_edge_count == 4
    assert result.changed_count == 1
    assert result.added_count == 2
    assert result.removed_count == 2
    assert "callgraph_deltas" in result.coverage
    assert "sink_or_api_call_deltas" in result.coverage

    copy = next(
        delta for delta in result.deltas if delta.callee_name == "nt!RtlCopyMemory"
    )
    assert copy.status == "changed"
    assert "callsites" in copy.changed_fields
    assert "sink_or_api_call_delta" in copy.security_relevance

    zw = next(
        delta for delta in result.deltas if delta.callee_name == "nt!ZwOpenProcess"
    )
    assert zw.status == "added"
    assert "callgraph_edge_added" in zw.security_relevance

    removed = next(
        delta for delta in result.deltas if delta.callee_name == "driver!OldHelper"
    )
    assert removed.status == "removed"

    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_callgraph_diff"
        for node in ctx.kb.nodes()
    )


def test_windows_project_callgraph_diff_cli_json(tmp_path: Path, capsys) -> None:
    before = _project(tmp_path, "before", variant="before")
    after = _project(tmp_path, "after", variant="after")

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-callgraph-diff",
            "--before-project-path",
            str(before),
            "--after-project-path",
            str(after),
            "--target-name-contains",
            "zwopen",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["added_count"] == 1
    assert output["deltas"][0]["callee_name"] == "nt!ZwOpenProcess"


def test_memory_agent_registers_windows_project_callgraph_diff() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_callgraph_diff" in agent._function_toolset.tools
