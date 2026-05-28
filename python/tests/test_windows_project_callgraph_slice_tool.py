from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_callgraph_slice import build_tool


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
"""
    )
    conn.execute(
        "INSERT INTO binaries VALUES (1, 'abc', 'sample.sys', 'PE', 'x86_64', 64, 1, 0)"
    )
    conn.executemany(
        "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, ?, ?)",
        [
            (1, 0x1000, "cldflt!CallerA", "pdb", None, None),
            (1, 0x1100, "cldflt!CallerB", "pdb", None, None),
            (1, 0x2000, "cldflt!Target", "pdb", None, None),
            (1, 0x3000, "cldflt!Callee", "pdb", None, None),
        ],
    )
    conn.executemany(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        [
            (1, 1, 0x1010, 0x2000, "call", 0x1000),
            (2, 1, 0x1110, 0x2000, "call", 0x1100),
            (3, 1, 0x2020, 0x3000, "call", 0x2000),
            (4, 1, 0x2030, 0x4000, "data_read", 0x2000),
        ],
    )
    conn.commit()
    conn.close()
    return project


def test_windows_project_callgraph_slice_returns_callers_and_callees(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            function_name="Target",
            direction="both",
            add_to_kb=True,
        ),
    )

    assert result.target is not None
    assert result.target.entry_va == 0x2000
    assert result.incoming_count_total == 2
    assert result.outgoing_count_total == 1
    assert [(edge.direction, edge.callsite_va) for edge in result.edges] == [
        ("incoming", 0x1010),
        ("incoming", 0x1110),
        ("outgoing", 0x2020),
    ]
    assert result.edges[0].caller_name == "cldflt!CallerA"
    assert result.edges[-1].callee_name == "cldflt!Callee"
    assert "project_call_xrefs" in result.coverage
    assert "cfg_dominance" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_callgraph_slice"
        for node in ctx.kb.nodes()
    )


def test_windows_project_callgraph_slice_can_limit_outgoing_edges(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            function_va=0x2000,
            direction="outgoing",
            max_edges=1,
        ),
    )

    assert result.incoming_count_total == 2
    assert result.outgoing_count_total == 1
    assert len(result.edges) == 1
    assert result.edges[0].direction == "outgoing"
    assert result.edges[0].callee_va == 0x3000


def test_memory_agent_registers_windows_project_callgraph_slice() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_callgraph_slice" in agent._function_toolset.tools
