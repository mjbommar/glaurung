from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_data_label_facts import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_project(tmp_path: Path) -> Path:
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
CREATE TABLE function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    demangled TEXT,
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
CREATE TABLE data_labels (
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    name TEXT NOT NULL,
    c_type TEXT,
    size INTEGER,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
);
"""
        )
        conn.execute(
            "INSERT INTO binaries VALUES (1, 'sha256', 'driver.sys', 'PE', 'x86_64', 64, 16, 0)"
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x2000, "Helper"),
            ],
        )
        conn.executemany(
            "INSERT INTO data_labels VALUES (1, ?, ?, ?, ?, ?, 0)",
            [
                (0x7000, "gPolicyTable", "POLICY_ENTRY[4]", 64, "pdb_public"),
                (0x7100, "gState", None, None, "manual"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, ?, ?, ?, ?, 0)",
            [
                (1, 0x1010, 0x7000, "data_read", 0x1000),
                (2, 0x1018, 0x7000, "data_write", 0x1000),
                (3, 0x2010, 0x7100, "data_read", 0x2000),
                (4, 0x1020, 0x7200, "data_read", 0x1000),
                (5, 0x3000, 0x9000, "call", 0x1000),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_data_label_facts_reports_label_coverage(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            add_to_kb=True,
        ),
    )

    assert result.binary_id == 1
    assert result.data_label_count == 2
    assert result.data_xref_count == 4
    assert result.labeled_xref_count == 3
    assert result.unlabeled_xref_count == 1
    assert "project_data_xrefs" in result.coverage
    assert "project_data_labels" in result.coverage
    assert "pdb_type_layouts" in result.missing_capabilities
    assert result.labels[0].name == "gPolicyTable"
    assert result.labels[0].xref_count == 2
    assert result.labels[0].read_xref_count == 1
    assert result.labels[0].write_xref_count == 1
    assert result.labels[0].source_function_count == 1
    assert result.xrefs[0].src_function_name == "DriverDispatch"
    assert result.xrefs[0].data_label_name == "gPolicyTable"
    assert result.unlabeled_targets[0].va == 0x7200
    assert result.unlabeled_targets[0].sample_source_vas == [0x1020]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_data_label_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_project_data_label_facts_filters_function_and_labeled_only(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            function_va=0x1000,
            labeled_only=True,
        ),
    )

    assert result.function_va == 0x1000
    assert result.data_xref_count == 3
    assert result.labeled_xref_count == 2
    assert result.unlabeled_xref_count == 1
    assert result.unlabeled_targets == []
    assert [xref.dst_va for xref in result.xrefs] == [0x7000, 0x7000]
    assert all(xref.data_label_name == "gPolicyTable" for xref in result.xrefs)


def test_memory_agent_registers_windows_project_data_label_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_data_label_facts" in agent._function_toolset.tools
