from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_fact_summary import build_tool


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
CREATE TABLE xref_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    function_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL
);
CREATE TABLE data_xref_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    xref_count INTEGER NOT NULL
);
CREATE TABLE function_prototypes (
    binary_id INTEGER NOT NULL,
    function_name TEXT NOT NULL,
    return_type TEXT,
    params_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (binary_id, function_name)
);
CREATE TABLE stack_frame_vars (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    name TEXT NOT NULL,
    c_type TEXT,
    use_count INTEGER NOT NULL DEFAULT 0,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, function_va, offset)
);
CREATE TABLE comments (
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    body TEXT NOT NULL,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
);
CREATE TABLE basic_blocks (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    start_va INTEGER NOT NULL,
    end_va INTEGER NOT NULL,
    instruction_count INTEGER NOT NULL,
    is_entry INTEGER NOT NULL DEFAULT 0,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id)
);
CREATE TABLE cfg_edges (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    src_block_id TEXT NOT NULL,
    dst_block_id TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'cfg',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, src_block_id, dst_block_id, kind)
);
CREATE TABLE cfg_dominance (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    immediate_dominator_id TEXT,
    immediate_post_dominator_id TEXT,
    reachable_from_entry INTEGER NOT NULL,
    can_reach_exit INTEGER NOT NULL,
    dominator_count INTEGER NOT NULL,
    post_dominator_count INTEGER NOT NULL,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id)
);
CREATE TABLE cfg_dominance_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    function_count INTEGER NOT NULL,
    block_count INTEGER NOT NULL
);
CREATE TABLE cfg_branch_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    branch_va INTEGER NOT NULL,
    branch_mnemonic TEXT NOT NULL,
    branch_operands_json TEXT NOT NULL DEFAULT '[]',
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT NOT NULL DEFAULT '[]',
    condition_kind TEXT NOT NULL,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id, branch_va)
);
CREATE TABLE cfg_branch_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    function_count INTEGER NOT NULL,
    branch_count INTEGER NOT NULL
);
CREATE TABLE function_boundaries (
    boundary_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    end_va INTEGER,
    size INTEGER,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    name TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    indexed_at INTEGER NOT NULL
);
"""
    )
    conn.execute(
        "INSERT INTO binaries VALUES (1, 'abc', 'sample.sys', 'PE', 'x86_64', 64, 1, 0)"
    )
    conn.executemany(
        "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, ?, ?)",
        [
            (1, 0x1000, "nt!Entry", "pdb", None, None),
            (1, 0x2000, "nt!Helper", "pdb", None, None),
        ],
    )
    conn.executemany(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        [
            (1, 1, 0x1010, 0x2000, "call", 0x1000),
            (2, 1, 0x1020, 0x5000, "data_read", 0x1000),
            (3, 1, 0x1030, 0x6000, "data_write", 0x1000),
        ],
    )
    conn.execute("INSERT INTO xref_index_state VALUES (1, 0, 2, 1)")
    conn.execute("INSERT INTO data_xref_index_state VALUES (1, 0, 2)")
    conn.execute(
        "INSERT INTO function_prototypes VALUES (1, 'nt!Entry', 'NTSTATUS', '[]')"
    )
    conn.execute(
        "INSERT INTO stack_frame_vars VALUES (1, 0x1000, -8, 'var_8', 'ULONG', 1, 'auto', 0)"
    )
    conn.execute("INSERT INTO comments VALUES (1, 0x1000, 'entry comment', 'manual', 0)")
    conn.executemany(
        "INSERT INTO basic_blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 0x1000, "entry", 0x1000, 0x1010, 3, 1, 0),
            (1, 0x1000, "sink", 0x1010, 0x1020, 2, 0, 0),
        ],
    )
    conn.execute(
        "INSERT INTO cfg_edges VALUES (1, 0x1000, 'entry', 'sink', 'cfg', 0)"
    )
    conn.executemany(
        "INSERT INTO cfg_dominance VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 0x1000, "entry", None, "sink", 1, 1, 0, 1, 0),
            (1, 0x1000, "sink", "entry", None, 1, 1, 1, 0, 0),
        ],
    )
    conn.execute("INSERT INTO cfg_dominance_index_state VALUES (1, 0, 1, 2)")
    conn.execute(
        "INSERT INTO cfg_branch_facts VALUES "
        "(1, 0x1000, 'entry', 0x1008, 'je', '[\"0x1010\"]', "
        "0x1004, 'cmp', '[\"rcx\", \"0\"]', 'equal', 'sink', NULL, 0)"
    )
    conn.execute("INSERT INTO cfg_branch_index_state VALUES (1, 0, 1, 1)")
    conn.execute(
        "INSERT INTO function_boundaries VALUES "
        "(1, 1, 0x1000, 0x1020, 0x20, 'pdb', 0.95, 'nt!Entry', '{}', 0)"
    )
    conn.commit()
    conn.close()
    return project


def test_windows_project_fact_summary_counts_project_facts(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            function_va=0x1000,
            add_to_kb=True,
        ),
    )

    assert result.counts.function_name_count == 2
    assert result.counts.call_xref_count == 1
    assert result.counts.data_read_xref_count == 1
    assert result.counts.data_write_xref_count == 1
    assert result.counts.function_prototype_count == 1
    assert result.counts.basic_block_count == 2
    assert result.counts.cfg_edge_count == 1
    assert result.counts.cfg_dominance_count == 2
    assert result.counts.cfg_branch_fact_count == 1
    assert result.counts.function_boundary_count == 1
    assert result.functions[0].canonical == "nt!Entry"
    assert result.functions[0].call_out_count == 1
    assert result.functions[0].stack_var_count == 1
    assert result.xrefs[0].kind == "call"
    assert "function_names" in result.coverage
    assert "call_xrefs" in result.coverage
    assert "data_xrefs" in result.coverage
    assert "cfg" in result.coverage
    assert "cfg_dominance" in result.coverage
    assert "branch_conditions" in result.coverage
    assert "function_boundaries" in result.coverage
    assert "persisted_cfg" not in result.missing_capabilities
    assert "cfg_dominance" not in result.missing_capabilities
    assert "branch_conditions" not in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_fact_summary"
        for node in ctx.kb.nodes()
    )


def test_windows_project_fact_summary_filters_function_name(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            function_name_contains="helper",
        ),
    )

    assert [function.canonical for function in result.functions] == ["nt!Helper"]


def test_memory_agent_registers_windows_project_fact_summary() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_fact_summary" in agent._function_toolset.tools
