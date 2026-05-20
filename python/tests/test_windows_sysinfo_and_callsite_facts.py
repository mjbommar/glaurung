from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb import windows_callsite_facts, windows_sysinfo
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_project_sysinfo_dispatch_facts import (
    build_tool as build_sysinfo_dispatch_tool,
)
from glaurung.llm.tools.windows_project_zero_length_write_paths import (
    build_tool as build_zero_length_write_paths_tool,
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.sys"
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
    fallthrough_block_id TEXT
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
        "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, NULL, NULL)",
        [
            (1, 0x1000, "ExpQuerySystemInformation", "pdb"),
            (1, 0x2000, "CmQueryBuildVersionInformation", "pdb"),
            (1, 0x3000, "ExpGetProcessInformation", "pdb"),
        ],
    )
    conn.executemany(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        [
            (1, 1, 0x1014, 0x2000, "call", 0x1000),
            (2, 1, 0x1024, 0x3000, "call", 0x1000),
        ],
    )
    conn.executemany(
        "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                1,
                0x1000,
                "bb0",
                0x1008,
                "je",
                '["0x1018"]',
                0x1004,
                "cmp",
                '["eax", "253"]',
                "equal",
                "bb1",
                "bb2",
            ),
            (
                1,
                0x1000,
                "bb2",
                0x101C,
                "jne",
                '["0x1030"]',
                0x1018,
                "cmp",
                '["r9d", "0"]',
                "not_equal",
                "bb3",
                "bb4",
            ),
        ],
    )
    conn.execute(
        "INSERT INTO function_boundaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', 0)",
        (1, 1, 0x3000, 0x3100, 0x100, "pdb", 0.95, "ExpGetProcessInformation"),
    )
    conn.commit()
    conn.close()
    return project


def test_windows_sysinfo_dispatch_indexer_persists_first_class_rows(
    tmp_path: Path,
) -> None:
    project = _write_project(tmp_path)
    kb = PersistentKnowledgeBase.open(project)
    try:
        count = windows_sysinfo.index_sysinfo_dispatch_facts(kb)
        assert count == 2
        count = windows_sysinfo.index_sysinfo_dispatch_facts(kb)
        assert count == 2
        rows = windows_sysinfo.list_sysinfo_dispatch_facts(kb)
    finally:
        kb.close()

    assert [
        (row.information_class, row.information_class_name, row.helper_name)
        for row in rows
    ] == [
        (222, "SystemBuildVersionInformation", "CmQueryBuildVersionInformation"),
        (253, "SystemProcessInformationExtension", "ExpGetProcessInformation"),
    ]
    assert rows[0].callsite_va == 0x1014
    assert rows[1].callsite_va == 0x1024
    assert rows[0].dispatcher_name == "ExpQuerySystemInformation"


def test_windows_project_sysinfo_dispatch_facts_tool_queries_project_rows(
    tmp_path: Path,
) -> None:
    project = _write_project(tmp_path)
    kb = PersistentKnowledgeBase.open(project)
    try:
        windows_sysinfo.index_sysinfo_dispatch_facts(kb)
    finally:
        kb.close()

    ctx = _ctx(tmp_path)
    tool = build_sysinfo_dispatch_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(project_path=str(project), information_class=253),
    )

    assert result.dispatch_count == 1
    assert (
        result.dispatches[0].information_class_name
        == "SystemProcessInformationExtension"
    )
    assert result.dispatches[0].helper_name == "ExpGetProcessInformation"
    assert "sysinfo_dispatch" in result.coverage


def test_memory_agent_registers_windows_project_sysinfo_dispatch_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_sysinfo_dispatch_facts" in agent._function_toolset.tools
    assert "windows_project_zero_length_write_paths" in agent._function_toolset.tools


def test_windows_project_zero_length_write_paths_proves_zero_to_write_helper(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "sample.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)
    kb = PersistentKnowledgeBase.open(project)
    try:
        windows_callsite_facts.persist_callsite_argument_facts(
            kb,
            binary_id=1,
            callsite_va=0x1024,
            arguments=[
                {
                    "index": 3,
                    "register_name": "r9",
                    "role": "arg3",
                    "expression": "0",
                    "value_role": "zero_or_null",
                    "confidence": 0.82,
                }
            ],
        )
        windows_callsite_facts.index_callsite_path_conditions(kb)
    finally:
        kb.close()

    def fake_decompile_range_at(*_args, **_kwargs):
        return """
fn sub_3000(arg0, arg1, arg2, arg3) {
  RtlCopyMemory(arg0, arg1, arg2);
}
"""

    monkeypatch.setattr(g.ir, "decompile_range_at", fake_decompile_range_at)
    ctx = _ctx(tmp_path)
    tool = build_zero_length_write_paths_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            callsite_va=0x1024,
            callee_name="ExpGetProcessInformation",
        ),
    )

    assert result.path_count == 1
    path = result.paths[0]
    assert path.callsite_va == 0x1024
    assert path.callee_name == "ExpGetProcessInformation"
    assert path.zero_arg_index == 3
    assert "zero_length_or_null_gate" in path.path_condition_roles
    assert "user_buffer_copy" in path.write_primitive_kinds
    assert "callee_write_primitives" in result.coverage


def test_windows_callsite_path_conditions_attach_nearby_branches(
    tmp_path: Path,
) -> None:
    project = _write_project(tmp_path)
    kb = PersistentKnowledgeBase.open(project)
    try:
        count = windows_callsite_facts.index_callsite_path_conditions(kb)
        assert count == 3
        rows = windows_callsite_facts.list_callsite_path_conditions(
            kb,
            callsite_va=0x1024,
        )
    finally:
        kb.close()

    roles = {row.condition_role for row in rows}
    assert "sysinfo_class_gate" in roles
    assert "zero_length_or_null_gate" in roles
    assert all(row.callsite_va == 0x1024 for row in rows)
