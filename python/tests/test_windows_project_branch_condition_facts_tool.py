from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_branch_condition_facts import build_tool


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
    conn.executescript(
        """
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
"""
    )
    conn.executemany(
        "INSERT INTO basic_blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 0x1000, "entry", 0x1000, 0x1010, 2, 1, 0),
            (1, 0x1000, "gate", 0x1010, 0x1020, 2, 0, 0),
        ],
    )
    conn.executemany(
        "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                1,
                0x1000,
                "entry",
                0x1008,
                "je",
                '["0x1010"]',
                0x1004,
                "cmp",
                '["rcx", "0"]',
                "equal",
                "gate",
                None,
                0,
            ),
            (
                1,
                0x1000,
                "gate",
                0x1018,
                "jne",
                '["0x1020"]',
                0x1014,
                "test",
                '["rdx", "rdx"]',
                "not_equal",
                "sink",
                None,
                0,
            ),
        ],
    )
    conn.commit()
    conn.close()
    return project


def test_windows_project_branch_condition_facts_returns_structured_rows(
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
            block_id="entry",
            add_to_kb=True,
        ),
    )

    assert result.scanned_fact_count == 1
    assert result.returned_fact_count == 1
    assert result.coverage == ["branch_conditions"]
    fact = result.facts[0]
    assert fact.block_id == "entry"
    assert fact.block_start_va == 0x1000
    assert fact.branch_mnemonic == "je"
    assert fact.branch_operands == ["0x1010"]
    assert fact.compare_mnemonic == "cmp"
    assert fact.compare_operands == ["rcx", "0"]
    assert fact.condition_kind == "equal"
    assert fact.inverse_condition_kind == "not_equal"
    assert fact.target_predicate == "rcx == 0"
    assert fact.fallthrough_predicate == "rcx != 0"
    assert fact.target_block_id == "gate"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_branch_condition_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_project_branch_condition_facts_filters_path_blocks(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            path_block_ids=["gate"],
            max_rows=8,
        ),
    )

    assert [fact.block_id for fact in result.facts] == ["gate"]
    assert result.facts[0].on_supplied_path is True
    assert result.facts[0].compare_mnemonic == "test"
    assert result.facts[0].target_predicate == "rdx != 0"
    assert result.facts[0].fallthrough_predicate == "rdx == 0"


def test_memory_agent_registers_windows_project_branch_condition_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_branch_condition_facts" in agent._function_toolset.tools
