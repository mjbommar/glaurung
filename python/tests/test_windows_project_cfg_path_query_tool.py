from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_cfg_path_query import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_project_cfg(tmp_path: Path, *, bypass: bool = False) -> Path:
    project = tmp_path / ("bypass.glaurung" if bypass else "covered.glaurung")
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
CREATE TABLE cfg_edges (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    src_block_id TEXT NOT NULL,
    dst_block_id TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'cfg',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, src_block_id, dst_block_id, kind)
);
"""
    )
    blocks = [
        (1, 0x1000, "entry", 0x1000, 0x1010, 2, 1, 0),
        (1, 0x1000, "gate", 0x1010, 0x1020, 2, 0, 0),
        (1, 0x1000, "sink", 0x1020, 0x1030, 2, 0, 0),
    ]
    if bypass:
        blocks.append((1, 0x1000, "bypass", 0x1030, 0x1040, 2, 0, 0))
    conn.executemany("INSERT INTO basic_blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?)", blocks)
    edges = [
        (1, 0x1000, "entry", "gate", "cfg", 0),
        (1, 0x1000, "gate", "sink", "cfg", 0),
    ]
    if bypass:
        edges.extend(
            [
                (1, 0x1000, "entry", "bypass", "cfg", 0),
                (1, 0x1000, "bypass", "sink", "cfg", 0),
            ]
        )
    conn.executemany("INSERT INTO cfg_edges VALUES (?, ?, ?, ?, ?, ?)", edges)
    conn.commit()
    conn.close()
    return project


def test_windows_project_cfg_path_query_reports_covered_gate(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project_cfg(tmp_path)),
            branch_va=0x1004,
            gate_va=0x1014,
            sink_va=0x1024,
            add_to_kb=True,
        ),
    )

    assert result.status == "covered"
    assert result.function_va == 0x1000
    assert result.entry_block_id == "entry"
    assert result.branch_block_id == "entry"
    assert result.gate_block_id == "gate"
    assert result.sink_block_id == "sink"
    assert result.branch_reaches_sink is True
    assert result.entry_reaches_sink is True
    assert result.gate_reaches_sink is True
    assert result.all_paths_to_sink_pass_gate is True
    assert result.bypass_path_block_ids == []
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_cfg_path_query"
        for node in ctx.kb.nodes()
    )


def test_windows_project_cfg_path_query_reports_bypass_path(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project_cfg(tmp_path, bypass=True)),
            gate_va=0x1014,
            sink_va=0x1024,
        ),
    )

    assert result.status == "bypass"
    assert result.all_paths_to_sink_pass_gate is False
    assert result.bypass_path_block_ids == ["entry", "bypass", "sink"]


def test_windows_project_cfg_path_query_can_skip_gate_check(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project_cfg(tmp_path)),
            branch_va=0x1004,
            sink_va=0x1024,
        ),
    )

    assert result.status == "not_requested"
    assert result.entry_reaches_sink is True
    assert result.branch_reaches_sink is True
    assert result.all_paths_to_sink_pass_gate is None


def test_memory_agent_registers_windows_project_cfg_path_query() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_cfg_path_query" in agent._function_toolset.tools
