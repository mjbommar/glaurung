from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_cfg_dominance import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_project_cfg(tmp_path: Path) -> Path:
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
    conn.executemany(
        "INSERT INTO basic_blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 0x1000, "entry", 0x1000, 0x1010, 2, 1, 0),
            (1, 0x1000, "gate", 0x1010, 0x1020, 2, 0, 0),
            (1, 0x1000, "sink", 0x1020, 0x1030, 2, 0, 0),
        ],
    )
    conn.executemany(
        "INSERT INTO cfg_edges VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, 0x1000, "entry", "gate", "cfg", 0),
            (1, 0x1000, "gate", "sink", "cfg", 0),
        ],
    )
    conn.commit()
    conn.close()
    return project


def test_windows_cfg_dominance_reports_same_block(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            function_va=0x1000,
            gate_va=0x1010,
            sink_va=0x1018,
            cfg_blocks=[
                {
                    "id": "entry",
                    "start_va": 0x1000,
                    "end_va": 0x1020,
                    "successor_ids": ["gate"],
                },
                {
                    "id": "gate",
                    "start_va": 0x2000,
                    "end_va": 0x2050,
                    "successor_ids": ["sink"],
                    "predecessor_ids": ["entry"],
                },
                {
                    "id": "sink",
                    "start_va": 0x3000,
                    "end_va": 0x3050,
                    "predecessor_ids": ["gate"],
                },
            ],
            add_to_kb=True,
        ),
    )

    assert result.status == "same_block"
    assert result.gate_block_id == "entry"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_cfg_dominance"
        for node in ctx.kb.nodes()
    )


def test_windows_cfg_dominance_reports_gate_dominates_sink(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            gate_va=0x2010,
            sink_va=0x3010,
            cfg_blocks=[
                {
                    "id": "entry",
                    "start_va": 0x1000,
                    "end_va": 0x1020,
                    "successor_ids": ["gate"],
                },
                {
                    "id": "gate",
                    "start_va": 0x2000,
                    "end_va": 0x2020,
                    "successor_ids": ["sink"],
                    "predecessor_ids": ["entry"],
                },
                {
                    "id": "sink",
                    "start_va": 0x3000,
                    "end_va": 0x3020,
                    "predecessor_ids": ["gate"],
                },
            ],
        ),
    )

    assert result.status == "dominated"
    assert result.gate_block_id == "gate"
    assert result.sink_block_id == "sink"
    assert "dominates" in result.reason


def test_windows_cfg_dominance_reports_not_dominated(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            gate_va=0x2010,
            sink_va=0x3010,
            cfg_blocks=[
                {
                    "id": "entry",
                    "start_va": 0x1000,
                    "end_va": 0x1020,
                    "successor_ids": ["gate", "bypass"],
                },
                {
                    "id": "gate",
                    "start_va": 0x2000,
                    "end_va": 0x2020,
                    "successor_ids": ["sink"],
                    "predecessor_ids": ["entry"],
                },
                {
                    "id": "bypass",
                    "start_va": 0x2500,
                    "end_va": 0x2520,
                    "successor_ids": ["sink"],
                    "predecessor_ids": ["entry"],
                },
                {
                    "id": "sink",
                    "start_va": 0x3000,
                    "end_va": 0x3020,
                    "predecessor_ids": ["gate", "bypass"],
                },
            ],
        ),
    )

    assert result.status == "not_dominated"
    assert "does not pass through gate block" in result.reason


def test_windows_cfg_dominance_reads_persisted_project_cfg(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project_cfg(tmp_path)),
            gate_va=0x1014,
            sink_va=0x1024,
        ),
    )

    assert result.status == "dominated"
    assert result.function_va == 0x1000
    assert result.gate_block_id == "gate"
    assert result.sink_block_id == "sink"
    assert result.provenance == ["persisted_project_cfg"]
    assert result.block_count == 3
    assert result.edge_count == 2


def test_memory_agent_registers_windows_cfg_dominance() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_cfg_dominance" in agent._function_toolset.tools
