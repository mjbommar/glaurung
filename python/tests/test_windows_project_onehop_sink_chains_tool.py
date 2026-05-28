from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_onehop_sink_chains import build_tool


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
"""
        )
        conn.execute(
            "INSERT INTO binaries VALUES (1, 'sha256', 'driver.sys', 'PE', 'x86_64', 64, 16, 0)"
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x2000, "CopyHelper"),
                (0x3000, "CleanupHelper"),
                (0x5000, "RtlCopyMemory"),
                (0x6000, "IoCompleteRequest"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, ?, ?, ?, ?, 0)",
            [
                (1, 0x1100, 0x2000, "call", 0x1000),
                (2, 0x1110, 0x3000, "call", 0x1000),
                (3, 0x2100, 0x5000, "call", 0x2000),
                (4, 0x3100, 0x6000, "call", 0x3000),
                (5, 0x2120, 0x7000, "data_read", 0x2000),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def _write_sinks(tmp_path: Path) -> Path:
    sinks = tmp_path / "pe-sinks.yaml"
    sinks.write_text(
        """
- id: rtl_copy_memory
  symbols: [RtlCopyMemory, memcpy]
  sink_kind: copy
  effects: [writes_destination_range, reads_source_range]
  arg_roles:
    0: destination_buffer
    1: source_buffer
    2: byte_count
  required_gates: [destination_range_valid, byte_count_bounded]
- id: io_complete_request
  symbols: [IoCompleteRequest]
  sink_kind: completion
  effects: [completes_irp, transfers_irp_ownership]
  arg_roles:
    0: irp
    1: priority_boost
  required_gates: [no_later_irp_access]
""",
        encoding="utf-8",
    )
    return sinks


def test_windows_project_onehop_sink_chains_maps_helper_to_sink(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            sinks_path=str(_write_sinks(tmp_path)),
            caller_function_name="DriverDispatch",
            sink_kind="copy",
            add_to_kb=True,
        ),
    )

    assert result.scanned_helper_call_count == 2
    assert result.scanned_helper_sink_call_count == 2
    assert result.chain_count == 1
    chain = result.chains[0]
    assert chain.caller_name == "DriverDispatch"
    assert chain.helper_callsite_va == 0x1100
    assert chain.helper_name == "CopyHelper"
    assert chain.sink_callsite_va == 0x2100
    assert chain.sink_symbol == "RtlCopyMemory"
    assert chain.sink_kind == "copy"
    assert chain.sink_arg_roles == {
        0: "destination_buffer",
        1: "source_buffer",
        2: "byte_count",
    }
    assert chain.required_gates == ["destination_range_valid", "byte_count_bounded"]
    assert "project_onehop_sink_chains" in result.coverage
    assert "interprocedural_value_equivalence" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_onehop_sink_chains"
        for node in ctx.kb.nodes()
    )


def test_windows_project_onehop_sink_chains_filters_helper(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            sinks_path=str(_write_sinks(tmp_path)),
            helper_function_name="CleanupHelper",
        ),
    )

    assert result.scanned_helper_call_count == 1
    assert result.chain_count == 1
    assert result.chains[0].helper_name == "CleanupHelper"
    assert result.chains[0].sink_kind == "completion"


def test_memory_agent_registers_windows_project_onehop_sink_chains() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_onehop_sink_chains" in agent._function_toolset.tools
