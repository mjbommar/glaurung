from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_callsite_facts import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


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
- id: ex_free_pool
  symbols: [ExFreePool, ExFreePoolWithTag]
  sink_kind: free
  effects: [releases_pool_memory, invalidates_pointer]
  arg_roles:
    0: object_pointer
  required_gates: [ownership_established, no_later_use]
""",
        encoding="utf-8",
    )
    return sinks


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
CREATE TABLE function_prototypes (
    binary_id INTEGER NOT NULL,
    function_name TEXT NOT NULL,
    return_type TEXT,
    params_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (binary_id, function_name)
);
"""
    )
    conn.execute(
        "INSERT INTO binaries VALUES (1, 'abc', 'sample.sys', 'PE', 'x86_64', 64, 1, 0)"
    )
    conn.executemany(
        "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, ?, ?)",
        [
            (1, 0x1000, "cldflt!Handler", "pdb", None, None),
            (1, 0x2000, "RtlCopyMemory", "pdb", None, None),
            (1, 0x3000, "ExFreePoolWithTag", "pdb", None, None),
            (1, 0x4000, "cldflt!Helper", "pdb", None, None),
        ],
    )
    conn.executemany(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        [
            (1, 1, 0x1010, 0x2000, "call", 0x1000),
            (2, 1, 0x1020, 0x3000, "call", 0x1000),
            (3, 1, 0x1030, 0x5000, "data_read", 0x1000),
            (4, 1, 0x4010, 0x2000, "call", 0x4000),
        ],
    )
    conn.executemany(
        "INSERT INTO function_prototypes VALUES (?, ?, ?, ?)",
        [
            (1, "RtlCopyMemory", "VOID", '["PVOID dst", "PVOID src", "SIZE_T len"]'),
            (1, "ExFreePoolWithTag", "VOID", '["PVOID ptr", "ULONG tag"]'),
        ],
    )
    conn.commit()
    conn.close()
    return project


def test_windows_project_callsite_facts_reads_project_xrefs(
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
            function_va=0x1000,
            add_to_kb=True,
        ),
    )

    assert result.scanned_call_count == 2
    assert [site.callsite_va for site in result.callsites] == [0x1010, 0x1020]
    assert result.callsites[0].caller_name == "cldflt!Handler"
    assert result.callsites[0].callee_name == "RtlCopyMemory"
    assert result.callsites[0].operation is not None
    assert result.callsites[0].operation.id == "rtl_copy_memory"
    assert result.callsites[0].callee_prototype is not None
    assert "VOID RtlCopyMemory" in result.callsites[0].callee_prototype
    assert "project_call_xrefs" in result.coverage
    assert "operation_metadata" in result.coverage
    assert "call_argument_operands" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_callsite_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_project_callsite_facts_filters_symbol_and_operation(
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
            call_symbol="nt!RtlCopyMemory",
            operation_only=True,
        ),
    )

    assert [site.callsite_va for site in result.callsites] == [0x1010, 0x4010]
    assert all(site.operation and site.operation.id == "rtl_copy_memory" for site in result.callsites)


def test_memory_agent_registers_windows_project_callsite_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_callsite_facts" in agent._function_toolset.tools
