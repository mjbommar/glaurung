from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_operation_coverage_summary import build_tool


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
    project = tmp_path / "coverage.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
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
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
            [
                (1, 0x1000, "cldflt!Handler", "[]", "pdb", None, None),
                (1, 0x1100, "cldflt!OtherHandler", "[]", "pdb", None, None),
                (1, 0x2000, "RtlCopyMemory", "[]", "pdb", None, None),
                (
                    1,
                    0x2500,
                    "__imp_RtlCopyMemory",
                    '["ntoskrnl!RtlCopyMemory"]',
                    "iat",
                    None,
                    "import",
                ),
                (1, 0x3000, "KeAcquireSpinLock", "[]", "pdb", None, None),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
            [
                (1, 1, 0x1010, 0x2000, "call", 0x1000),
                (2, 1, 0x1020, 0x2500, "call", 0x1000),
                (3, 1, 0x1030, 0x3000, "call", 0x1000),
                (4, 1, 0x1110, 0x9000, "call", 0x1100),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_operation_coverage_summary_reports_backlog(
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
            add_to_kb=True,
        ),
    )

    assert result.scanned_callsite_count == 4
    assert result.returned_callsite_count == 4
    assert result.operation_callsite_count == 2
    assert result.alias_or_thunk_match_count == 1
    assert result.unmatched_named_callsite_count == 1
    assert result.unmatched_unnamed_callsite_count == 1
    assert result.operation_match_rate == 0.5
    assert result.operation_kind_counts == {"copy": 2}
    assert result.resolution_kind_counts == {
        "direct_name": 3,
        "import_or_thunk_name": 1,
    }
    assert result.unmatched_groups[0].symbol == "KeAcquireSpinLock"
    assert result.unmatched_groups[0].recommended_next_action == (
        "classify callee semantics and add ASB sink metadata if security-relevant"
    )
    assert "operation_match_rate" in result.coverage
    assert "alias_or_import_thunk_operation_match_counts" in result.coverage
    assert "unmatched_project_callsite_summary" in result.coverage
    assert "asb_sink_metadata_for_unmatched_symbols" in result.missing_capabilities
    assert "indirect_call_target_resolution" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_operation_coverage_summary"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_project_operation_coverage_summary() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_operation_coverage_summary" in agent._function_toolset.tools
