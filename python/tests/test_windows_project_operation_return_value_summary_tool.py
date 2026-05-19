from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_operation_return_value_summary import build_tool


class _Addr:
    def __init__(self, value: int) -> None:
        self.value = value


class _Insn:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Addr(va)
        self.mnemonic = mnemonic
        self.operands = operands


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
  symbols: [RtlCopyMemory]
  sink_kind: copy
  effects: [writes_destination_range]
  arg_roles:
    0: destination_buffer
    1: source_buffer
    2: byte_count
  required_gates: [destination_range_valid]
""",
        encoding="utf-8",
    )
    return sinks


def _write_backlog(tmp_path: Path) -> Path:
    backlog = tmp_path / "pe-operation-classification-backlog.yaml"
    backlog.write_text(
        """
- id: cldflt_hsmp_get_stream_size
  target_id: cldflt
  component: cldflt.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: cldflt_snapshot
  symbol: HsmpGetStreamSize
  observed_callsite_count: 220
  caller_function_count: 56
  resolution_kind_counts:
    direct_name: 220
  sample_callers: [HsmFltPreWRITE]
  triage_category: size_and_stream_state
  candidate_operation_kinds: [size_query, length_gate_input]
  likely_security_relevance: medium
  required_capabilities: [return_value_flow, path_sensitive_argument_values]
  recommended_next_actions:
    - recover return-value uses at caller callsites
- id: cldflt_user_request_rundown_protection
  target_id: cldflt
  component: cldflt.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: cldflt_snapshot
  symbol: HsmpAcquireUserRequestRundownProtection
  observed_callsite_count: 26
  caller_function_count: 14
  resolution_kind_counts:
    direct_name: 26
  sample_callers: [HsmFltPreREAD]
  triage_category: lifetime_and_concurrency
  candidate_operation_kinds: [rundown_acquire, lifetime_gate]
  likely_security_relevance: high
  required_capabilities: [helper_side_effect_summary, cleanup_path_modeling]
  recommended_next_actions:
    - identify matching release helpers and all cleanup exits
""",
        encoding="utf-8",
    )
    return backlog


def _write_project(tmp_path: Path) -> Path:
    project = tmp_path / "backlog.glaurung"
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
                (1, 0x1000, "HsmFltPreWRITE", "[]", "pdb", None, None),
                (1, 0x1100, "HsmFltPreREAD", "[]", "pdb", None, None),
                (1, 0x2000, "HsmpGetStreamSize", "[]", "pdb", None, None),
                (1, 0x2100, "HsmpAcquireUserRequestRundownProtection", "[]", "pdb", None, None),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
            [
                (1, 1, 0x1010, 0x2000, "call", 0x1000),
                (2, 1, 0x1020, 0x2000, "call", 0x1000),
                (3, 1, 0x1110, 0x2100, "call", 0x1100),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_operation_return_value_summary_samples_backlog_callsites(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1010, "call", ["0x2000"]),
            _Insn(0x1015, "test", ["rax", "rax"]),
            _Insn(0x1018, "je", ["0x1030"]),
            _Insn(0x1020, "call", ["0x2000"]),
            _Insn(0x1025, "mov", ["rcx", "rax"]),
            _Insn(0x1029, "call", ["0x3000"]),
        ]

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            sinks_path=str(_write_sinks(tmp_path)),
            backlog_path=str(_write_backlog(tmp_path)),
            target_id="cldflt",
            max_callsites_per_entry=2,
            add_to_kb=True,
        ),
    )

    assert result.scanned_callsite_count == 3
    assert result.backlog_entry_count_total == 2
    assert result.matched_backlog_entry_count == 1
    assert result.matched_project_callsite_count == 2
    assert result.sampled_callsite_count == 2
    assert "local_return_value_use_snapshots" in result.coverage
    assert "return_value_check_summary" in result.coverage
    assert "return_value_branch_summary" in result.coverage

    group = result.groups[0]
    assert group.symbol == "HsmpGetStreamSize"
    assert group.project_callsite_count == 2
    assert group.sampled_callsite_count == 2
    assert group.checked_callsite_count == 1
    assert group.branch_related_callsite_count == 1
    assert group.use_kind_counts["null_or_status_check"] == 1
    assert group.use_kind_counts["stored_to_register"] == 1
    assert group.use_kind_counts["passed_as_argument"] == 1
    assert [sample.callsite_va for sample in group.samples] == [0x1010, 0x1020]
    assert group.samples[0].first_use_kind == "null_or_status_check"
    assert group.samples[1].first_use_kind == "stored_to_register"
    assert "path_sensitive_return_value_flow" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_operation_return_value_summary"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_project_operation_return_value_summary() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_operation_return_value_summary" in agent._function_toolset.tools
