from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_operation_return_value_snapshots import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_snapshots(tmp_path: Path) -> Path:
    snapshots = tmp_path / "pe-operation-return-value-snapshots.yaml"
    snapshots.write_text(
        """
- id: cldflt_win11_ltsc_v4_operation_return_value_2026_05_19
  target_id: cldflt
  component: cldflt.sys
  build_label: win11-ltsc-v4
  binary_id: 1
  binary_path: /corpus/cldflt.sys
  binary_sha256: "00"
  project_path: /projects/cldflt.glaurung
  backlog_path: data/kg/pe-operation-classification-backlog.yaml
  sinks_path: data/kg/pe-sinks.yaml
  source_backlog_snapshot_id: cldflt_backlog
  tool: windows_project_operation_return_value_summary
  tool_commit: d63eefb
  generated_on: "2026-05-19"
  scanned_callsite_count: 4666
  backlog_entry_count_total: 5
  matched_backlog_entry_count: 1
  matched_project_callsite_count: 220
  sampled_callsite_count: 32
  coverage: [project_backlog_callsite_evidence, local_return_value_use_snapshots]
  missing_capabilities: [path_sensitive_return_value_flow]
  notes: [bounded local sample]
  groups:
    - backlog_id: cldflt_hsmp_get_stream_size
      symbol: HsmpGetStreamSize
      triage_category: size_and_stream_state
      candidate_operation_kinds: [size_query, length_gate_input]
      likely_security_relevance: medium
      required_capabilities: [return_value_flow, path_sensitive_argument_values]
      metadata_observed_callsite_count: 220
      project_callsite_count: 220
      sampled_callsite_count: 32
      project_caller_function_count: 56
      sample_callers: [HsmFltPreWRITE, HsmFltPreREAD]
      use_kind_counts:
        null_or_status_check: 1
        stored_to_memory: 7
        clobbered_by_write: 11
      checked_callsite_count: 2
      branch_related_callsite_count: 2
      clobbered_callsite_count: 17
      ignored_callsite_count: 0
      sample_return_uses:
        - callsite_va: "0x1c00040b8"
          caller_name: HsmFltPreWRITE
          first_use_kind: stored_to_memory
          coverage: [project_call_xref, nearby_disassembly]
          uses:
            - use_kind: stored_to_memory
              instruction_va: "0x1c00040e4"
              instruction_text: "mov rsp:[rsp + 0x30], rax"
              branch_va: null
              branch_text: null
              expression: "rsp:[rsp + 0x30]"
        - callsite_va: "0x1c00042c5"
          caller_name: HsmpRecallInitiateHydrationEx
          first_use_kind: null_or_status_check
          coverage: [project_call_xref, return_value_check]
          uses:
            - use_kind: null_or_status_check
              instruction_va: "0x1c00042ca"
              instruction_text: "test rax, rax"
              branch_va: "0x1c00042cd"
              branch_text: "je 0x1c00044c4"
              expression: "rax, rax"
      recommended_next_actions:
        - classify whether returned stream size gates later copy sinks
      notes: sample note
""",
        encoding="utf-8",
    )
    return snapshots


def test_windows_operation_return_value_snapshots_filters_and_adds_evidence(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            snapshots_path=str(_write_snapshots(tmp_path)),
            target_id="cldflt",
            backlog_id="cldflt_hsmp_get_stream_size",
            use_kind="null_or_status_check",
            max_samples_per_group=1,
            add_to_kb=True,
        ),
    )

    assert result.snapshot_count_total == 1
    assert result.returned_snapshot_count == 1
    assert result.returned_group_count == 1
    assert result.returned_sample_count == 1
    snapshot = result.snapshots[0]
    assert snapshot.tool_commit == "d63eefb"
    assert snapshot.matched_project_callsite_count == 220
    group = snapshot.groups[0]
    assert group.symbol == "HsmpGetStreamSize"
    assert group.use_kind_counts["null_or_status_check"] == 1
    assert group.sample_return_uses[0].callsite_va == "0x1c00042c5"
    assert group.sample_return_uses[0].uses[0].branch_va == "0x1c00042cd"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_operation_return_value_snapshots"
        for node in ctx.kb.nodes()
    )
    assert "not interprocedural return-flow proof" in result.notes[0]


def test_windows_operation_return_value_snapshots_filters_empty_groups(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            snapshots_path=str(_write_snapshots(tmp_path)),
            symbol="HsmpGetStreamSize",
            use_kind="passed_as_argument",
        ),
    )

    assert result.returned_snapshot_count == 0
    assert result.returned_group_count == 0


def test_memory_agent_registers_windows_operation_return_value_snapshots() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_operation_return_value_snapshots" in agent._function_toolset.tools
