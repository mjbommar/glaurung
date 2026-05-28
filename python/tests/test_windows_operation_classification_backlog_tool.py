from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_operation_classification_backlog import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_backlog(tmp_path: Path) -> Path:
    backlog = tmp_path / "pe-operation-classification-backlog.yaml"
    backlog.write_text(
        """
- id: cldflt_hsmp_get_stream_size
  target_id: cldflt
  component: cldflt.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: cldflt_win11_ltsc_v4_operation_coverage_2026_05_18
  symbol: HsmpGetStreamSize
  observed_callsite_count: 220
  caller_function_count: 56
  resolution_kind_counts:
    direct_name: 220
  sample_callers: [HsmFltPreWRITE, HsmFltPreREAD]
  triage_category: size_and_stream_state
  candidate_operation_kinds: [size_query, length_gate_input]
  likely_security_relevance: medium
  required_capabilities: [return_value_flow, path_sensitive_argument_values]
  recommended_next_actions:
    - recover return-value uses at caller callsites
    - classify whether returned stream size gates later copy sinks
- id: cldflt_user_request_rundown_protection
  target_id: cldflt
  component: cldflt.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: cldflt_win11_ltsc_v4_operation_coverage_2026_05_18
  symbol: HsmpAcquireUserRequestRundownProtection
  observed_callsite_count: 26
  caller_function_count: 14
  resolution_kind_counts:
    direct_name: 26
  sample_callers: [HsmFltPreWRITE, HsmFltProcessHydrate]
  triage_category: lifetime_and_concurrency
  candidate_operation_kinds: [rundown_acquire, lifetime_gate]
  likely_security_relevance: high
  required_capabilities: [helper_side_effect_summary, cleanup_path_modeling]
  recommended_next_actions:
    - identify matching release helpers and all cleanup exits
- id: tcpip_parser_state
  target_id: tcpip
  component: tcpip.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: tcpip_snapshot
  symbol: TcpParseState
  observed_callsite_count: 8
  caller_function_count: 4
  resolution_kind_counts:
    direct_name: 8
  sample_callers: [TcpReceive]
  triage_category: parser_state
  candidate_operation_kinds: [state_gate]
  likely_security_relevance: high
  required_capabilities: [packet_field_flow]
  recommended_next_actions:
    - classify packet field state transitions
""",
        encoding="utf-8",
    )
    return backlog


def test_windows_operation_classification_backlog_filters_and_adds_evidence(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            backlog_path=str(_write_backlog(tmp_path)),
            target_id="cldflt",
            required_capability="helper_side_effect_summary",
            likely_security_relevance="high",
            add_to_kb=True,
        ),
    )

    assert result.entry_count_total == 3
    assert [entry.id for entry in result.entries] == [
        "cldflt_user_request_rundown_protection"
    ]
    entry = result.entries[0]
    assert entry.symbol == "HsmpAcquireUserRequestRundownProtection"
    assert entry.observed_callsite_count == 26
    assert entry.resolution_kind_counts == {"direct_name": 26}
    assert "lifetime_gate" in entry.candidate_operation_kinds
    assert "cleanup_path_modeling" in entry.required_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_operation_classification_backlog"
        for node in ctx.kb.nodes()
    )
    assert "not sink claims or findings" in result.notes[0]


def test_windows_operation_classification_backlog_sorts_by_callsite_count(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            backlog_path=str(_write_backlog(tmp_path)),
            component="cldflt.sys",
            min_callsite_count=20,
        ),
    )

    assert [entry.id for entry in result.entries] == [
        "cldflt_hsmp_get_stream_size",
        "cldflt_user_request_rundown_protection",
    ]
    assert result.entries[0].observed_callsite_count == 220


def test_memory_agent_registers_windows_operation_classification_backlog() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_operation_classification_backlog" in agent._function_toolset.tools
