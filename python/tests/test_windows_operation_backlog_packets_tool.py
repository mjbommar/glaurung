from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_operation_backlog_packets import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_backlog(tmp_path: Path) -> Path:
    path = tmp_path / "pe-operation-classification-backlog.yaml"
    path.write_text(
        """
- id: backlog_copy_driver
  target_id: driver
  component: driver.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: snapshot-driver
  symbol: RtlCopyMemory
  observed_callsite_count: 7
  caller_function_count: 2
  resolution_kind_counts: {import: 7}
  sample_callers: [DriverDispatch]
  triage_category: memory_copy
  candidate_operation_kinds: [copy]
  likely_security_relevance: high
  required_capabilities: [source_arg_roles, destination_range_gate]
  recommended_next_actions:
    - classify destination/source/length argument roles
    - prove required gates before packet promotion
  notes: Classifier backlog entry, not a finding.
- id: backlog_low_relevance
  target_id: other
  component: other.dll
  build_label: win11-ltsc-v4
  source_snapshot_id: snapshot-other
  symbol: TraceLoggingWrite
  observed_callsite_count: 3
  caller_function_count: 1
  resolution_kind_counts: {import: 3}
  sample_callers: [OtherFunction]
  triage_category: telemetry
  candidate_operation_kinds: [logging]
  likely_security_relevance: low
  required_capabilities: [operation_classification]
  recommended_next_actions:
    - deprioritize unless new evidence appears
""",
        encoding="utf-8",
    )
    return path


def test_windows_operation_backlog_packets_emit_review_packets(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            backlog_path=str(_write_backlog(tmp_path)),
            target_id="driver",
            max_packets=4,
            add_to_kb=True,
        ),
    )

    assert result.backlog_entry_count_total == 2
    assert result.matched_backlog_entry_count == 1
    assert result.packet_count == 1
    packet = result.packets[0]
    assert packet.candidate_id == "backlog-backlog_copy_driver-rtlcopymemory"
    assert packet.binary == "driver.sys"
    assert packet.build == "win11-ltsc-v4"
    assert packet.entrypoint == "DriverDispatch"
    assert packet.source_refinement_status == "missing"
    assert packet.sink_symbol == "RtlCopyMemory"
    assert packet.sink_kind == "copy"
    assert "destination_range_gate" in packet.required_gates
    assert "destination_range_gate" in packet.missing_required_gates
    assert packet.promotion_preconditions_met is False
    assert any("missing project fact" in item for item in packet.promotion_blockers)
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_operation_backlog_packets"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_operation_backlog_packets() -> None:
    agent = create_memory_agent()

    assert "windows_operation_backlog_packets" in agent._function_toolset.tools
