from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_replay_regression_fixtures import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_metadata(tmp_path: Path) -> tuple[Path, Path]:
    gates = tmp_path / "pe-gates.yaml"
    gates.write_text(
        """
- id: probeforwrite
  symbols: [ProbeForWrite]
  gate_kind: user_pointer
  proves: [user_pointer_write_range_valid]
  required_conditions: [call_dominates_write_sink]
  invalid_when: [length_is_zero]
""",
        encoding="utf-8",
    )
    sinks = tmp_path / "pe-sinks.yaml"
    sinks.write_text(
        """
- id: rtl_copy_memory
  symbols: [RtlCopyMemory]
  sink_kind: copy
  effects: [writes_destination_range, reads_source_range]
  arg_roles:
    0: destination_buffer
    1: source_buffer
    2: byte_count
  required_gates: [destination_range_valid, byte_count_bounded]
""",
        encoding="utf-8",
    )
    return gates, sinks


def _write_fixtures(tmp_path: Path) -> Path:
    fixtures = tmp_path / "pe-regression-fixtures.yaml"
    fixtures.write_text(
        """
- id: unchecked_user_pointer_write
  bug_class: validation
  primitive: unchecked_user_pointer_write
  source_roles: [output_buffer, length]
  sink_kinds: [copy]
  required_gates: [destination_range_valid]
  cases:
    - id: missing_probe
      expected: positive
      description: Missing ProbeForWrite.
      pseudocode: |
        void Handler(void *Out, void *Src, ULONG Len) {
            RtlCopyMemory(Out, Src, Len);
        }
    - id: probe_before_copy
      expected: negative
      description: ProbeForWrite before copy.
      pseudocode: |
        void Handler(void *Out, void *Src, ULONG Len) {
            ProbeForWrite(Out, Len, 1);
            RtlCopyMemory(Out, Src, Len);
        }
- id: selector_case_missing_validation
  bug_class: validation
  primitive: selector_case_missing_validation
  source_roles: [selector, output_buffer]
  sink_kinds: [copy]
  required_gates: [destination_range_valid]
  cases:
    - id: missing_case_gate
      expected: positive
      description: One selector case lacks gate.
      pseudocode: |
        void Handler(ULONG InfoClass, void *Out, ULONG Len) {
            switch (InfoClass) {
            case 1:
                ProbeForWrite(Out, Len, 1);
                RtlCopyMemory(Out, SrcA, Len);
                break;
            case 2:
                RtlCopyMemory(Out, SrcB, Len);
                break;
            }
        }
    - id: all_cases_gated
      expected: negative
      description: Cases are gated.
      pseudocode: |
        void Handler(ULONG InfoClass, void *Out, ULONG Len) {
            switch (InfoClass) {
            case 1:
                ProbeForWrite(Out, Len, 1);
                RtlCopyMemory(Out, SrcA, Len);
                break;
            case 2:
                ProbeForWrite(Out, Len, 1);
                RtlCopyMemory(Out, SrcB, Len);
                break;
            }
        }
""",
        encoding="utf-8",
    )
    return fixtures


def _write_unsupported_fixture(tmp_path: Path) -> Path:
    fixtures = tmp_path / "unsupported-fixtures.yaml"
    fixtures.write_text(
        """
- id: future_shape
  bug_class: validation
  primitive: future_unimplemented_primitive
  source_roles: [input]
  sink_kinds: [copy]
  required_gates: [some_gate]
  cases:
    - id: positive_shape
      expected: positive
      description: Shape not implemented yet.
      pseudocode: "void Handler(void) { FutureSink(); }"
    - id: negative_shape
      expected: negative
      description: Control shape not implemented yet.
      pseudocode: "void Handler(void) { return; }"
""",
        encoding="utf-8",
    )
    return fixtures


def test_windows_replay_regression_fixtures_passes_supported_cases(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    fixtures = _write_fixtures(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            fixtures_path=str(fixtures),
            gates_path=str(gates),
            sinks_path=str(sinks),
            add_to_kb=True,
        ),
    )

    assert result.fixture_count == 2
    assert result.case_count == 4
    assert result.passed_count == 4
    assert result.failed_count == 0
    assert result.unsupported_count == 0
    assert {replay.status for replay in result.replays} == {"passed"}
    assert {replay.case_id: replay.detected for replay in result.replays} == {
        "missing_probe": True,
        "probe_before_copy": False,
        "missing_case_gate": True,
        "all_cases_gated": False,
    }
    assert "not live reachability" in result.notes[0]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_replay_regression_fixtures"
        for node in ctx.kb.nodes()
    )


def test_windows_replay_regression_fixtures_marks_unsupported(
    tmp_path: Path,
) -> None:
    fixtures = _write_unsupported_fixture(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(fixtures_path=str(fixtures)),
    )

    assert result.fixture_count == 1
    assert result.case_count == 2
    assert result.passed_count == 0
    assert result.failed_count == 0
    assert result.unsupported_count == 2
    assert {replay.status for replay in result.replays} == {"unsupported"}
    assert all(replay.signal == "unsupported_primitive" for replay in result.replays)


def test_memory_agent_registers_windows_replay_regression_fixtures() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_replay_regression_fixtures" in agent._function_toolset.tools
