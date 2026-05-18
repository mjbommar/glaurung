from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_regression_fixture_catalog import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


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
      pseudocode: "void f(void *out, ULONG len) { RtlCopyMemory(out, Src, len); }"
    - id: with_probe
      expected: negative
      description: ProbeForWrite before copy.
      pseudocode: "void f(void *out, ULONG len) { ProbeForWrite(out, len, 1); RtlCopyMemory(out, Src, len); }"
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
      pseudocode: "void f(int c) { switch (c) { case 1: RtlCopyMemory(Out, Src, Len); } }"
    - id: all_cases_gated
      expected: negative
      description: Cases are gated.
      pseudocode: "void f(int c) { ProbeForWrite(Out, Len, 1); RtlCopyMemory(Out, Src, Len); }"
""",
        encoding="utf-8",
    )
    return fixtures


def test_windows_regression_fixture_catalog_filters_primitive_and_expected(
    tmp_path: Path,
) -> None:
    fixtures = _write_fixtures(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            fixtures_path=str(fixtures),
            primitive="unchecked_user_pointer_write",
            expected="positive",
            add_to_kb=True,
        ),
    )

    assert result.fixture_count_total == 2
    assert result.case_count_total == 4
    assert len(result.fixtures) == 1
    fixture = result.fixtures[0]
    assert fixture.id == "unchecked_user_pointer_write"
    assert [case.id for case in fixture.cases] == ["missing_probe"]
    assert fixture.cases[0].expected == "positive"
    assert "RtlCopyMemory" in fixture.cases[0].pseudocode
    assert "reduced semantic shapes" in result.notes[0]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_regression_fixture_catalog"
        for node in ctx.kb.nodes()
    )


def test_windows_regression_fixture_catalog_can_omit_pseudocode(
    tmp_path: Path,
) -> None:
    fixtures = _write_fixtures(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(fixtures_path=str(fixtures), include_pseudocode=False),
    )

    assert len(result.fixtures) == 2
    assert all(case.pseudocode == "" for fixture in result.fixtures for case in fixture.cases)


def test_memory_agent_registers_windows_regression_fixture_catalog() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_regression_fixture_catalog" in agent._function_toolset.tools
