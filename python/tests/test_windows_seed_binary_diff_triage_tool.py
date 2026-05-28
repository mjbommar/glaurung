from __future__ import annotations

from pathlib import Path

import pytest
import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_seed_binary_diff_triage import build_tool


_SWITCHY_V1 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_seeds(tmp_path: Path) -> Path:
    seeds = tmp_path / "pe-vulnerability-seeds.yaml"
    seeds.write_text(
        """
- id: dispatch_bounds_seed
  public_ids: [TEST-0001]
  title: Dispatch bounds seed
  target_id: switchy
  component: switchy
  functions: [dispatch, missing_seed_function]
  surfaces: [local_file]
  attacker_classes: [windows-local-user]
  invariant_family: validation
  primitive: selector_dispatch_without_bounds_gate
  source_roles: [selector]
  expected_gates: [selector_bounded]
  expected_sinks: [case_dispatch]
  diff_signals: [added_selector_bounds_check]
  validation_requirements: [prove_selector_reachability]
  references:
    - kind: other
      title: Synthetic seed
      url: https://example.test/seed
""",
        encoding="utf-8",
    )
    return seeds


def test_windows_seed_binary_diff_triage_reports_seed_function_change(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            seeds_path=str(_write_seeds(tmp_path)),
            public_id="TEST-0001",
        ),
    )

    assert result.seed_count_total == 1
    assert result.matched_seed_count == 1
    record = result.records[0]
    assert record.seed_id == "dispatch_bounds_seed"
    assert record.changed_functions == ["dispatch"]
    assert record.missing_functions == ["missing_seed_function"]
    dispatch = next(fn for fn in record.functions if fn.function == "dispatch")
    assert dispatch.status == "changed"
    assert dispatch.b_size is not None
    assert dispatch.a_size is not None
    assert dispatch.b_size > dispatch.a_size
    assert "does not prove" in result.notes[0]


def test_windows_seed_binary_diff_triage_adds_evidence(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            seeds_path=str(_write_seeds(tmp_path)),
            seed_id="dispatch_bounds_seed",
            add_to_kb=True,
        ),
    )

    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_seed_binary_diff_triage"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_seed_binary_diff_triage() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_seed_binary_diff_triage" in agent._function_toolset.tools
