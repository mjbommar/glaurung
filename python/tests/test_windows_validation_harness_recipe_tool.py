from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_validation_harness_recipe import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_recipes(tmp_path: Path) -> Path:
    path = tmp_path / "pe-validation-harness-recipes.yaml"
    path.write_text(
        r"""
- id: cldflt_placeholder_policy_recipe
  profile_id: cldflt_cloud_filter_policy
  target_id: cldflt
  component: cldflt.sys
  surfaces: [cloud_filter, registry]
  trigger_kind: cloud_filter_placeholder_policy_sequence
  setup_steps:
    - Restore snapshot.
    - Prepare provider root.
  stock_commands:
    - powershell -File run-cldflt.ps1 -Mode Stock
  current_commands:
    - powershell -File run-cldflt.ps1 -Mode Current
  artifact_requirements:
    - KDNET attach transcript.
    - Registry export.
  known_blockers:
    - KDNET attach proof is not recorded.
  operator_notes:
    - Preserve caller token.
  notes: Unit fixture.
- id: fltmgr_minifilter_lifetime_recipe
  profile_id: fltmgr_filter_callback_lifetime
  target_id: fltmgr
  component: fltmgr.sys
  surfaces: [file_system_filter]
  trigger_kind: minifilter_callback_lifetime_sequence
  setup_steps:
    - Enable verifier.
  stock_commands:
    - powershell -File run-fltmgr.ps1 -Mode Stock
  current_commands:
    - powershell -File run-fltmgr.ps1 -Mode Current
  artifact_requirements:
    - Verifier transcript.
""",
        encoding="utf-8",
    )
    return path


def test_windows_validation_harness_recipe_filters_and_adds_kb(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            recipes_path=str(_write_recipes(tmp_path)),
            component="cldflt.sys",
            surface_id="cloud_filter",
            add_to_kb=True,
        ),
    )

    assert result.recipe_count_total == 2
    assert len(result.recipes) == 1
    recipe = result.recipes[0]
    assert recipe.id == "cldflt_placeholder_policy_recipe"
    assert recipe.profile_id == "cldflt_cloud_filter_policy"
    assert recipe.trigger_kind == "cloud_filter_placeholder_policy_sequence"
    assert any("run-cldflt" in command for command in recipe.stock_commands)
    assert any("Registry export" in item for item in recipe.artifact_requirements)
    assert any("KDNET attach proof" in blocker for blocker in recipe.known_blockers)
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_validation_harness_recipe"
        and node.props["recipe_matches"] == 1
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_validation_harness_recipe() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")
    assert "windows_validation_harness_recipe" in agent._function_toolset.tools
