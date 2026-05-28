"""Regression tests for the pydantic-ai 1.x ModelSettings shim.

pydantic-ai 1.0 moved sampling parameters (temperature, top_p, max_tokens,
seed, presence/frequency penalty) off Agent.run() top-level kwargs and into
a ``model_settings=ModelSettings(...)`` argument. Glaurung's single_pass and
iterative_refinement agents previously passed those as kwargs, which fails
with ``AbstractAgent.run() got an unexpected keyword argument 'temperature'``.

These tests pin the call shape so future refactors don't regress to kwargs.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from glaurung.llm.agents.base import ExecutionState, ModelHyperparameters


class _FakeAgent:
    """Mimics pydantic-ai's Agent surface used by single_pass / iterative."""

    def __init__(self):
        self.run = AsyncMock(return_value=SimpleNamespace(output="ok"))


def _build_hyperparameters() -> ModelHyperparameters:
    # Non-default values so we can verify they get propagated.
    return ModelHyperparameters(
        temperature=0.5,
        top_p=0.7,
        max_tokens=2048,
        presence_penalty=0.1,
        frequency_penalty=-0.1,
        seed=42,
    )


def test_to_model_kwargs_uses_max_tokens_not_output_tokens():
    """pydantic-ai's ModelSettings expects 'max_tokens', not 'max_output_tokens'.

    A prior implementation emitted 'max_output_tokens' which is silently dropped
    by ModelSettings, defeating the budget cap.
    """
    params = _build_hyperparameters()
    kwargs = params.to_model_kwargs()
    assert "max_tokens" in kwargs
    assert kwargs["max_tokens"] == 2048
    assert "max_output_tokens" not in kwargs


def test_to_model_kwargs_includes_all_supported_fields():
    params = _build_hyperparameters()
    kwargs = params.to_model_kwargs()
    for key in ("temperature", "top_p", "max_tokens",
                "presence_penalty", "frequency_penalty", "seed"):
        assert key in kwargs, f"missing {key}"


def test_modelsettings_accepts_to_model_kwargs_output():
    """The dict produced by ModelHyperparameters.to_model_kwargs must construct
    a pydantic-ai ModelSettings successfully. If the field names drift, this
    fails immediately rather than at the next live agent call."""
    pytest.importorskip("pydantic_ai")
    from pydantic_ai.settings import ModelSettings

    params = _build_hyperparameters()
    kwargs = params.to_model_kwargs()
    settings = ModelSettings(**kwargs)
    # Keys are TypedDict so the only way to check is to round-trip values:
    assert settings["temperature"] == 0.5
    assert settings["max_tokens"] == 2048


@pytest.mark.asyncio
async def test_single_pass_passes_model_settings_not_top_level_kwargs():
    """SinglePassAgent must call agent.run(question, deps=..., model_settings=...)
    with sampling parameters bundled into ModelSettings -- never as raw kwargs."""
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.agents.single_pass import SinglePassAgent, SinglePassConfig

    fake_pyd_agent = _FakeAgent()
    sp = SinglePassAgent(
        base_agent=fake_pyd_agent,
        config=SinglePassConfig(optimize_context=False, pre_populate_kb=False),
        model="anthropic:claude-haiku-4-5",
    )

    # Minimal MemoryContext-shaped object: needs a .kb that supports add_node.
    fake_kb = MagicMock()
    context = SimpleNamespace(kb=fake_kb)

    params = _build_hyperparameters()
    state = ExecutionState()
    await sp._execute_with_monitoring(
        "what is in this file?", context, state, params,
    )

    fake_pyd_agent.run.assert_awaited_once()
    call = fake_pyd_agent.run.await_args
    # First positional arg is the question.
    assert call.args[0] == "what is in this file?"
    # Sampling params MUST NOT appear at the top level.
    forbidden = {"temperature", "top_p", "max_tokens", "presence_penalty",
                 "frequency_penalty", "seed"}
    assert not (forbidden & set(call.kwargs.keys())), (
        f"Sampling kwargs leaked to Agent.run top-level: "
        f"{forbidden & set(call.kwargs.keys())}"
    )
    # And they must appear inside model_settings.
    assert "model_settings" in call.kwargs
    ms = call.kwargs["model_settings"]
    assert ms["temperature"] == 0.5
    assert ms["max_tokens"] == 2048


@pytest.mark.asyncio
async def test_iterative_refinement_passes_model_settings_not_top_level_kwargs():
    """Same constraint for the iterative agent's per-iteration run."""
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.agents.iterative_refinement import (
        IterativeRefinementAgent, IterativeConfig,
    )

    fake_pyd_agent = _FakeAgent()
    it = IterativeRefinementAgent(
        base_agent=fake_pyd_agent,
        config=IterativeConfig(),
        model="anthropic:claude-haiku-4-5",
    )

    fake_kb = MagicMock()
    context = SimpleNamespace(kb=fake_kb)
    state = ExecutionState()
    params = _build_hyperparameters()

    await it._execute_iteration("prompt", context, params, state)

    fake_pyd_agent.run.assert_awaited_once()
    call = fake_pyd_agent.run.await_args
    forbidden = {"temperature", "top_p", "max_tokens", "presence_penalty",
                 "frequency_penalty", "seed"}
    assert not (forbidden & set(call.kwargs.keys())), (
        f"Iterative agent leaked sampling kwargs to run(): "
        f"{forbidden & set(call.kwargs.keys())}"
    )
    assert "model_settings" in call.kwargs
