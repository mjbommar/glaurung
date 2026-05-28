"""Regression tests for ModelHyperparameters → ModelSettings conversion.

The 2026-05-26 hunt cycle surfaced that `to_model_kwargs()` was spreading
`temperature` directly as a kwarg to `Agent.run()`, which pydantic-ai
rejects with `AbstractAgent.run() got unexpected kwarg 'temperature'`.
That dropped the entire annotated-lift pipeline into heuristic-fallback
mode for the duration of the session.

These tests pin the fix in place.
"""

from __future__ import annotations

import pytest

from glaurung.llm.agents.base import ModelHyperparameters


def test_to_model_settings_returns_dict_compatible_with_pydantic_ai():
    """to_model_settings returns a dict-shaped ModelSettings (TypedDict)."""
    params = ModelHyperparameters(temperature=0.3, max_tokens=1000)
    settings = params.to_model_settings()
    # pydantic-ai 0.7+ defines ModelSettings as a TypedDict, so the
    # runtime value is a plain dict with the expected keys.
    assert isinstance(settings, dict)
    assert settings["temperature"] == 0.3
    assert settings["max_tokens"] == 1000


def test_to_model_settings_passes_temperature():
    """temperature is preserved through the conversion."""
    params = ModelHyperparameters(temperature=0.5)
    settings = params.to_model_settings()
    # ModelSettings is a TypedDict-like; dict access is the canonical
    # way to read its fields in pydantic-ai 0.7+.
    assert settings.get("temperature") == 0.5


def test_to_model_settings_passes_max_tokens_under_correct_key():
    """max_tokens (not max_output_tokens) is the pydantic-ai field name."""
    params = ModelHyperparameters(max_tokens=65536)
    settings = params.to_model_settings()
    assert settings.get("max_tokens") == 65536
    # Sanity: the old wrong key must NOT be present.
    assert "max_output_tokens" not in settings


def test_to_model_settings_omits_unset_fields():
    """Fields left as None do not appear in the ModelSettings."""
    params = ModelHyperparameters()  # All defaults
    settings = params.to_model_settings()
    # top_p was None -> not in settings
    assert "top_p" not in settings
    # max_tokens was None -> not in settings
    assert "max_tokens" not in settings


def test_to_model_settings_drops_top_k():
    """top_k is not a pydantic-ai ModelSettings field; must be dropped."""
    params = ModelHyperparameters(top_k=10)
    settings = params.to_model_settings()
    assert "top_k" not in settings


def test_to_model_settings_passes_all_supported_fields():
    """Round-trip for every supported field."""
    params = ModelHyperparameters(
        temperature=0.7,
        top_p=0.9,
        max_tokens=2048,
        presence_penalty=0.1,
        frequency_penalty=0.2,
        seed=42,
    )
    settings = params.to_model_settings()
    assert settings.get("temperature") == 0.7
    assert settings.get("top_p") == 0.9
    assert settings.get("max_tokens") == 2048
    assert settings.get("presence_penalty") == 0.1
    assert settings.get("frequency_penalty") == 0.2
    assert settings.get("seed") == 42


def test_pydantic_ai_agent_accepts_model_settings_at_run():
    """Smoke test: pydantic-ai Agent.run() accepts model_settings= kwarg.

    This is the assumption the fix is built on. If pydantic-ai ever
    renames `model_settings`, this test catches it immediately rather
    than letting the regression land in the agent layer silently.
    """
    from pydantic_ai import Agent
    import inspect

    # Pydantic-ai's Agent.run signature must accept model_settings=
    sig = inspect.signature(Agent.run)
    assert "model_settings" in sig.parameters, (
        "pydantic-ai Agent.run() no longer accepts model_settings= kwarg; "
        "the single_pass / iterative_refinement runner needs to be revisited."
    )


def test_to_model_kwargs_deprecated_uses_correct_key():
    """Even the deprecated to_model_kwargs() emits the right max_tokens key.

    Some legacy callers may still use this method via a custom wrapper.
    Make sure the wrong-key bug (max_output_tokens) is fixed there too.
    """
    params = ModelHyperparameters(max_tokens=4096)
    kwargs = params.to_model_kwargs()
    assert kwargs.get("max_tokens") == 4096
    assert "max_output_tokens" not in kwargs
