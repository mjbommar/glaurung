"""Smoke tests for the LLM config and model-id resolution.

These tests do NOT make network calls. They only verify that the config
layer wires the expected model IDs and that `preferred_model()` picks the
right default given credentials.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from glaurung.llm.config import LLMConfig


def test_default_model_is_gpt_5_4_mini():
    cfg = LLMConfig()
    assert cfg.default_model == "openai:gpt-5.4-mini"


def test_fallback_model_is_claude_haiku_4_5():
    cfg = LLMConfig()
    assert cfg.fallback_model == "anthropic:claude-haiku-4-5"


def test_preferred_model_keeps_openai_default_when_both_keys_present():
    with patch.dict(
        os.environ, {"ANTHROPIC_API_KEY": "sk-x", "OPENAI_API_KEY": "sk-y"}
    ):
        cfg = LLMConfig()
        assert cfg.preferred_model() == "openai:gpt-5.4-mini"


def test_preferred_model_uses_openai_default_without_anthropic_key():
    # Clear Anthropic credentials and retain the default provider.
    env = {k: v for k, v in os.environ.items() if "ANTHROPIC" not in k}
    env["OPENAI_API_KEY"] = "sk-only-openai"
    with patch.dict(os.environ, env, clear=True):
        cfg = LLMConfig()
        assert cfg.preferred_model() == "openai:gpt-5.4-mini"


def test_preferred_model_returns_default_when_no_keys():
    env = {
        k: v
        for k, v in os.environ.items()
        if not any(p in k for p in ("ANTHROPIC", "OPENAI", "GOOGLE", "GEMINI"))
    }
    with patch.dict(os.environ, env, clear=True):
        cfg = LLMConfig()
        # No creds — returns the declared default.
        assert cfg.preferred_model() == cfg.default_model


def test_env_override_still_works():
    with patch.dict(os.environ, {"GLAURUNG_LLM_MODEL": "openai:gpt-5.5"}):
        cfg = LLMConfig()
        assert cfg.default_model == "openai:gpt-5.5"


def test_pydantic_ai_agent_can_be_constructed_with_policy_models():
    """Offline — just verify the string model IDs are accepted by Agent()."""
    from pydantic_ai import Agent

    # Neither call makes a network request; they only initialise the model
    # configuration. If pydantic-ai ever drops support for these ID shapes
    # the construction itself will raise, catching a silent breakage.
    # Current provider clients validate credentials during construction.
    # Dummy values are sufficient because this test performs no requests.
    with patch.dict(
        os.environ,
        {"OPENAI_API_KEY": "sk-test", "ANTHROPIC_API_KEY": "sk-ant-test"},
    ):
        Agent(model="openai:gpt-5.4-mini", system_prompt="test")
        Agent(model="anthropic:claude-haiku-4-5", system_prompt="test")
