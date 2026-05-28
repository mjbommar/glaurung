"""Tests for F1: UsageLimits foundation."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from glaurung.llm import config as _config_mod
from glaurung.llm.config import LLMConfig
from glaurung.llm.usage_limits import build_usage_limits, default_max_output_tokens


# ---- LLMConfig defaults ----

def test_llmconfig_has_request_limit_default():
    c = LLMConfig()
    assert c.default_request_limit == 12
    assert c.default_input_tokens_limit == 400_000
    assert c.default_total_tokens_limit == 500_000
    assert c.default_max_output_tokens == 32_768


def test_llmconfig_env_overrides_request_limit():
    with patch.dict(os.environ, {"GLAURUNG_REQUEST_LIMIT": "5"}, clear=False):
        c = LLMConfig()
        assert c.default_request_limit == 5


def test_llmconfig_env_overrides_input_tokens():
    with patch.dict(os.environ, {"GLAURUNG_INPUT_TOKENS_LIMIT": "100000"}, clear=False):
        c = LLMConfig()
        assert c.default_input_tokens_limit == 100_000


def test_llmconfig_env_overrides_total_tokens():
    with patch.dict(os.environ, {"GLAURUNG_TOTAL_TOKENS_LIMIT": "150000"}, clear=False):
        c = LLMConfig()
        assert c.default_total_tokens_limit == 150_000


def test_llmconfig_env_overrides_max_output():
    with patch.dict(os.environ, {"GLAURUNG_MAX_OUTPUT_TOKENS": "16384"}, clear=False):
        c = LLMConfig()
        assert c.default_max_output_tokens == 16_384


def test_llmconfig_invalid_env_logs_and_keeps_default():
    """Garbage env value must NOT crash config init."""
    with patch.dict(os.environ, {"GLAURUNG_REQUEST_LIMIT": "not-a-number"},
                    clear=False):
        c = LLMConfig()
        assert c.default_request_limit == 12  # untouched


# ---- build_usage_limits ----

def test_build_usage_limits_uses_config_defaults_when_no_kwargs():
    ul = build_usage_limits()
    assert ul.request_limit == 12
    assert ul.input_tokens_limit == 400_000
    assert ul.total_tokens_limit == 500_000
    # output_tokens_limit stays None unless explicit (model decides)
    assert ul.output_tokens_limit is None


def test_build_usage_limits_per_call_override_request():
    ul = build_usage_limits(request_limit=4)
    assert ul.request_limit == 4
    assert ul.input_tokens_limit == 400_000  # other defaults preserved


def test_build_usage_limits_per_call_override_all():
    ul = build_usage_limits(
        request_limit=2,
        input_tokens_limit=50_000,
        total_tokens_limit=70_000,
        output_tokens_limit=4_096,
        tool_calls_limit=0,
    )
    assert ul.request_limit == 2
    assert ul.input_tokens_limit == 50_000
    assert ul.total_tokens_limit == 70_000
    assert ul.output_tokens_limit == 4_096
    assert ul.tool_calls_limit == 0


def test_build_usage_limits_model_name_is_accepted_currently_informational():
    """Future revisions may branch on provider; for now the call must
    at least accept the kwarg without error."""
    ul = build_usage_limits(model_name="anthropic:claude-opus-4-7")
    assert ul.request_limit == 12


def test_build_usage_limits_env_override_propagates_through_helper():
    """End-to-end: env var sets config, helper picks it up.

    Note: get_config() caches a singleton, so we patch the cache too.
    """
    _config_mod._config = None  # bust the cached singleton
    try:
        with patch.dict(os.environ, {"GLAURUNG_REQUEST_LIMIT": "3"},
                        clear=False):
            ul = build_usage_limits()
        assert ul.request_limit == 3
    finally:
        _config_mod._config_instance = None


def test_default_max_output_tokens_returns_config_value():
    assert default_max_output_tokens() == 32_768


def test_default_max_output_tokens_respects_env():
    _config_mod._config = None
    try:
        with patch.dict(os.environ, {"GLAURUNG_MAX_OUTPUT_TOKENS": "8192"},
                        clear=False):
            assert default_max_output_tokens() == 8_192
    finally:
        _config_mod._config = None
