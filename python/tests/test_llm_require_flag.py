"""Tests for the require_llm hard-fail mode in run_structured_llm.

The 2026-05-26 hunt cycle surfaced multiple agents reporting silent
heuristic-fallback when the LLM was unreachable. Downstream peer-hunt
agents trusted heuristic output as LLM output, producing incorrect
verdicts. The require_llm flag (and GLAURUNG_REQUIRE_LLM env var)
converts the silent fallback into a loud LLMUnavailable exception.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from pydantic import BaseModel

from glaurung.llm.tools._llm_helpers import (
    LLMUnavailable,
    _require_llm_flag,
    run_structured_llm,
)


class DummyOutput(BaseModel):
    answer: str


def _dummy_fallback() -> DummyOutput:
    return DummyOutput(answer="HEURISTIC")


class TestRequireLLMFlagResolution:
    """Precedence: kwarg > env > default(False)."""

    def test_default_is_false(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GLAURUNG_REQUIRE_LLM", None)
            assert _require_llm_flag(None) is False

    @pytest.mark.parametrize("envval", ["1", "true", "yes", "ON", "True"])
    def test_env_var_truthy(self, envval):
        with patch.dict(os.environ, {"GLAURUNG_REQUIRE_LLM": envval}):
            assert _require_llm_flag(None) is True

    @pytest.mark.parametrize("envval", ["0", "false", "no", "", "junk"])
    def test_env_var_falsey(self, envval):
        with patch.dict(os.environ, {"GLAURUNG_REQUIRE_LLM": envval}):
            assert _require_llm_flag(None) is False

    def test_explicit_kwarg_overrides_env(self):
        with patch.dict(os.environ, {"GLAURUNG_REQUIRE_LLM": "1"}):
            assert _require_llm_flag(False) is False
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GLAURUNG_REQUIRE_LLM", None)
            assert _require_llm_flag(True) is True


class TestRequireLLMHardFail:
    """When require_llm=True, fallbacks become exceptions."""

    def test_no_credentials_raises(self):
        """No API key → LLMUnavailable, not heuristic."""
        with patch("glaurung.llm.tools._llm_helpers.can_call_llm",
                   return_value=False):
            with pytest.raises(LLMUnavailable, match="no provider credentials"):
                run_structured_llm(
                    prompt="test",
                    output_type=DummyOutput,
                    system_prompt="sys",
                    fallback=_dummy_fallback,
                    require_llm=True,
                )

    def test_no_credentials_falls_back_when_not_required(self):
        """Default behaviour: silent fallback to heuristic."""
        with patch("glaurung.llm.tools._llm_helpers.can_call_llm",
                   return_value=False):
            result = run_structured_llm(
                prompt="test",
                output_type=DummyOutput,
                system_prompt="sys",
                fallback=_dummy_fallback,
                require_llm=False,
            )
            assert result.answer == "HEURISTIC"

    def test_env_var_triggers_hard_fail(self):
        """GLAURUNG_REQUIRE_LLM=1 → LLMUnavailable on missing creds."""
        with patch("glaurung.llm.tools._llm_helpers.can_call_llm",
                   return_value=False):
            with patch.dict(os.environ, {"GLAURUNG_REQUIRE_LLM": "1"}):
                with pytest.raises(LLMUnavailable):
                    run_structured_llm(
                        prompt="test",
                        output_type=DummyOutput,
                        system_prompt="sys",
                        fallback=_dummy_fallback,
                    )

    def test_nested_event_loop_raises_when_required(self):
        """Inside running loop → LLMUnavailable when required."""
        with patch("glaurung.llm.tools._llm_helpers.can_call_llm",
                   return_value=True), \
             patch("glaurung.llm.tools._llm_helpers.in_running_event_loop",
                   return_value=True):
            with pytest.raises(LLMUnavailable, match="asyncio loop"):
                run_structured_llm(
                    prompt="test",
                    output_type=DummyOutput,
                    system_prompt="sys",
                    fallback=_dummy_fallback,
                    require_llm=True,
                )

    def test_warning_emitted_on_fallback(self, capsys):
        """Non-required fallback should still emit a stderr warning."""
        with patch("glaurung.llm.tools._llm_helpers.can_call_llm",
                   return_value=False):
            run_structured_llm(
                prompt="test",
                output_type=DummyOutput,
                system_prompt="sys",
                fallback=_dummy_fallback,
                require_llm=False,
            )
        captured = capsys.readouterr()
        assert "WARNING" in captured.err
        assert "Falling back to heuristic" in captured.err
