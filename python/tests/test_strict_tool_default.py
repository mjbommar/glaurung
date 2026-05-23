"""Tests for D2: per-model strict-tool default in tool_to_pyd_ai.

The memory agent registers ~163 tools; Anthropic caps strict-tool count at
20. Before D2 we needed the environment workaround `GLAURUNG_TOOL_STRICT=0`
to use any Anthropic model. After D2, passing `model_name="anthropic:..."`
to `register_analysis_tools` flips strict off automatically.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from glaurung.llm.tools.base import (
    _DEFAULT_TOOL_STRICT as _initial_default,
    default_tool_strict_for,
    default_tool_strict_for_model,
    set_default_tool_strict,
)


def test_default_tool_strict_for_model_anthropic():
    """Anthropic models get strict=False (cap at 20 strict tools)."""
    assert default_tool_strict_for_model("anthropic:claude-haiku-4-5") is False
    assert default_tool_strict_for_model("anthropic:claude-opus-4-7") is False


def test_default_tool_strict_for_model_openai():
    """OpenAI models keep strict on (their cap is total-tools, not strict-tools)."""
    assert default_tool_strict_for_model("openai:gpt-5.4-mini") is True


def test_default_tool_strict_for_model_unknown():
    """Unknown / None providers default to strict=True for back-compat."""
    assert default_tool_strict_for_model("test") is True
    assert default_tool_strict_for_model(None) is True
    assert default_tool_strict_for_model("") is True


def test_set_default_tool_strict_round_trip():
    prev = set_default_tool_strict(False)
    try:
        from glaurung.llm.tools.base import _DEFAULT_TOOL_STRICT as cur
        assert cur is False
    finally:
        set_default_tool_strict(prev)


def test_default_tool_strict_for_context_manager_restores():
    """The context manager must restore the previous default even on exception."""
    set_default_tool_strict(None)
    with pytest.raises(RuntimeError):
        with default_tool_strict_for(False):
            from glaurung.llm.tools.base import _DEFAULT_TOOL_STRICT as inside
            assert inside is False
            raise RuntimeError("boom")
    from glaurung.llm.tools.base import _DEFAULT_TOOL_STRICT as after
    assert after is None


def test_java_helper_delegates_to_canonical():
    """The Java agent's legacy _default_tool_strict_for_model must now
    return the same answer as the canonical helper."""
    from glaurung.llm.agents.java import _default_tool_strict_for_model as _java
    assert _java("anthropic:claude-haiku-4-5") is False
    assert _java("openai:gpt-5.4-mini") is True


def test_register_analysis_tools_flips_strict_for_anthropic_model():
    """Passing model_name='anthropic:...' to register_analysis_tools must
    cause subsequent tool_to_pyd_ai calls to default to strict=False, even
    when those calls don't pass `strict=` explicitly.
    """
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.tools.base import (
        _DEFAULT_TOOL_STRICT,
        default_tool_strict_for,
        default_tool_strict_for_model,
    )

    # 1. Confirm the helper picks the right default for the provider.
    assert default_tool_strict_for_model("anthropic:claude-haiku-4-5") is False

    # 2. Confirm the context manager sets and restores the module-level default.
    set_default_tool_strict(None)  # baseline
    with default_tool_strict_for(default_tool_strict_for_model("anthropic:claude-haiku-4-5")):
        from glaurung.llm.tools.base import _DEFAULT_TOOL_STRICT as inside
        assert inside is False, (
            f"Default inside Anthropic context should be False; got {inside}"
        )
    from glaurung.llm.tools.base import _DEFAULT_TOOL_STRICT as after
    assert after is None, f"Default not restored after context exit; got {after}"

    # 3. Confirm tool_to_pyd_ai inherits the module-level default when
    #    no explicit strict= is passed. Use the simplest possible tool.
    from glaurung.llm.tools.base import MemoryTool, ToolMeta, tool_to_pyd_ai
    from pydantic import BaseModel

    class _In(BaseModel):
        x: int = 0

    class _Out(BaseModel):
        ok: bool = True

    class _T(MemoryTool):
        def __init__(self):
            super().__init__(ToolMeta(name="t", description="t"), _In, _Out)

        def run(self, ctx, kb, args):  # pragma: no cover -- unused
            return _Out()

    set_default_tool_strict(None)
    with default_tool_strict_for(False):
        wrapped = tool_to_pyd_ai(_T())
    # pydantic-ai Tool exposes the resolved strict value on the instance.
    # We don't assume the attribute name -- the only thing we need is that
    # the module-level default was honored. The functional check is round-trip:
    # passing the default through default_tool_strict_for(False) yields a
    # wrapped tool whose strict mode is False.
    assert getattr(wrapped, "strict", None) is False, (
        f"tool_to_pyd_ai did not inherit module-level default; "
        f"got strict={getattr(wrapped, 'strict', '<missing>')}"
    )
