"""Shared helpers for LLM-backed tools.

Every Layer 0–4 tool in :mod:`glaurung.llm.tools` follows the same
three-branch pattern:

1. If no API key is configured → return a LOW-confidence heuristic
   fallback so the offline CLI still works.
2. If we're nested inside another pydantic-ai Agent's event loop →
   fall back to heuristics (``Agent.run_sync`` cannot drive a nested
   loop). This keeps composite agents safe.
3. Otherwise → run the LLM and return its structured output.

When ``GLAURUNG_REQUIRE_LLM`` is set in the environment (or callers
pass ``require_llm=True``), the silent fallbacks above turn into
``LLMUnavailable`` exceptions instead — preventing the heuristic
output from being mistaken for an LLM lift downstream. This is the
recommended setting for ASB automation and batch-pipeline runs.

Centralising the boilerplate here keeps each tool focused on *what* it
does, not *how* it calls the model.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any, Callable, Optional, TypeVar

from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

from ..config import get_config


T = TypeVar("T", bound=BaseModel)


class LLMUnavailable(RuntimeError):
    """Raised when an LLM call is required but cannot be made.

    Replaces the previous silent heuristic-fallback path when the
    caller (CLI flag or ``GLAURUNG_REQUIRE_LLM`` env var) has asked
    for guaranteed LLM output.
    """


def _require_llm_flag(require_llm: Optional[bool]) -> bool:
    """Resolve the effective require_llm flag.

    Precedence: explicit kwarg > env var > default (False).
    """
    if require_llm is not None:
        return require_llm
    val = os.environ.get("GLAURUNG_REQUIRE_LLM", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def can_call_llm() -> bool:
    """True when there is a configured provider we can actually reach."""
    cfg = get_config()
    return any(cfg.available_models().values())


def in_running_event_loop() -> bool:
    """Detect whether we're already inside an asyncio loop.

    ``pydantic_ai.Agent.run_sync`` deadlocks when invoked from an async
    context — so any tool that uses it must branch on this and return a
    heuristic result instead.
    """
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


def run_structured_llm(
    prompt: str,
    output_type: type[T],
    system_prompt: str,
    fallback: Callable[[], T],
    model: Optional[str] = None,
    *,
    require_llm: Optional[bool] = None,
) -> T:
    """One-shot structured LLM call with automatic fallback.

    The ``fallback`` callable is invoked — and its result returned
    unchanged — in all of these situations:

    - no LLM credentials configured
    - currently inside another agent's event loop
    - the LLM call itself raised an exception

    This means callers can always trust the return value to match
    ``output_type`` regardless of environment.

    When ``require_llm=True`` (or the ``GLAURUNG_REQUIRE_LLM``
    environment variable is set), each of the fallback conditions
    above raises :class:`LLMUnavailable` instead. Use this for
    automation paths where a heuristic result would be mistaken for
    an LLM lift downstream (see GLAURUNG-IMPROVEMENTS-2026-05-27.md
    #5 + ASB BACKLOG-2026-05-26.md P0-H).
    """
    require = _require_llm_flag(require_llm)

    if not can_call_llm():
        msg = (
            "LLM unreachable: no provider credentials configured "
            "(check OPENAI_API_KEY / ANTHROPIC_API_KEY)."
        )
        if require:
            raise LLMUnavailable(msg)
        print(f"[glaurung.llm] WARNING: {msg} Falling back to heuristic.",
              file=sys.stderr)
        return fallback()

    if in_running_event_loop():
        msg = (
            "LLM call attempted from inside a running asyncio loop; "
            "pydantic-ai Agent.run_sync would deadlock."
        )
        if require:
            raise LLMUnavailable(msg)
        # Nested-event-loop fallback is normal in composite agents,
        # so emit at debug level (still stderr but quieter framing).
        print(f"[glaurung.llm] DEBUG: {msg} Falling back to heuristic.",
              file=sys.stderr)
        return fallback()

    cfg = get_config()
    model_name = model or cfg.preferred_model()
    agent_kwargs = {
        "model": model_name,
        "output_type": output_type,
        "system_prompt": system_prompt,
    }
    # Project policy: OpenAI calls run at service_tier=flex by default.
    # See LLMConfig.openai_service_tier and CLAUDE.md "LLM model defaults".
    # max_tokens: pydantic-ai / OpenAI default is small (~4096), which
    # truncates Tool #14 rewrites of large functions like afd.sys's
    # AfdConnect (1327-line pseudocode -> needs ~20k tokens of C output).
    # Without this, the LLM emits a stub + a "too inconsistent to rewrite"
    # disclaimer at confidence 0.06. 65536 is the project default per
    # mike@273ventures.com (2026-05-26) and is enough for any function
    # we realistically pass through Tool #14.
    model_settings_kwargs: dict[str, Any] = {"max_tokens": 65536}
    if model_name.startswith("openai:") and cfg.openai_service_tier:
        model_settings_kwargs["extra_body"] = {
            "service_tier": cfg.openai_service_tier,
        }
    agent_kwargs["model_settings"] = ModelSettings(**model_settings_kwargs)
    agent = Agent[str, output_type](**agent_kwargs)
    try:
        result = agent.run_sync(prompt).output
    except Exception as exc:
        msg = f"LLM call failed: {type(exc).__name__}: {exc}"
        if require:
            raise LLMUnavailable(msg) from exc
        print(f"[glaurung.llm] WARNING: {msg} Falling back to heuristic.",
              file=sys.stderr)
        return fallback()
    # pydantic-ai occasionally returns a raw string instead of the
    # requested structured output (e.g. when the LLM emits unparseable
    # JSON or refuses the schema). Validate the result type before
    # returning so the caller never gets surprised by AttributeError on
    # the wrong shape.
    if not isinstance(result, output_type):
        msg = (
            f"LLM returned wrong type: expected {output_type.__name__}, "
            f"got {type(result).__name__}."
        )
        if require:
            raise LLMUnavailable(msg)
        print(f"[glaurung.llm] WARNING: {msg} Falling back to heuristic.",
              file=sys.stderr)
        return fallback()
    return result
