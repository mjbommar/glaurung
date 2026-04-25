"""Shared helpers for LLM-backed tools.

Every Layer 0–4 tool in :mod:`glaurung.llm.tools` follows the same
three-branch pattern:

1. If no API key is configured → return a LOW-confidence heuristic
   fallback so the offline CLI still works.
2. If we're nested inside another pydantic-ai Agent's event loop →
   fall back to heuristics (``Agent.run_sync`` cannot drive a nested
   loop). This keeps composite agents safe.
3. Otherwise → run the LLM and return its structured output.

Centralising the boilerplate here keeps each tool focused on *what* it
does, not *how* it calls the model.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional, TypeVar

from pydantic import BaseModel
from pydantic_ai import Agent

from ..config import get_config


T = TypeVar("T", bound=BaseModel)


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
) -> T:
    """One-shot structured LLM call with automatic fallback.

    The ``fallback`` callable is invoked — and its result returned
    unchanged — in all of these situations:

    - no LLM credentials configured
    - currently inside another agent's event loop
    - the LLM call itself raised an exception

    This means callers can always trust the return value to match
    ``output_type`` regardless of environment.
    """
    if not can_call_llm() or in_running_event_loop():
        return fallback()

    cfg = get_config()
    agent = Agent[str, output_type](
        model=model or cfg.preferred_model(),
        output_type=output_type,
        system_prompt=system_prompt,
    )
    try:
        result = agent.run_sync(prompt).output
    except Exception:
        return fallback()
    # pydantic-ai occasionally returns a raw string instead of the
    # requested structured output (e.g. when the LLM emits unparseable
    # JSON or refuses the schema). Validate the result type before
    # returning so the caller never gets surprised by AttributeError on
    # the wrong shape.
    if not isinstance(result, output_type):
        return fallback()
    return result
