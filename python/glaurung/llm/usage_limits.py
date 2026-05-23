"""Build pydantic-ai :class:`UsageLimits` from Glaurung's LLMConfig.

pydantic-ai 1.86's default ``UsageLimits.request_limit`` is 50. With
~30-50K input tokens per Agent.run() round-trip (system prompt +
tool-schema serialization + prior turns), a confused tool-using agent
can burn 1.5M+ input tokens before giving up. The defaults in
:class:`LLMConfig` are the project's fail-fast budget:

* ``request_limit``        12      -- abort after 12 tool-turns
* ``input_tokens_limit``   400_000 -- per-Agent.run() input budget
* ``total_tokens_limit``   500_000 -- per-Agent.run() total budget
* ``max_output_tokens``    32_768  -- generation cap (May-2026 models
                                      do 64K output comfortably, but
                                      no single Agent.run() needs that)

Callers override per-site by passing kwargs:

.. code-block:: python

    # findings discovery: structured output, ~8 tool-turns is plenty
    usage_limits = build_usage_limits(
        model_name=model_name, request_limit=8,
    )

    # critic: no tools, single round-trip
    usage_limits = build_usage_limits(
        model_name=model_name, request_limit=2, total_tokens_limit=50_000,
    )

The model-name argument is currently informational (logged with the
record); a future revision can use it to vary defaults by provider.
"""

from __future__ import annotations

import logging
from typing import Optional

from pydantic_ai.usage import UsageLimits

from .config import get_config


logger = logging.getLogger(__name__)


def build_usage_limits(
    model_name: Optional[str] = None,
    *,
    request_limit: Optional[int] = None,
    input_tokens_limit: Optional[int] = None,
    output_tokens_limit: Optional[int] = None,
    total_tokens_limit: Optional[int] = None,
    tool_calls_limit: Optional[int] = None,
    count_tokens_before_request: bool = False,
) -> UsageLimits:
    """Build a :class:`UsageLimits` honoring LLMConfig defaults.

    Any keyword that's ``None`` falls back to ``LLMConfig`` default.
    Pass an explicit ``0`` (or any non-None value) to disable / set
    a tight cap without inheriting the config default.

    ``model_name`` is currently informational (no per-provider
    branching yet) but present so call sites pass it consistently;
    future tuning lives behind this argument.
    """
    cfg = get_config()
    req = request_limit if request_limit is not None else cfg.default_request_limit
    inp = (
        input_tokens_limit
        if input_tokens_limit is not None
        else cfg.default_input_tokens_limit
    )
    tot = (
        total_tokens_limit
        if total_tokens_limit is not None
        else cfg.default_total_tokens_limit
    )
    out = output_tokens_limit  # None unless caller specifies
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "build_usage_limits(model=%s, req=%s, in=%s, out=%s, tot=%s, tool=%s)",
            model_name, req, inp, out, tot, tool_calls_limit,
        )
    return UsageLimits(
        request_limit=req,
        input_tokens_limit=inp,
        output_tokens_limit=out,
        total_tokens_limit=tot,
        tool_calls_limit=tool_calls_limit,
        count_tokens_before_request=count_tokens_before_request,
    )


def default_max_output_tokens() -> int:
    """Convenience: project default for per-call max-output (F3)."""
    return get_config().default_max_output_tokens
