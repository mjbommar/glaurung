"""Resource budgets for a local DecBench replay, matching the published standard.

DecBench standardised its per-binary and per-function budgets in
`decbench/decompilers/limits.py` (upstream `5818d67`). Before that each backend
carried its own timeout and our replay harness used 20s per function and 600s
per binary -- 30x and 6x tighter than the standard. A run at a tighter budget
fails functions the published board would have scored, so its numbers are not
comparable to any other column.

The defaults here are therefore the upstream constants, not our history. An
override stays available for cheap local iteration, but `budget_receipt` names
every one of them so a run's provenance states the deviation rather than
burying it. The environment variable names mirror upstream's resolution order
so a value set for one side of the harness means the same thing on the other.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

#: Upstream `limits.FUNCTION_TIMEOUT_SECONDS`.
FUNCTION_TIMEOUT_SECONDS = 600
#: Upstream `limits.BINARY_TIMEOUT_SECONDS`.
BINARY_TIMEOUT_SECONDS = 3600

#: Per-function override, the name upstream's Glaurung backend already reads.
FUNCTION_TIMEOUT_VAR = "DECBENCH_GLAURUNG_TIMEOUT_MS"
#: Per-binary overrides, most specific first, as upstream resolves them.
BINARY_TIMEOUT_VARS = ("DECBENCH_GLAURUNG_TIMEOUT", "DECBENCH_DECOMPILE_TIMEOUT")


class BudgetError(ValueError):
    """Raised when a configured budget is malformed or unreachable."""


def _positive_int(name: str, raw: str) -> int:
    """Parse a strictly positive integer budget.

    Args:
        name: Environment variable the value came from, for the message.
        raw: The raw environment value.

    Returns:
        The parsed value.

    Raises:
        BudgetError: If the value is not a base-10 integer greater than zero.
            A malformed budget is never silently replaced by the default: that
            would label an unstandard run as standard.
    """
    text = raw.strip()
    try:
        value = int(text)
    except ValueError as error:
        raise BudgetError(f"{name} must be a positive integer, got {raw!r}") from error
    if value <= 0:
        raise BudgetError(f"{name} must be greater than zero, got {raw!r}")
    return value


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    """Return the environment to resolve against, defaulting to the process."""
    return os.environ if env is None else env


def function_timeout_ms(*, env: Mapping[str, str] | None = None) -> int:
    """Per-function decompiler budget in milliseconds.

    Args:
        env: Environment to read; the process environment by default.

    Returns:
        The configured budget, or the published standard when unset.

    Raises:
        BudgetError: If the override is malformed.
    """
    raw = _env(env).get(FUNCTION_TIMEOUT_VAR)
    if raw is None:
        return FUNCTION_TIMEOUT_SECONDS * 1000
    return _positive_int(FUNCTION_TIMEOUT_VAR, raw)


def binary_timeout_seconds(*, env: Mapping[str, str] | None = None) -> int:
    """Per-binary wall-clock budget in seconds.

    Resolves the backend-specific variable before the generic one, matching
    upstream `limits.binary_timeout_seconds`.

    Args:
        env: Environment to read; the process environment by default.

    Returns:
        The configured budget, or the published standard when unset.

    Raises:
        BudgetError: If the first variable that is set is malformed.
    """
    source = _env(env)
    for name in BINARY_TIMEOUT_VARS:
        raw = source.get(name)
        if raw is not None:
            return _positive_int(name, raw)
    return BINARY_TIMEOUT_SECONDS


def budget_receipt(*, env: Mapping[str, str] | None = None) -> dict[str, object]:
    """Resolved budgets plus the declaration a run's provenance must carry.

    Args:
        env: Environment to read; the process environment by default.

    Returns:
        Mapping with the resolved `function_timeout_ms` and
        `binary_timeout_seconds`, the `overrides` that produced them, and
        `matches_published_standard`, which is False whenever either budget
        differs from upstream's.

    Raises:
        BudgetError: If a budget is malformed, or if the per-function budget
            exceeds the per-binary budget and so can never be reached.
    """
    source = _env(env)
    function_ms = function_timeout_ms(env=source)
    binary_s = binary_timeout_seconds(env=source)
    if function_ms > binary_s * 1000:
        raise BudgetError(
            f"per-function budget {function_ms}ms exceeds the per-binary budget "
            f"{binary_s}s; the function budget could never be reached"
        )
    overrides = {
        name: source[name]
        for name in (FUNCTION_TIMEOUT_VAR, *BINARY_TIMEOUT_VARS)
        if name in source
    }
    standard = (
        function_ms == FUNCTION_TIMEOUT_SECONDS * 1000
        and binary_s == BINARY_TIMEOUT_SECONDS
    )
    return {
        "function_timeout_ms": function_ms,
        "binary_timeout_seconds": binary_s,
        "overrides": overrides,
        "matches_published_standard": standard,
        "published_standard": {
            "function_timeout_ms": FUNCTION_TIMEOUT_SECONDS * 1000,
            "binary_timeout_seconds": BINARY_TIMEOUT_SECONDS,
        },
    }
