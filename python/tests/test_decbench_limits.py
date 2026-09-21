"""Check the DecBench resource-budget contract our replay harness must honour.

DecBench standardised per-binary and per-function budgets in `decbench/
decompilers/limits.py` (upstream `5818d67`, "Standardize decompiler resource
limits"). A local replay that runs tighter budgets than the published standard
is not comparable to the published board, so the defaults here MUST equal the
upstream constants and any deviation MUST be declared in run provenance.
"""

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "decbench_limits", ROOT / "tools" / "decbench_limits.py"
)
assert SPEC is not None and SPEC.loader is not None
LIMITS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIMITS)


def test_defaults_equal_the_published_upstream_standard() -> None:
    """The unconfigured budgets are DecBench's, not our historical 20s/600s."""
    assert LIMITS.FUNCTION_TIMEOUT_SECONDS == 600
    assert LIMITS.BINARY_TIMEOUT_SECONDS == 3600
    assert LIMITS.function_timeout_ms(env={}) == 600_000
    assert LIMITS.binary_timeout_seconds(env={}) == 3600


def test_function_budget_is_overridable() -> None:
    env = {"DECBENCH_GLAURUNG_TIMEOUT_MS": "20000"}
    assert LIMITS.function_timeout_ms(env=env) == 20_000


def test_binary_budget_prefers_the_backend_specific_variable() -> None:
    """Upstream resolves `DECBENCH_<NAME>_TIMEOUT` before the generic one."""
    env = {
        "DECBENCH_GLAURUNG_TIMEOUT": "900",
        "DECBENCH_DECOMPILE_TIMEOUT": "1800",
    }
    assert LIMITS.binary_timeout_seconds(env=env) == 900
    assert (
        LIMITS.binary_timeout_seconds(env={"DECBENCH_DECOMPILE_TIMEOUT": "1800"})
        == 1800
    )


@pytest.mark.parametrize("value", ["", "abc", "0", "-5", "12.5.3", " "])
def test_a_malformed_budget_fails_loudly(value: str) -> None:
    """A typo must not silently restore the default and mislabel the run."""
    with pytest.raises(LIMITS.BudgetError):
        LIMITS.function_timeout_ms(env={"DECBENCH_GLAURUNG_TIMEOUT_MS": value})
    with pytest.raises(LIMITS.BudgetError):
        LIMITS.binary_timeout_seconds(env={"DECBENCH_DECOMPILE_TIMEOUT": value})


def test_receipt_declares_standard_compliance() -> None:
    receipt = LIMITS.budget_receipt(env={})
    assert receipt["function_timeout_ms"] == 600_000
    assert receipt["binary_timeout_seconds"] == 3600
    assert receipt["matches_published_standard"] is True
    assert receipt["overrides"] == {}


def test_receipt_names_every_override_so_a_run_cannot_hide_a_deviation() -> None:
    env = {
        "DECBENCH_GLAURUNG_TIMEOUT_MS": "20000",
        "DECBENCH_DECOMPILE_TIMEOUT": "600",
    }
    receipt = LIMITS.budget_receipt(env=env)
    assert receipt["function_timeout_ms"] == 20_000
    assert receipt["binary_timeout_seconds"] == 600
    assert receipt["matches_published_standard"] is False
    assert receipt["overrides"] == {
        "DECBENCH_GLAURUNG_TIMEOUT_MS": "20000",
        "DECBENCH_DECOMPILE_TIMEOUT": "600",
    }


def test_a_function_budget_may_not_exceed_the_binary_budget() -> None:
    """A per-function budget above the per-binary one can never be reached."""
    env = {
        "DECBENCH_GLAURUNG_TIMEOUT_MS": "7200000",
        "DECBENCH_DECOMPILE_TIMEOUT": "3600",
    }
    with pytest.raises(LIMITS.BudgetError, match="exceeds"):
        LIMITS.budget_receipt(env=env)
