"""Semantic regression gate over the decompiler fixture corpus.

Runs the fail-closed execution-differential harness across the required x86-64
matrix (gcc/clang x O0/O2) and compares each function's status to the committed
per-function baseline (`baseline.json`):

  * a function that was PASS in the baseline but now FAILS  -> regression, FAIL.
  * a lane (fixture,cc,opt) that compiled in the baseline but now errors -> FAIL.
  * a function/result that has gone missing                 -> FAIL.
  * a function that was FAIL and now PASSES                 -> not a failure, but
    the baseline is stale and should be regenerated (reported).

This is the gate the review asked for: known semantic bugs stay visible without
letting NEW regressions slip through green. It is marked `slow` (compiles +
executes the whole matrix); run with `-m slow`. The fail-closed *unit* checks in
test_decompiler_fixture_harness.py run in the normal suite.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import fixture_harness as H
import manifest as M

BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"
VALID_STATUSES = {"pass", "fail", "structural", "missing", "nocases"}

pytestmark = pytest.mark.slow


def _baseline_data():
    assert BASELINE.is_file(), (
        "baseline.json is missing — required corpus artifact. Regenerate with "
        "`python tools/fixture_harness.py --write-baseline`."
    )
    return json.loads(BASELINE.read_text())


@pytest.fixture(scope="session")
def baseline():
    return _baseline_data()


@pytest.fixture(scope="session")
def current():
    # Run exactly the toolchain lanes present in the baseline. Same FIXTURE_FUZZ
    # as the baseline generator -> identical vectors -> no phantom diffs.
    lanes = sorted({tuple(k.split(":")[1:]) for k in _baseline_data() if ":" in k})
    return H.run_matrix([(cc, opt) for cc, opt in lanes], fuzz=M.FIXTURE_FUZZ)


def test_baseline_schema_is_valid(baseline):
    """The committed baseline must cover all ten fixtures with valid statuses and
    must never bake in infrastructure failures (lane errors / missing / nocases)."""
    probs = H.schema_problems(baseline, sorted({tuple(k.split(":")[1:]) for k in baseline}))
    probs += H.baseline_problems(baseline)
    assert not probs, "BASELINE SCHEMA INVALID:\n  " + "\n  ".join(probs)


def test_no_lane_became_broken(current, baseline):
    """A lane that compiled + ran in the baseline must not start erroring."""
    broken = []
    for lane, base in baseline.items():
        cur = current.get(lane)
        assert cur is not None, f"lane {lane} disappeared from the current run"
        base_ok = "__lane__" not in base
        cur_ok = "__lane__" not in cur
        if base_ok and not cur_ok:
            broken.append(f"{lane}: {cur.get('__lane__')}")
    assert not broken, "LANES NEWLY BROKEN:\n  " + "\n  ".join(broken)


def test_no_function_regressions(current, baseline):
    """No function that passed in the baseline may now fail, go missing, or turn
    into an infra status."""
    regressions, missing = [], []
    for lane, base in baseline.items():
        if "__lane__" in base:
            continue
        cur = current.get(lane, {})
        if "__lane__" in cur:
            continue  # covered by the lane test
        for func, base_status in base.items():
            cur_status = cur.get(func)
            if cur_status is None:
                missing.append(f"{lane}:{func}")
            elif base_status == "pass" and cur_status != "pass":
                regressions.append(f"{lane}:{func} ({base_status}->{cur_status})")
    assert not missing, "RESULTS MISSING (fail-closed):\n  " + "\n  ".join(missing)
    assert not regressions, "SEMANTIC REGRESSIONS:\n  " + "\n  ".join(regressions)


def test_improvements_require_a_baseline_refresh(current, baseline):
    """Ratchet: a function that now passes but the baseline records as failing
    must FAIL the gate, forcing a baseline refresh (after verifying the fix). This
    is what makes the gate ratchet upward — an improvement can never silently
    regress later because the baseline is stale."""
    improved = []
    for lane, base in baseline.items():
        if "__lane__" in base:
            continue
        cur = current.get(lane, {})
        for func, base_status in base.items():
            if base_status != "pass" and cur.get(func) == "pass":
                improved.append(f"{lane}:{func} ({base_status}->pass)")
    assert not improved, (
        "IMPROVEMENTS — verify the differential, then refresh baseline.json:\n  "
        + "\n  ".join(improved)
    )
