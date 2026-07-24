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
import fixture_harness as H

BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"

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
    # Run exactly the toolchain lanes present in the baseline (so a gcc-O0-only
    # baseline is compared against a gcc-O0-only run, and a full-matrix baseline
    # against the full matrix) — keeps the gate consistent and no slower than the
    # committed baseline.
    lanes = sorted({tuple(k.split(":")[1:]) for k in _baseline_data() if ":" in k})
    return H.run_matrix([(cc, opt) for cc, opt in lanes], fuzz=12)


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
    """No function that passed in the baseline may now fail or go missing."""
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
            elif base_status == "pass" and cur_status == "fail":
                regressions.append(f"{lane}:{func}")
    assert not missing, "RESULTS MISSING (fail-closed):\n  " + "\n  ".join(missing)
    assert not regressions, "SEMANTIC REGRESSIONS (pass->fail):\n  " + "\n  ".join(regressions)


def test_report_improvements(current, baseline):
    """Not a failure: surface functions that now pass but the baseline says fail,
    so the baseline can be regenerated to lock the improvement in."""
    improved = []
    for lane, base in baseline.items():
        if "__lane__" in base:
            continue
        cur = current.get(lane, {})
        for func, base_status in base.items():
            if base_status == "fail" and cur.get(func) == "pass":
                improved.append(f"{lane}:{func}")
    if improved:
        print("\nIMPROVED since baseline (regenerate baseline.json to lock in):")
        for i in improved:
            print(f"  {i}")
