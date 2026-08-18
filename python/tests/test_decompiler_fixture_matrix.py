"""Semantic regression gate over the decompiler fixture corpus.

Runs the fail-closed execution-differential harness across the required x86-64
matrix (gcc/clang x O0/O2) and compares each function's status to the committed
per-function baseline (`baseline.json`):

  * a function that was PASS in the baseline but now FAILS  -> regression, FAIL.
  * a lane (fixture,cc,opt) that compiled in the baseline but now errors -> FAIL.
  * a function/result that has gone missing                 -> FAIL.
  * a lane recorded `env-missing` that this environment can actually run -> FAIL
    (its real results would otherwise drop out of every comparison).
  * a compile toolchain different from the one the baseline was recorded with
    -> FAIL (the verdicts are not comparable at all).
  * a function that was FAIL and now PASSES                 -> not a failure, but
    the baseline is stale and should be regenerated (reported).

This is the gate the review asked for: known semantic bugs stay visible without
letting NEW regressions slip through green. It is marked `slow` (compiles +
executes the whole matrix); run with `-m slow`. The fail-closed *unit* checks in
test_decompiler_fixture_harness.py run in the normal suite.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import fixture_harness as H
import fixture_toolchain as TC
import manifest as M

BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"
VALID_STATUSES = set(H.STATUS_KINDS)

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
    lanes = sorted({tuple(k.split(":")[1:]) for k in H.lanes(_baseline_data())})
    result = H.run_matrix([(cc, opt) for cc, opt in lanes], fuzz=M.FIXTURE_FUZZ)
    # The observed map is the evidence for any baseline refresh; dumping it here
    # (rather than re-running the matrix) makes a CI failure actionable without a
    # second 40-minute run.
    dest = os.environ.get("GLAURUNG_FIXTURE_OBSERVED")
    if dest:
        Path(dest).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def test_the_compile_toolchain_matches_the_baseline(baseline):
    """Before any verdict is compared: the compilers must be the ones the baseline
    was recorded with. Fixture codegen and the set of C diagnostics that are hard
    errors both move between compiler releases, so a mismatched toolchain produces
    phantom regressions and phantom improvements rather than information."""
    probs = TC.fingerprint_problems(baseline.get(H.TOOLCHAIN_KEY))
    assert not probs, "COMPILE TOOLCHAIN MISMATCH:\n  " + "\n  ".join(probs)


def test_baseline_schema_is_valid(baseline):
    """The committed baseline must cover all ten fixtures with valid statuses and
    must never bake in infrastructure failures (lane errors / missing / nocases)."""
    probs = H.schema_problems(
        baseline, sorted({tuple(k.split(":")[1:]) for k in H.lanes(baseline)})
    )
    probs += H.baseline_problems(baseline)
    assert not probs, "BASELINE SCHEMA INVALID:\n  " + "\n  ".join(probs)


def test_env_availability_matches_the_baseline(current, baseline):
    """A lane recorded `env-missing` is excluded from the per-function comparison.
    That is only sound while the gap is real: where the runtime IS provisioned the
    lane runs and its results would silently vanish from the gate."""
    probs = H.env_lane_problems(current, baseline)
    assert not probs, "LANE ENVIRONMENT CHANGED:\n  " + "\n  ".join(probs)


def test_no_function_timed_out(current):
    """A worker timeout is an INFRASTRUCTURE result, not a verdict: it means the
    machine was too slow (or a fixture drives an unbounded path), not that the
    decompilation is wrong. Recording it as `fail` would make the baseline
    machine-dependent, so it must fail the gate loudly and visibly instead."""
    timed_out = [
        f"{lane}:{func}"
        for lane, fns in H.lanes(current).items()
        for func, st in fns.items()
        if st == "timeout"
    ]
    assert not timed_out, (
        "WORKER TIMEOUTS (infrastructure, not a verdict — pin the guard parameter "
        "with the manifest's `arg_values`, or investigate the slowdown):\n  "
        + "\n  ".join(timed_out)
    )


def test_no_lane_became_broken(current, baseline):
    """A lane that compiled + ran in the baseline must not start erroring."""
    broken = []
    for lane, base in H.lanes(baseline).items():
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
    for lane, base in H.lanes(baseline).items():
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


def test_every_function_the_run_produced_is_recorded(current, baseline):
    """Fail closed on a function the baseline does not know about.

    Every other comparison iterates the BASELINE's function list, so a function
    that newly appears — one added to a fixture source, or an export the compiler
    started emitting — would be completely ungated: no regression could ever be
    detected for it until somebody happened to refresh. The baseline must be the
    exact set of functions the run produces."""
    unrecorded = []
    for lane, cur in H.lanes(current).items():
        if "__lane__" in cur:
            continue
        base = H.lanes(baseline).get(lane, {})
        if "__lane__" in base:
            continue  # env-availability change; covered by its own test
        for func in cur:
            if func not in base:
                unrecorded.append(f"{lane}:{func} ({cur[func]})")
    assert not unrecorded, (
        "FUNCTIONS NOT IN THE BASELINE (ungated — refresh baseline.json):\n  "
        + "\n  ".join(unrecorded)
    )


def test_improvements_require_a_baseline_refresh(current, baseline):
    """Ratchet: a function that now passes but the baseline records as failing
    must FAIL the gate, forcing a baseline refresh (after verifying the fix). This
    is what makes the gate ratchet upward — an improvement can never silently
    regress later because the baseline is stale."""
    improved = []
    for lane, base in H.lanes(baseline).items():
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
