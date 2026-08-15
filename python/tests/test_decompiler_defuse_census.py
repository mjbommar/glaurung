"""Definition-before-use lane: the recovered C must not read what it never wrote.

The decompiler verifies the exact AST it is about to print
(``src/ir/verify_defs.rs::verify_before_render``, called at the last pre-render
boundary in ``python_bindings::ir::decbench_text``). A violation means the
emitted C reads a value the machine never produced, so the recompiled function
returns garbage — a wrong-code bug, and one that ``type_match`` / ``GED`` /
``byte_match`` cannot see because the C still parses, still compiles, and still
has the right shape.

The structural lane already ratchets these violations, but only for the single
``gcc -O0`` build it makes of each fixture. Measured at ``2ed9b07``, that lane
holds 7 of the 304 violations present in REQUIRED functions across all 740
lanes; the other 297 live in the optimising and Rust lanes and were ungated.
This lane closes that gap.

Two levels, deliberately at different precision:

* REQUIRED functions are pinned per function and per message. A new violation
  names itself; a resolved one fails too, so the baseline must be refreshed and
  the improvement can never silently slide back.
* Every OTHER emitted function (library bodies, compiler runtime, PLT thunks —
  real decompilations the corpus makes no contract about) is held to a per-lane
  ceiling on totals. Naming 12,702 violations would be a transcript, not a gate;
  a ceiling still makes the number impossible to grow quietly.

Marked ``slow``: it compiles and decompiles the whole corpus in every lane. Run
with ``-m slow``. Refresh with ``tools/gen_defuse_baseline.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import defuse as D

BASELINE = ROOT / "tests" / "decompiler_fixtures" / "defuse_baseline.json"
pytestmark = pytest.mark.slow


@pytest.fixture(scope="session")
def baseline() -> dict:
    assert BASELINE.is_file(), (
        "defuse_baseline.json missing — regenerate with tools/gen_defuse_baseline.py"
    )
    return json.loads(BASELINE.read_text())


@pytest.fixture(scope="session")
def report() -> dict:
    return D.defuse_report()


def test_every_declared_lane_was_actually_censused(report):
    # A lane that failed to build contributes no violations, which reads exactly
    # like a lane with none. Fail on the omission rather than on its consequence.
    assert report["problems"] == [], (
        "lanes the census could not measure:\n  " + "\n  ".join(report["problems"])
    )


def test_the_census_covers_the_whole_declared_matrix(report, baseline):
    missing = sorted(set(baseline["required"]) - set(report["required"]))
    assert not missing, (
        f"{len(missing)} recorded function-lane(s) absent from this census: "
        f"{missing[:10]}"
    )


def test_the_toolchain_matches_the_one_the_census_was_recorded_against(
    report, baseline
):
    # The violations follow the compiled binary. Compared across compiler
    # releases this baseline is not a gate, it is a snapshot of one machine.
    assert report[D.TOOLCHAIN_KEY] == baseline[D.TOOLCHAIN_KEY], (
        "compile toolchain differs from the one the census was recorded against; "
        f"recorded={baseline[D.TOOLCHAIN_KEY]} current={report[D.TOOLCHAIN_KEY]}"
    )


def test_no_new_definition_before_use_violation(report, baseline):
    problems = []
    for key, recorded in baseline["required"].items():
        current = report["required"].get(key)
        if current is None:
            problems.append(f"{key}: MISSING from the census")
            continue
        new = sorted(set(current) - set(recorded))
        if new:
            problems.append(f"{key}: NEW undefined read(s): {new}")
    for key, current in report["required"].items():
        if key not in baseline["required"] and current and current != ["not_emitted"]:
            problems.append(f"{key}: unrecorded function with violation(s): {current}")
    assert not problems, (
        "DEFINITION-BEFORE-USE REGRESSIONS — the recovered C reads values the "
        "original never produced:\n  " + "\n  ".join(problems)
    )


def test_no_lane_emits_more_undefined_reads_than_recorded(report, baseline):
    # The aggregate ceiling over EVERY emitted function, including the ones the
    # manifest makes no per-function claim about.
    problems = []
    for lane, recorded in baseline["lane_totals"].items():
        current = report["lane_totals"].get(lane)
        if current is None:
            problems.append(f"{lane}: MISSING from the census")
            continue
        if current["violations"] > recorded["violations"]:
            problems.append(
                f"{lane}: {recorded['violations']} -> {current['violations']} "
                "undefined read(s) across all emitted functions"
            )
        if current["functions_with_violations"] > recorded["functions_with_violations"]:
            problems.append(
                f"{lane}: {recorded['functions_with_violations']} -> "
                f"{current['functions_with_violations']} unverified function(s)"
            )
    assert not problems, "DEFINITION-BEFORE-USE CEILINGS EXCEEDED:\n  " + "\n  ".join(
        problems
    )


def test_improvements_require_a_baseline_refresh(report, baseline):
    # The other half of the ratchet. A violation that is fixed must be recorded
    # as fixed, or the gate would happily let it come back.
    improved = []
    for key, recorded in baseline["required"].items():
        fixed = sorted(set(recorded) - set(report["required"].get(key, [])))
        if fixed:
            improved.append(f"{key}: resolved {fixed}")
    for lane, recorded in baseline["lane_totals"].items():
        current = report["lane_totals"].get(lane, recorded)
        if current["violations"] < recorded["violations"]:
            improved.append(
                f"{lane}: {recorded['violations']} -> {current['violations']} "
                "undefined read(s) — a real improvement"
            )
    assert not improved, (
        "DEFINITION-BEFORE-USE IMPROVEMENTS — refresh defuse_baseline.json with "
        "tools/gen_defuse_baseline.py to ratchet:\n  " + "\n  ".join(improved)
    )
