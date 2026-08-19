"""The stripped lane: does removing the debug info change a VERDICT?

`tools/fixture_harness.compile_fixture` compiles every lane with `-g`,
unconditionally, so the whole 198-fixture corpus is blind to any defect that only
appears without debug info — which is the configuration real targets ship in.
`tools/stripped_differential.py` adds a lane that builds the same compile, runs
`strip` over the object, decompiles THAT, and diffs the verdicts against the `-g`
build's.

Two tiers here, deliberately:

  * the pure rules (`classify`, `compare`, `ratchet`, `split_opt`,
    `stripped_lanes_for`, `Lane.control_key`) run in the ordinary suite. They are
    where the lane's meaning lives, and none of them needs a compiler.
  * the lane itself is `slow`-marked, because it compiles and executes ~380
    lanes.

The `slow` test asserts the DIFFERENCE, not a pass rate. A cell that fails with
`-g` and stripped is a pre-existing defect this lane did not find; a cell that
passes with `-g` and fails stripped is a real defect that arrives with its own
control attached. Only the second kind moves this gate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import dectest as DT  # ty: ignore[unresolved-import]
import fixture_harness as H  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]
import stripped_differential as SD  # ty: ignore[unresolved-import]


# --------------------------------------------------------------------------
# The lane vocabulary (no compiler required)
# --------------------------------------------------------------------------


def test_split_opt_round_trips_the_strip_suffix():
    assert H.split_opt("O2") == ("O2", False)
    assert H.split_opt("O0") == ("O0", False)
    assert H.split_opt("O2strip") == ("O2", True)
    assert H.stripped_opt("O2") == "O2strip"
    # Idempotent: asking for the stripped form of a stripped lane is not an
    # `O2stripstrip`, which would name an object nothing builds.
    assert H.stripped_opt("O2strip") == "O2strip"


def test_stripped_lanes_stay_inside_their_language():
    """A Rust fixture gets `rustc:O2strip` and never `gcc:O2strip`.

    The same trap `lanes_for` exists to close (`10_cpp_runtime_shapes:rustc:O0`,
    a C++ fixture recorded under a Rust lane label). `stripped_lanes_for` derives
    from `matrix_for` rather than restating a compiler list, so there is no second
    list to fall out of step.
    """
    src = ROOT / "tests" / "decompiler_fixtures" / "src"
    rust = next(src.glob("*.rs"))
    assert H.stripped_lanes_for(rust) == [("rustc", "O2strip")]
    c = next(src.glob("*.c"))
    assert H.stripped_lanes_for(c) == [("gcc", "O2strip"), ("clang", "O2strip")]


def test_no_stripped_lane_is_in_the_required_matrix():
    """The stripped lane is a differential, not a second corpus.

    Folding it into `REQUIRED_MATRIX` would double `baseline.json` and record
    every already-known failure a second time under a new key. Its control is the
    `fixture:cc:O2` row that is already there.
    """
    assert all(not H.split_opt(opt)[1] for _cc, opt in H.REQUIRED_MATRIX)
    assert all(not H.split_opt(opt)[1] for _cc, opt in H.RUST_MATRIX)


def test_a_glob_in_the_optimisation_slot_never_reaches_a_stripped_lane():
    """`@o0` and `@o2` must mean exactly what they always meant.

    A stripped lane costs a second compile and a second decompilation, and every
    named set in `sets.toml` selects fixtures rather than lanes — so if `*` in the
    optimisation slot expanded over the stripped opts, every set in the file would
    silently double.
    """
    o2 = DT.resolve(["*:gcc:O2"])
    assert o2, "the selector should match the host lanes"
    assert all(not lane.is_stripped for lane in o2)
    assert all(not lane.is_stripped for lane in DT.resolve(["@o0"]))
    assert all(not lane.is_stripped for lane in DT.resolve(["@o2"]))


def test_a_stripped_lane_is_selectable_by_name_and_by_flag():
    named = DT.resolve(["03_loop_shapes:gcc:O2strip"])
    assert [lane.key for lane in named] == ["03_loop_shapes:gcc:O2strip"]
    assert named[0].is_stripped
    flagged = DT.resolve(["03_loop_shapes:gcc:O2"], stripped=True)
    assert [lane.key for lane in flagged] == ["03_loop_shapes:gcc:O2strip"]


def test_a_stripped_lane_selects_exactly_its_control_s_functions():
    control = DT.resolve(["03_loop_shapes:gcc:O2"])[0]
    stripped = DT.resolve(["03_loop_shapes:gcc:O2strip"])[0]
    assert stripped.funcs == control.funcs
    assert stripped.control_key == control.key


def test_an_ordinary_lane_is_its_own_control():
    lane = DT.resolve(["03_loop_shapes:gcc:O2"])[0]
    assert lane.control_key == lane.key == "03_loop_shapes:gcc:O2"


def test_stripped_retarget_refuses_an_optimisation_with_no_stripped_lane():
    """`@o0 --stripped` must say so rather than invent an `O0strip` lane.

    `stripped_lanes_for` builds `-O2` only, so an `O0strip` selector would name an
    object that is never compiled — and `dectest`'s contract is that a selector
    matching nothing is an ERROR, because a typo that matched zero lanes prints
    "no regressions" and reads as success.
    """
    with pytest.raises(DT.NoMatch):
        DT.resolve(["03_loop_shapes:gcc:O0"], stripped=True)


# --------------------------------------------------------------------------
# The differential's rules (no compiler required)
# --------------------------------------------------------------------------


def test_classify_names_the_direction_of_every_divergence():
    assert SD.classify("pass", "pass") is None
    assert SD.classify("fail", "fail") is None
    assert SD.classify("pass", "fail") == SD.REGRESSION
    assert SD.classify("pass", "structural") == SD.REGRESSION
    assert SD.classify("fail", "pass") == SD.IMPROVEMENT
    assert SD.classify("structural", "fail") == SD.CHANGED


def test_compare_reports_the_difference_and_not_the_failure_rate():
    """A cell failing on BOTH sides is pre-existing and is not a finding.

    This is the whole reason the lane is a differential. Most of the corpus's
    known failures fail with `-g` too; a standalone stripped baseline would record
    them again and call it coverage.
    """
    stripped = {
        "f:gcc:O2strip": {
            "already_broken": "fail",
            "only_stripped": "fail",
            "ok": "pass",
        }
    }
    baseline = {
        "f:gcc:O2": {"already_broken": "fail", "only_stripped": "pass", "ok": "pass"}
    }
    found, problems = SD.compare(stripped, baseline)
    assert problems == []
    assert list(found) == ["f:gcc:O2strip:only_stripped"]
    assert found["f:gcc:O2strip:only_stripped"] == {
        "kind": SD.REGRESSION,
        "debug": "pass",
        "stripped": "fail",
    }


def test_compare_treats_a_missing_control_as_infrastructure_not_a_finding():
    """Without the `-g` control the lane cannot answer its own question.

    A stripped cell with nothing to compare against says nothing about whether the
    debug info was load-bearing, so it is an infrastructure problem — never a
    silently-dropped cell, and never a regression by default.
    """
    found, problems = SD.compare({"f:gcc:O2strip": {"a": "fail"}}, {})
    assert found == {}
    assert problems and "no `-g` control lane f:gcc:O2" in problems[0]

    found, problems = SD.compare(
        {"f:gcc:O2strip": {"a": "fail"}}, {"f:gcc:O2": {"b": "pass"}}
    )
    assert found == {}
    assert problems and "no `-g` control verdict" in problems[0]


def test_compare_reports_a_lane_error_as_infrastructure():
    found, problems = SD.compare(
        {"f:gcc:O2strip": {"__lane__": "compile-failed: boom"}}, {}
    )
    assert found == {}
    assert problems == ["f:gcc:O2strip: lane error (compile-failed: boom)"]
    # A declared, probed environment gap is not an error.
    found, problems = SD.compare({"f:gcc:O2strip": {"__lane__": "env-missing"}}, {})
    assert (found, problems) == ({}, [])


def test_ratchet_fails_in_both_directions():
    """A new divergence and a vanished one are both failures.

    A recorded divergence that stops diverging means the file describes a defect
    that no longer exists, and leaving it there would let the NEXT occurrence of
    the same cell arrive pre-approved.
    """
    found = {"a": {"kind": SD.REGRESSION, "debug": "pass", "stripped": "fail"}}
    assert SD.ratchet(found, found) == ([], [])
    assert SD.ratchet(found, {}) == (["a"], [])
    assert SD.ratchet({}, found) == ([], ["a"])
    # Same cell, different verdict: still unrecorded.
    worse = {"a": {"kind": SD.REGRESSION, "debug": "pass", "stripped": "timeout"}}
    assert SD.ratchet(worse, found) == (["a"], [])


def test_recorded_divergences_name_real_cells():
    """Every entry in `stripped_divergences.json` must name a fixture, a lane the
    corpus builds, and a function the `-g` control actually has.

    A stale entry is worse than no entry: it silently pre-approves a cell.
    """
    if not SD.DIVERGENCES.is_file():
        pytest.skip("no divergences recorded yet")
    recorded = json.loads(SD.DIVERGENCES.read_text())
    baseline = json.loads(SD.BASELINE.read_text())
    sources = SD.fixture_sources()
    for cell, divergence in sorted(recorded.items()):
        fixture, cc, opt, func = cell.split(":")
        assert fixture in sources, f"{cell}: no such fixture"
        assert (cc, opt) in H.stripped_lanes_for(sources[fixture]), (
            f"{cell}: not a stripped lane this corpus builds"
        )
        control = baseline.get(f"{fixture}:{cc}:{H.split_opt(opt)[0]}", {})
        assert control.get(func) == divergence["debug"], (
            f"{cell}: records -g={divergence['debug']!r} but baseline.json says "
            f"{control.get(func)!r} — refresh with --write-divergences"
        )
        assert divergence["kind"] == SD.classify(
            divergence["debug"], divergence["stripped"]
        )


# --------------------------------------------------------------------------
# The lane itself
# --------------------------------------------------------------------------


@pytest.mark.slow
def test_no_new_divergence_between_the_stripped_and_debug_builds():
    """The gate. Compiles and executes every stripped lane.

    Failure names BOTH verdicts, because the `-g` one is what makes the stripped
    one interpretable: `pass -> fail` is a defect in what analysis had to infer,
    and `fail -> fail` is not this lane's business at all.
    """
    baseline = json.loads(SD.BASELINE.read_text())
    plan = SD.planned_lanes(None)
    observed = H.run_lanes(
        [(fixture, cc, opt, ()) for fixture, cc, opt in plan], M.FIXTURE_FUZZ
    )
    found, problems = SD.compare(observed, baseline)
    assert not problems, "STRIPPED LANE INFRASTRUCTURE:\n  " + "\n  ".join(problems)
    recorded = (
        json.loads(SD.DIVERGENCES.read_text()) if SD.DIVERGENCES.is_file() else {}
    )
    new, healed = SD.ratchet(found, recorded)
    report = [
        f"{cell}: -g={found[cell]['debug']} stripped={found[cell]['stripped']}"
        for cell in new
    ] + [f"{cell}: no longer diverges" for cell in healed]
    assert not report, (
        "the stripped and `-g` builds of the same compile disagree in ways "
        "`stripped_divergences.json` does not record:\n  " + "\n  ".join(report)
    )
