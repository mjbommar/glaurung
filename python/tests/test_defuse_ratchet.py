"""Tests for `tools/defuse_ratchet.py`: the guard on the def-before-use writer.

`python/tests/test_decompiler_defuse_census.py` is a two-sided ratchet, and the
side that fires on an IMPROVEMENT tells you to run
`tools/gen_defuse_baseline.py`. That writer used to rewrite the file from the
current measurement with no guard at all, so the documented workflow could —
and did — reset the ceiling upward without anyone reading the number. Between
`9dfd8457` and `fd0b6455`, a single commit, `rustc:O0` went 7525 -> 7535 and
`rustc:O2` went 4451 -> 4457 undefined reads while every tracked `required` cell
stayed byte-identical.

These tests are on synthetic censuses, deliberately: the guard is a pure
decision over two dicts, and pinning it to the real corpus would make it a
`slow` test that nobody runs and that changes meaning every time the decompiler
does. The real corpus exercises the same functions through
`tools/gen_defuse_baseline.py`.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "defuse_ratchet.py"
BASELINE = ROOT / "tests" / "decompiler_fixtures" / "defuse_baseline.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("defuse_ratchet", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def dr():
    return _load_tool()


def _census(
    lane_totals: dict[str, dict[str, int]],
    fixture_lane_totals: dict[str, dict[str, int]] | None = None,
    required: dict[str, list[str]] | None = None,
) -> dict:
    report = {
        "lane_totals": lane_totals,
        "required": required or {},
        "problems": [],
    }
    if fixture_lane_totals is not None:
        report["fixture_lane_totals"] = fixture_lane_totals
    return report


def _totals(violations: int, with_violations: int = 1, emitted: int = 10) -> dict:
    return {
        "functions_emitted": emitted,
        "functions_with_violations": with_violations,
        "violations": violations,
    }


def test_language_totals_keep_rust_from_obscuring_c(dr):
    lanes = {
        "gcc:O0": _totals(7, with_violations=2, emitted=20),
        "clang:O2": _totals(11, with_violations=3, emitted=30),
        "rustc:O0": _totals(900, with_violations=200, emitted=400),
        "rustc:O2": _totals(500, with_violations=100, emitted=300),
    }
    assert dr.language_totals(lanes) == {
        "c": {
            "functions_emitted": 50,
            "functions_with_violations": 5,
            "violations": 18,
        },
        "rust": {
            "functions_emitted": 700,
            "functions_with_violations": 300,
            "violations": 1400,
        },
    }


def test_committed_language_totals_match_the_lane_census(dr):
    baseline = json.loads(BASELINE.read_text())
    assert baseline["language_totals"] == dr.language_totals(baseline["lane_totals"])


# --------------------------------------------------------------------------
# parse_acceptances
# --------------------------------------------------------------------------


def test_an_acceptance_defaults_to_the_violations_measure(dr):
    parsed = dr.parse_acceptances(["rustc:O0=+10: aggregate-return work, fd0b6455"])
    assert parsed == {
        ("rustc:O0", "violations"): (10, "aggregate-return work, fd0b6455")
    }


def test_the_other_measure_is_named_with_a_slash(dr):
    # The lane name already contains a colon, which is why the measure is not
    # colon-separated.
    parsed = dr.parse_acceptances(["rustc:O0/functions_with_violations=+3: why"])
    assert parsed == {("rustc:O0", "functions_with_violations"): (3, "why")}


def test_a_reason_may_contain_colons_and_equals_signs(dr):
    parsed = dr.parse_acceptances(["gcc:O2=+1: see x=y, ticket: 12"])
    assert parsed[("gcc:O2", "violations")] == (1, "see x=y, ticket: 12")


@pytest.mark.parametrize(
    "bad",
    [
        "rustc:O0+10: why",  # no '='
        "rustc:O0=10: why",  # no '+': only rises are acceptable here
        "rustc:O0=+10",  # no reason at all
        "rustc:O0=+10:   ",  # blank reason
        "rustc:O0=-10: why",  # a fall needs no acceptance
    ],
)
def test_a_malformed_acceptance_is_refused_rather_than_ignored(dr, bad):
    with pytest.raises(dr.AcceptSyntaxError):
        dr.parse_acceptances([bad])


def test_an_unknown_measure_is_refused(dr):
    with pytest.raises(dr.AcceptSyntaxError, match="unknown measure"):
        dr.parse_acceptances(["rustc:O0/functions_emitted=+1: why"])


def test_the_same_ceiling_cannot_be_accepted_twice(dr):
    with pytest.raises(dr.AcceptSyntaxError, match="duplicate"):
        dr.parse_acceptances(["rustc:O0=+1: a", "rustc:O0=+2: b"])


# --------------------------------------------------------------------------
# find_regressions — the frictionless directions
# --------------------------------------------------------------------------


def test_an_unchanged_census_reports_nothing(dr):
    baseline = _census({"gcc:O0": _totals(7)})
    assert dr.find_regressions(_census({"gcc:O0": _totals(7)}), baseline) == []


def test_lowering_a_ceiling_needs_no_flag(dr):
    baseline = _census({"gcc:O0": _totals(7)})
    assert dr.find_regressions(_census({"gcc:O0": _totals(4)}), baseline) == []


def test_a_lane_the_baseline_never_recorded_needs_no_flag(dr):
    # A new compiler lane is an addition, not a regression.
    baseline = _census({"gcc:O0": _totals(7)})
    current = _census({"gcc:O0": _totals(7), "rustc:O0": _totals(900)})
    assert dr.find_regressions(current, baseline) == []


def test_a_required_cell_the_baseline_never_recorded_needs_no_flag(dr):
    baseline = _census({}, required={"a:gcc:O0:f": []})
    current = _census({}, required={"a:gcc:O0:f": [], "new:gcc:O0:g": ["read of x"]})
    assert dr.find_regressions(current, baseline) == []


def test_a_new_fixture_may_raise_a_lane_total_for_free(dr):
    # The whole rise is charged to a fixture-lane the baseline had never seen.
    baseline = _census(
        {"gcc:O0": _totals(7)},
        fixture_lane_totals={"01_old:gcc:O0": _totals(7)},
    )
    current = _census(
        {"gcc:O0": _totals(19, with_violations=2, emitted=20)},
        fixture_lane_totals={
            "01_old:gcc:O0": _totals(7),
            "197_new:gcc:O0": _totals(12),
        },
    )
    assert dr.find_regressions(current, baseline) == []


# --------------------------------------------------------------------------
# find_regressions — the direction that must argue for itself
# --------------------------------------------------------------------------


def test_raising_a_lane_total_is_a_regression(dr):
    baseline = _census({"rustc:O0": _totals(7525)})
    current = _census({"rustc:O0": _totals(7535)})
    (found,) = dr.find_regressions(current, baseline)
    assert (found.kind, found.key, found.measure) == (
        "lane_total",
        "rustc:O0",
        "violations",
    )
    assert (found.before, found.after, found.attributable) == (7525, 7535, 10)
    assert found.token == "rustc:O0=+10"


def test_raising_the_violating_function_count_is_its_own_regression(dr):
    baseline = _census({"gcc:O2": _totals(100, with_violations=10)})
    current = _census({"gcc:O2": _totals(100, with_violations=12)})
    (found,) = dr.find_regressions(current, baseline)
    assert found.measure == "functions_with_violations"
    assert found.token == "gcc:O2/functions_with_violations=+2"


def test_an_existing_fixture_getting_worse_is_charged_even_beside_a_new_one(dr):
    # The line this guard draws: a rise inside a fixture-lane the baseline
    # already tracked is charged; the new fixture's own violations are not, and
    # the new fixture's headroom does not absorb the old fixture's regression.
    baseline = _census(
        {"gcc:O0": _totals(7)},
        fixture_lane_totals={"01_old:gcc:O0": _totals(7)},
    )
    current = _census(
        {"gcc:O0": _totals(22, with_violations=2, emitted=20)},
        fixture_lane_totals={
            "01_old:gcc:O0": _totals(10),
            "197_new:gcc:O0": _totals(12),
        },
    )
    (found,) = dr.find_regressions(current, baseline)
    assert found.after - found.before == 15
    assert found.attributable == 3
    assert "new fixture-lane" in found.detail


def test_without_a_per_fixture_breakdown_the_whole_rise_is_charged(dr):
    # The committed baseline predates `fixture_lane_totals`. Nothing can be
    # attributed, so the conservative direction is to ask for a reason and let
    # the reason say "new fixture 197 adds 12 functions".
    baseline = _census({"gcc:O0": _totals(7)})
    current = _census(
        {"gcc:O0": _totals(19)},
        fixture_lane_totals={"197_new:gcc:O0": _totals(12)},
    )
    (found,) = dr.find_regressions(current, baseline)
    assert found.attributable == 12
    assert found.detail == "no per-fixture breakdown in the baseline"


def test_a_new_violation_in_a_tracked_required_function_is_a_regression(dr):
    baseline = _census({}, required={"195:gcc:O0:make_quad": ["read of a"]})
    current = _census({}, required={"195:gcc:O0:make_quad": ["read of a", "read of b"]})
    (found,) = dr.find_regressions(current, baseline)
    assert found.kind == "required_function"
    assert found.token == "195:gcc:O0:make_quad/undefined_reads=+1"


def test_a_resolved_required_violation_is_not_a_regression(dr):
    baseline = _census({}, required={"195:gcc:O0:make_quad": ["read of a"]})
    assert (
        dr.find_regressions(
            _census({}, required={"195:gcc:O0:make_quad": []}), baseline
        )
        == []
    )


# --------------------------------------------------------------------------
# apply_acceptances
# --------------------------------------------------------------------------


def test_an_exact_acceptance_records_the_lane_delta_and_reason(dr):
    baseline = _census({"rustc:O0": _totals(7525)})
    current = _census({"rustc:O0": _totals(7535)})
    found = dr.find_regressions(current, baseline)
    records, problems = dr.apply_acceptances(
        found, dr.parse_acceptances(["rustc:O0=+10: aggregate-return work, fd0b6455"])
    )
    assert problems == []
    assert records == [
        {
            "attributable_delta": 10,
            "delta": 10,
            "from": 7525,
            "key": "rustc:O0",
            "kind": "lane_total",
            "measure": "violations",
            "reason": "aggregate-return work, fd0b6455",
            "to": 7535,
        }
    ]


def test_an_unaccepted_regression_names_the_flag_that_would_accept_it(dr):
    baseline = _census({"rustc:O0": _totals(7525)})
    current = _census({"rustc:O0": _totals(7535)})
    _, problems = dr.apply_acceptances(dr.find_regressions(current, baseline), {})
    assert len(problems) == 1
    assert "UNACCEPTED" in problems[0]
    assert "--accept-regression 'rustc:O0=+10: <why>'" in problems[0]


def test_accepting_a_smaller_delta_does_not_let_the_rest_through(dr):
    baseline = _census({"rustc:O0": _totals(7525)})
    current = _census({"rustc:O0": _totals(7535)})
    records, problems = dr.apply_acceptances(
        dr.find_regressions(current, baseline),
        dr.parse_acceptances(["rustc:O0=+2: only two, honest"]),
    )
    assert records == []
    assert "WRONG DELTA" in problems[0]
    assert "you accepted +2, the census measured +10" in problems[0]


def test_accepting_a_larger_delta_does_not_pre_authorise_drift(dr):
    baseline = _census({"rustc:O0": _totals(7525)})
    current = _census({"rustc:O0": _totals(7530)})
    records, problems = dr.apply_acceptances(
        dr.find_regressions(current, baseline),
        dr.parse_acceptances(["rustc:O0=+50: room to grow"]),
    )
    assert records == []
    assert "WRONG DELTA" in problems[0]


def test_an_acceptance_that_matches_nothing_is_itself_a_problem(dr):
    # Otherwise the flag outlives the movement and silently pre-authorises the
    # next one.
    records, problems = dr.apply_acceptances(
        [], dr.parse_acceptances(["rustc:O0=+10: stale"])
    )
    assert records == []
    assert problems == [
        "STALE       --accept-regression for rustc:O0/violations "
        "matched no measured regression; remove it"
    ]


# --------------------------------------------------------------------------
# the history that makes the drift impossible to regenerate away
# --------------------------------------------------------------------------


def test_the_accepted_history_is_carried_forward_into_the_next_baseline(dr):
    previous = {
        "accepted_regressions": [
            {
                "key": "rustc:O0",
                "measure": "violations",
                "from": 7500,
                "to": 7525,
                "reason": "a",
            }
        ]
    }
    carried = dr.carry_forward(
        previous,
        [
            {
                "key": "rustc:O0",
                "measure": "violations",
                "from": 7525,
                "to": 7535,
                "reason": "b",
            }
        ],
    )
    assert [entry["reason"] for entry in carried] == ["a", "b"]


def test_a_clean_regeneration_adds_no_history_entry(dr):
    previous = {
        "accepted_regressions": [
            {"key": "x", "measure": "violations", "from": 1, "to": 2, "reason": "a"}
        ]
    }
    assert len(dr.carry_forward(previous, [])) == 1


def test_the_drift_report_sums_the_walk_up_rather_than_the_last_step(dr):
    history = [
        {"key": "rustc:O0", "measure": "violations", "from": 7500, "to": 7525},
        {"key": "rustc:O0", "measure": "violations", "from": 7525, "to": 7535},
    ]
    lines = dr.drift_lines(history)
    assert lines[0] == "accepted regressions recorded: 2"
    assert lines[1].endswith("rustc:O0/violations: 7500 -> 7535 (+35)")


def test_no_history_means_no_drift_noise(dr):
    assert dr.drift_lines([]) == []


def test_a_renumbered_temporary_is_not_a_regression(dr):
    """The `var79` -> `var81` case, which cost a spurious accepted regression.

    `165_bitstream_reader:clang:O2:bit165_cross_check` carried exactly one
    undefined read before and after the byte-view `not` fix, at the same
    position in the same else-arm. The fix changed how many temporaries the
    function emits, so every later temporary renumbered. The ratchet compared
    raw message strings, found one gone and one new, and demanded a
    justification for a movement whose own printed delta was `+0`.

    Temporary numbering is not a property anyone intends to pin, and any lifter
    change that emits one more or one fewer temporary renumbers everything after
    it -- so this false positive would recur across a large fraction of lifter
    work, training the reader to accept without looking. That is exactly what
    the acceptance flag exists to prevent.
    """
    cell = "165_bitstream_reader:clang:O2:bit165_cross_check"
    baseline = _census({}, required={cell: ["var79 is read but never defined"]})
    current = _census({}, required={cell: ["var81 is read but never defined"]})
    assert dr.find_regressions(current, baseline) == []


def test_a_genuinely_new_undefined_read_still_regresses(dr):
    """The other half: normalising must not blind the gate to a real movement.

    Same cell, same count, but a DIFFERENT KIND of undefined value -- a frame
    register rather than a temporary. Normalisation collapses serial numbers,
    never the identity of what is undefined.
    """
    cell = "c:gcc:O0:f"
    baseline = _census({}, required={cell: ["var79 is read but never defined"]})
    current = _census({}, required={cell: ["rbp is read but never defined"]})
    found = dr.find_regressions(current, baseline)
    assert len(found) == 1, found
    assert "rbp" in found[0].detail
