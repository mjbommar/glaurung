"""Path feasibility through `glaurung.source`.

The Rust tests in `src/csource/feasibility.rs` pin the analysis itself -- that
a contradictory guard is refuted, that a witness re-runs under the interpreter
and again against the binary gcc built, that implication from a contradiction
does not manufacture findings.

What is here is what only Python can check: the boundary. The shape of both
results, that the two layers agree, that the bounds arrive, and that a build
without the solver says so instead of quietly reporting nothing.
"""

from __future__ import annotations

import pytest

import glaurung

#: One path no input can take: `x > 10` and `x < 5` cannot both hold.
DECIDE = "int decide(int x) { if (x > 10) { if (x < 5) { return 1; } } return 0; }"

#: The structurer's duplicated-guard shape.
DUP = "int dup(int x) { if (x > 0) { if (x > 0) { return 1; } return 2; } return 3; }"

#: A division nothing constrains.
DIVIDE = "int divide(int a, int b) { return a / b; }"

#: Nothing to report: every path feasible, every guard load bearing.
FINE = "int fine(int a, int b) { return a + b; }"


def _available() -> bool:
    """Whether this build can answer, not whether the name exists.

    The binding is present in every build so the generated native stub
    describes one surface; the build without `symbolic` raises. `hasattr` is
    true either way and would run these against a build that cannot answer.
    """
    try:
        glaurung.source.path_feasibility(FINE, "fine")
    except RuntimeError:
        return False
    return True


needs_solver = pytest.mark.skipif(
    not _available(), reason="extension built without the `symbolic` feature"
)


@pytest.mark.core
def test_a_build_without_the_solver_raises_rather_than_reporting_nothing():
    """ "Nothing to report" and "this build cannot answer" are different facts."""
    if _available():
        pytest.skip("this build has the solver")
    with pytest.raises(RuntimeError, match="symbolic"):
        glaurung.source.path_feasibility(DECIDE, "decide")
    with pytest.raises(RuntimeError, match="symbolic"):
        glaurung.source.source_findings(DECIDE)


@needs_solver
def test_the_report_has_every_field_a_consumer_reads():
    report = glaurung.source.path_feasibility(DECIDE, "decide")
    for key in (
        "function",
        "paths",
        "feasible",
        "infeasible",
        "unknown",
        "unreachable_blocks",
        "cuts",
        "total",
        "abstained",
        "redundant_guards",
        "undefined_behaviour",
    ):
        assert key in report, key
    assert report["function"] == "decide"
    assert report["feasible"] + report["infeasible"] + report["unknown"] == len(
        report["paths"]
    )


@needs_solver
def test_the_contradictory_arm_is_refuted_and_its_block_is_dead():
    report = glaurung.source.path_feasibility(DECIDE, "decide")
    assert report["infeasible"] == 1
    assert report["total"] is True
    assert len(report["unreachable_blocks"]) == 1


@needs_solver
def test_a_feasible_path_carries_an_input_that_takes_it():
    report = glaurung.source.path_feasibility(DECIDE, "decide")
    taken = [p for p in report["paths"] if p["verdict"] == "feasible"]
    assert taken, report
    for path in taken:
        assert isinstance(path["args"], list)
        assert path["why"] is None
    for path in report["paths"]:
        if path["verdict"] == "infeasible":
            assert path["args"] is None


@needs_solver
def test_a_refused_function_abstains_and_names_the_construct():
    report = glaurung.source.path_feasibility("double f(double x) { return x; }", "f")
    assert report["paths"] == []
    assert report["abstained"] is not None
    assert "floating" in report["abstained"]


@needs_solver
def test_findings_report_only_functions_with_something_to_say():
    found = glaurung.source.source_findings(DECIDE + DUP + DIVIDE + FINE)
    named = {entry["function"] for entry in found}
    assert "fine" not in named, "a clean function would bury the others"
    assert {"decide", "dup", "divide"} <= named, named


@needs_solver
def test_a_duplicated_guard_is_reported_as_forced():
    found = glaurung.source.source_findings(DUP)
    entry = next(e for e in found if e["function"] == "dup")
    assert entry["redundant_guards"], entry
    for r in entry["redundant_guards"]:
        assert {"path", "decision", "implied_by"} <= set(r)


@needs_solver
def test_reachable_undefined_behaviour_carries_the_input_that_triggers_it():
    found = glaurung.source.source_findings(DIVIDE)
    entry = next(e for e in found if e["function"] == "divide")
    ub = entry["undefined_behaviour"]
    assert ub, entry
    assert ub[0]["property"] == "division_by_zero"
    # The divisor is the second parameter, and it must be the zero.
    assert ub[0]["args"][1] == 0


@needs_solver
def test_the_two_layers_agree_on_the_same_function():
    one = glaurung.source.path_feasibility(DUP, "dup")
    whole = glaurung.source.source_findings(DUP)
    entry = next(e for e in whole if e["function"] == "dup")
    for key in ("infeasible", "unreachable_blocks", "redundant_guards"):
        assert one[key] == entry[key], key


@needs_solver
def test_bounds_are_accepted_and_change_what_is_decided():
    """A bound too small to cover the loop must leave the enumeration partial.

    And a partial enumeration must not claim any block dead -- "every path I
    looked at is infeasible" is not "no input gets here".
    """
    loop = "int f(int n) { int s = 0; int i = 0; while (i < n) { s += i; i++; } return s; }"
    tight = glaurung.source.path_feasibility(loop, "f", max_block_visits=2)
    assert tight["total"] is False
    assert tight["cuts"], tight
    assert tight["unreachable_blocks"] == []


@needs_solver
def test_a_clean_function_reports_nothing_but_still_decides_its_paths():
    report = glaurung.source.path_feasibility(FINE, "fine")
    assert report["infeasible"] == 0
    assert report["redundant_guards"] == []
    assert report["undefined_behaviour"] == []
    assert report["feasible"] >= 1, "it still has a path, and it is takeable"
