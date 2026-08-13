"""Metamorphic invariants: properties that hold with no ground truth at all.

Every other lane in this corpus needs an oracle — the original source, a
recorded baseline, or a hand-written known answer. These tests need none. They
assert relationships that must hold between two recoveries of the *same*
program, which means they apply unchanged to real-world binaries where no
source will ever be available.

Two properties are checked here:

* **Convergence.** Decompile a function, recompile the recovered C, and
  decompile that. The second recovery describes a program built from the first,
  so a decompiler that is stable under round-tripping must reach a fixpoint.
  Drift that never settles means the recovery is adding or losing structure on
  every pass, which is a defect regardless of which pass is "right".

* **Optimization invariance.** The `-O0` and `-O2` builds of one source are the
  same program. Their recoveries may differ in spelling, but a function that
  recovers at one optimization level and vanishes at another is a gap in the
  recovery, not a property of the source.

Both are marked slow: they decompile and rebuild repeatedly.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(ROOT / "tools"))

D = importlib.import_module("diff_decompile")
H = importlib.import_module("fixture_harness")

# A spread across the corpus's shape families rather than a random sample:
# arithmetic, loops, switches, aggregates, a graph algorithm, and one of the
# language edge cases. Kept small because each case rebuilds twice.
CONVERGENCE_CASES = [
    ("01_conditional_polarity", "cmp_signed"),
    ("03_loop_shapes", "for_sum"),
    ("04_switch_shapes", "dense_jumptable"),
    ("20_graph_bfs", "graph_bfs"),
    ("46_bitset", "bitset_population"),
    ("118_bit_tricks", "clear_lowest_set"),
]

# Recorded non-convergence, found by this lane on the revision that introduced
# it: `graph_bfs` renders 10 conditionals on the second pass and 11 on the
# third, so the recovery is still adding control flow after two round trips.
# Held here rather than deleted, and asserted to STILL fail, so that fixing it
# is noticed instead of silently absorbed -- the same ratchet discipline
# `baseline.json` applies to the execution lanes.
# `03_loop_shapes:for_sum` diverges far harder than `graph_bfs`: the second
# pass recovers the loop cleanly (`for` 1, `goto` 0) and the third loses it
# outright (`for` 0, `if` 3, `goto` 4). So the structuring is not drifting by a
# conditional — a rebuild of our own emitted `for` produces a binary whose loop
# we then fail to recognise at all. That makes this the sharper instance of the
# same defect and the better one to fix first.
KNOWN_NON_CONVERGENT = {
    ("20_graph_bfs", "graph_bfs"),
    ("03_loop_shapes", "for_sum"),
}


def _decompile_named(binary: str, function: str) -> str | None:
    exports = D.exported_functions(binary)
    if function not in exports:
        return None
    return D.decompiled_c(binary, exports[function])


def _control_flow_shape(code: str) -> dict[str, int]:
    """The control-flow skeleton of a recovered function.

    Exact text is deliberately NOT compared. Round-tripping legitimately
    reorders commutative operands -- `a & (a - 1)` came back as `(a - 1) & a`
    on the next pass -- and asserting on spelling would be measuring rendering
    noise instead of recovery quality. What must be stable is the shape: the
    number of branches, loops, returns and unstructured jumps. Adding or losing
    any of those between passes means the recovery is not converging on a
    description of the program.
    """
    return {
        "if": code.count("if ("),
        "while": code.count("while ("),
        "for": code.count("for ("),
        "switch": code.count("switch ("),
        "goto": code.count("goto "),
        "return": code.count("return"),
        "break": code.count("break;"),
    }


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
@pytest.mark.parametrize(  # ty: ignore[unresolved-attribute]
    ("fixture", "function"), CONVERGENCE_CASES
)
def test_round_trip_reaches_a_fixpoint(
    fixture: str, function: str, tmp_path: Path
) -> None:
    """decompile -> rebuild -> decompile must not keep drifting.

    The first and second recoveries are allowed to differ: the second describes
    a binary built from recovered C, which is genuinely a different program
    text. What must NOT happen is continued drift — by the second rebuild the
    recovery has to be describing a stable program, so recoveries two and three
    are required to agree.
    """
    source = FIXTURES / "src" / f"{fixture}.c"
    assert source.exists(), source

    original, error = H.compile_fixture(source, "gcc", "O0", strict=False)
    assert original is not None, error

    first = _decompile_named(str(original), function)
    if first is None:
        pytest.skip(f"{fixture}:{function} not recovered from the original build")

    rebuilt_one, diagnostic = D.build_so_with_diagnostic(
        first, tmp_path, "rt1", link_against=str(original)
    )
    if rebuilt_one is None:
        pytest.skip(f"recovered C did not rebuild: {diagnostic[:200]}")

    second = _decompile_named(str(rebuilt_one), function)
    assert second is not None, "function vanished after one round trip"

    rebuilt_two, diagnostic = D.build_so_with_diagnostic(
        second, tmp_path, "rt2", link_against=str(original)
    )
    if rebuilt_two is None:
        pytest.skip(f"second-generation C did not rebuild: {diagnostic[:200]}")

    third = _decompile_named(str(rebuilt_two), function)
    assert third is not None, "function vanished after two round trips"

    converged = _control_flow_shape(second) == _control_flow_shape(third)
    if (fixture, function) in KNOWN_NON_CONVERGENT:
        assert not converged, (
            f"{fixture}:{function} now converges — remove it from "
            f"KNOWN_NON_CONVERGENT so the invariant is enforced again"
        )
        return
    assert converged, (
        f"{fixture}:{function} control flow is still changing on the third "
        f"pass: {_control_flow_shape(second)} then "
        f"{_control_flow_shape(third)}.\n--- second ---\n{second}\n"
        f"--- third ---\n{third}"
    )


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
@pytest.mark.parametrize(  # ty: ignore[unresolved-attribute]
    ("fixture", "function"), CONVERGENCE_CASES
)
def test_function_recovers_at_both_optimization_levels(
    fixture: str, function: str
) -> None:
    """A function must be recoverable from both builds of the same source.

    The recovered text is expected to differ — that is what optimization does.
    The invariant is weaker and unarguable: the function exists in both builds,
    so a recovery that produces a body at one level and nothing at the other has
    lost the function, not simplified it.
    """
    source = FIXTURES / "src" / f"{fixture}.c"
    assert source.exists(), source

    recovered = {}
    for optimization in ("O0", "O2"):
        binary, error = H.compile_fixture(source, "gcc", optimization, strict=False)
        assert binary is not None, error
        recovered[optimization] = _decompile_named(str(binary), function)

    missing = [level for level, code in recovered.items() if not code]
    present = [level for level, code in recovered.items() if code]
    assert not (missing and present), (
        f"{fixture}:{function} recovered at {present} but not at {missing} — "
        f"the function is present in both builds"
    )
