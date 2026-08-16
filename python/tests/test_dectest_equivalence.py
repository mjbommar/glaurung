"""A scoped run must produce the same verdict as the full gate.

This is the property the whole fast loop rests on. `tools/dectest.py` exists so
you can ask about one function in ~3 seconds instead of running 56 lanes for ~3
minutes — but a fast answer that differs from the gate's answer is worse than no
fast answer, because you would tune against it and then discover the difference
at gate time.

Two things could break the equivalence, and both are checked here:

  * **the vectors.** `diff_decompile._stable_seed` derives each function's fuzz
    seed from its own name, so filtering must not shift them. If seeds were
    positional, running one function would test it with another's inputs.
  * **the binary.** The lane compiles the whole fixture either way; filtering
    selects which exports are executed, not what is compiled. A filtered compile
    would change inlining and codegen.

Marked slow: it compiles and executes. The pure selection tests are in
`test_dectest_selection.py` and run in the normal suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))

import arch_roundtrip as AR  # ty: ignore[unresolved-import]
import dectest as D  # ty: ignore[unresolved-import]
import fixture_harness as H  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]

pytestmark = pytest.mark.slow

# The comparison is only meaningful on a lane holding BOTH verdict classes: an
# all-pass lane cannot detect a filter that breaks the structural/non-executable
# path, and vice versa. Keep this on a compact mixed lane so the equivalence
# proof stays fast as decompiler improvements move old failures to pass.
LANE = ("08_indirect_dispatch", "clang", "O0")

#: The same property on a cross-architecture lane, where the filter is newer and
#: the plumbing longer: `arch_roundtrip._run_lane` cross-builds the target,
#: builds a pinned host reference, and compares them through `diff_decompile`.
#: Compact and mixed for the same reason as `LANE`.
ARCH_LANE = ("112_recursion_shapes", "i386", "O0")


@pytest.fixture(scope="module")
def whole_lane():
    fixture, cc, opt = LANE
    funcs = tuple(D.function_universe()[fixture])
    return H.run_lanes([(fixture, cc, opt, funcs)], fuzz=M.FIXTURE_FUZZ, jobs=1)


def test_a_single_function_run_agrees_with_the_whole_lane(whole_lane):
    fixture, cc, opt = LANE
    key = f"{fixture}:{cc}:{opt}"
    full = whole_lane[key]
    assert "__lane__" not in full, full

    # Check one function of each verdict class, so a filter that broke only the
    # structural path (or only the passing one) cannot slip through.
    a_pass = next((f for f, st in sorted(full.items()) if st == "pass"), None)
    a_nonpass = next((f for f, st in sorted(full.items()) if st != "pass"), None)
    assert a_pass and a_nonpass, f"lane has no pass/non-pass mix to compare: {full}"

    for name in (a_pass, a_nonpass):
        scoped = H.run_lanes([(fixture, cc, opt, (name,))], fuzz=M.FIXTURE_FUZZ, jobs=1)
        assert scoped[key] == {name: full[name]}, (
            f"{name}: scoped run said {scoped[key]}, whole lane said {full[name]}"
        )


def test_a_filtered_run_reports_only_what_was_asked_for(whole_lane):
    """Scope must be honest in both directions: no extra functions leaking into
    the result, which would make `--full` output disagree with the selector."""
    fixture, cc, opt = LANE
    key = f"{fixture}:{cc}:{opt}"
    two = tuple(sorted(whole_lane[key])[:2])
    scoped = H.run_lanes([(fixture, cc, opt, two)], fuzz=M.FIXTURE_FUZZ, jobs=1)
    assert set(scoped[key]) == set(two)


@pytest.fixture(scope="module")
def whole_arch_lane():
    fixture, arch, opt = ARCH_LANE
    funcs = tuple(D.arch_lane_function_universe()[(fixture, arch, opt)])
    return AR.run_lanes([(fixture, arch, opt, funcs)], fuzz=M.FIXTURE_FUZZ, jobs=1)


def test_a_single_function_arch_run_agrees_with_the_whole_arch_lane(whole_arch_lane):
    """What makes architecture-scoped iteration trustworthy rather than merely fast.

    `arch_roundtrip` had no function filter at all, so asking about one function
    on i386 meant executing every export in the fixture — 11.4s on
    `03_loop_shapes:i386:O2` for a question worth 0.9s. The filter that closes
    that gap is only worth having if a filtered verdict equals the unfiltered
    one, which is exactly the guarantee the host lanes already carry above.
    """
    fixture, arch, opt = ARCH_LANE
    key = f"{fixture}:{arch}:{opt}"
    full = whole_arch_lane[key]
    assert "__lane__" not in full, full

    a_pass = next((f for f, st in sorted(full.items()) if st == "pass"), None)
    a_nonpass = next((f for f, st in sorted(full.items()) if st != "pass"), None)
    assert a_pass and a_nonpass, f"lane has no pass/non-pass mix to compare: {full}"

    for name in (a_pass, a_nonpass):
        scoped = AR.run_lanes(
            [(fixture, arch, opt, (name,))], fuzz=M.FIXTURE_FUZZ, jobs=1
        )
        assert scoped[key] == {name: full[name]}, (
            f"{name}: scoped run said {scoped[key]}, whole lane said {full[name]}"
        )


def test_a_scoped_arch_result_map_is_not_writable_as_a_baseline(whole_arch_lane):
    """The arch counterpart of the rule below: no `__toolchain__` fingerprint, so
    `arch_roundtrip`'s own `--write-baseline` precondition refuses it."""
    problems = AR.schema_problems(whole_arch_lane, AR.REQUIRED_MATRIX)
    assert any(H.TOOLCHAIN_KEY in p for p in problems), problems


def test_a_scoped_result_map_is_not_writable_as_a_baseline(whole_lane):
    """The reason `dectest` has no `--write-baseline`: a scoped map carries no
    toolchain fingerprint, so `fixture_harness`'s own precondition rejects it.
    Belt and braces — the flag is absent AND the data would be refused."""
    problems = H.schema_problems(whole_lane, H.REQUIRED_MATRIX)
    assert any(H.TOOLCHAIN_KEY in p for p in problems), problems
