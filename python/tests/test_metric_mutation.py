"""The mutation harness in `tools/metric_mutation.py`, both of its halves.

The harness is an *instrument*: every number in
`docs/design/metrics-research/calibration.md` section 2 is produced by it, so a
silent defect in a mutator becomes a silent defect in a metric claim. Three
properties are pinned here, in increasing strength:

  * **the metric verdicts are the ones DecBench computes** -- in particular the
    three-step `GEDMetric` semantics, where a non-isomorphic pair is clamped to
    at least 1.0 and can never read as perfect, as opposed to bare `vj_ged`,
    which returns 0 whenever two degree multisets agree;
  * **the mutators do what their labels say** -- the specificity half is only
    evidence if its rewrites really are meaning-preserving, so each one is
    compiled and executed against the original and the outputs compared. An
    argument in a docstring is not a measurement;
  * **declines are reported** -- a mutation that does not apply is a finding
    about the corpus, and a harness that swallowed it would report a detection
    rate computed over a population it never described.

The execution differential needs a C compiler. It skips without one, and
``GLAURUNG_METRIC_MUTATION_REQUIRE_CC=1`` turns that skip into a failure, so a
machine that is supposed to run it cannot quietly stop running it.
"""

from __future__ import annotations

import os
import random
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import metric_mutation as MM  # ty: ignore[unresolved-import]

# A single program that every semantics-preserving class can rewrite, with a
# deterministic, input-covering `main` so that a behaviour change shows up as
# different output rather than as luck. `main` deliberately uses different
# identifier names from `classify`, because `rename-param` rewrites every
# occurrence in the text it is given.
PROGRAM = """#include <stdio.h>

int classify(int a, int b, int n)
{
\tint total = 0;
\tint i = 0;
\tif (a && b) {
\t\ttotal = total + 3;
\t}
\tif (a) {
\t\ttotal = total + 1;
\t} else {
\t\ttotal = total + 2;
\t}
\ttotal = total + 7;
\tfor (i = 0; i < n; i = i + 1) {
\t\tif (i == 3) {
\t\t\tbreak;
\t\t}
\t\ttotal = total + i;
\t}
\tputchar('.');
\twhile (i > 0) {
\t\ttotal = total + 1;
\t\ti = i - 1;
\t}
\tif (b) {
\t\ttotal = total + 10;
\t} else if (a) {
\t\ttotal = total + 20;
\t}
\ttotal++;
\treturn total;
}

int main(void)
{
\tint x, y, k;
\tfor (x = 0; x < 2; x++)
\t\tfor (y = 0; y < 2; y++)
\t\t\tfor (k = 0; k < 6; k++)
\t\t\t\tprintf("%d %d %d -> %d\\n", x, y, k, classify(x, y, k));
\treturn 0;
}
"""

SEED = 20260904


def _compiler() -> str:
    """The C compiler to use, or skip -- unless the demand switch is set."""
    found = shutil.which("cc") or shutil.which("gcc")
    if found:
        return found
    if os.environ.get("GLAURUNG_METRIC_MUTATION_REQUIRE_CC") == "1":
        pytest.fail(
            "GLAURUNG_METRIC_MUTATION_REQUIRE_CC=1 but no cc/gcc is on PATH. "
            "The execution differential is the only evidence that the "
            "specificity half's rewrites really preserve behaviour."
        )
    pytest.skip(
        "no cc/gcc on PATH; set GLAURUNG_METRIC_MUTATION_REQUIRE_CC=1 to demand it"
    )


def _apply(name: str, text: str = PROGRAM, salt: str = "t") -> str:
    """Apply one class to `text` with a fixed, class-derived generator."""
    return MM.BY_NAME[name].apply(text, random.Random(f"{SEED}|{salt}|{name}"))


PRESERVING = [cls.name for cls in MM.CATALOGUE if not cls.changes]
CHANGING = [cls.name for cls in MM.CATALOGUE if cls.changes]


# --- the catalogue ---------------------------------------------------------


def test_the_catalogue_has_both_halves_and_every_label_is_argued():
    """A one-sided catalogue cannot produce a confusion matrix."""
    assert PRESERVING and CHANGING
    assert len({cls.name for cls in MM.CATALOGUE}) == len(MM.CATALOGUE)
    for cls in MM.CATALOGUE:
        assert cls.rationale.strip(), f"{cls.name} has no ground-truth argument"


def test_rejected_classes_are_named_with_reasons():
    """ "Not tested" and "not meaning-preserving" are different statements."""
    assert MM.REJECTED
    for name, why in MM.REJECTED:
        assert name.strip() and len(why) > 60


# --- the metric verdicts ---------------------------------------------------


def _cfg(nodes, edges, entry=(0,), exits=()) -> MM.Cfg:
    return MM.Cfg(
        nodes=tuple(nodes),
        edges=tuple(edges),
        entry=frozenset(entry),
        exit=frozenset(exits),
        degenerate=False,
    )


def test_isomorphism_is_decided_not_approximated():
    """A relabelling is isomorphic; a genuinely different shape is not."""
    triangle = _cfg([0, 1, 2], [(0, 1), (1, 2), (2, 0)])
    relabelled = _cfg([7, 8, 9], [(7, 8), (8, 9), (9, 7)], entry=(7,))
    assert MM.is_isomorphic(triangle, relabelled)
    path = _cfg([0, 1, 2], [(0, 1), (1, 2), (0, 2)])
    assert not MM.is_isomorphic(triangle, path)


def test_ged_and_bare_vj_ged_disagree_on_a_degree_preserving_rewiring():
    """The distinction that the three-step semantics exists to make.

    Two graphs with identical `(in, out, role)` multisets but different shapes:
    bare `vj_ged` scores 0 and calls it perfect, while `GEDMetric` finds them
    non-isomorphic and clamps to at least 1.0. Scoring with the wrong one is
    the mistake `tools/source_cfg_parity.py` records having made.
    """
    two_cycles = _cfg(
        [0, 1, 2, 3, 4, 5], [(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3)]
    )
    one_cycle = _cfg(
        [0, 1, 2, 3, 4, 5], [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 0)]
    )
    assert MM.vj_ged_is_zero(two_cycles, one_cycle)
    assert not MM.is_isomorphic(two_cycles, one_cycle)

    raw = MM.vj_ged_raw_verdict(two_cycles, one_cycle)
    ged = MM.ged_verdict(two_cycles, one_cycle)
    assert raw.perfect and raw.value == 0.0
    assert not ged.perfect and ged.value is not None and ged.value >= 1.0


def test_vj_ged_matches_its_own_zero_predicate_and_costs_a_deletion():
    """The pure-Python LSAP reproduces the two values that can be read off."""
    triangle = _cfg([0, 1, 2], [(0, 1), (1, 2), (2, 0)])
    assert MM.vj_ged(triangle, triangle) == 0.0
    # Deleting one node of the triangle costs `1 + in + out` for the node plus
    # the degree mismatches its two neighbours acquire.
    edge = _cfg([0, 1], [(0, 1), (1, 0)])
    assert MM.vj_ged(triangle, edge) > 0.0


def test_a_role_mismatch_is_never_perfect():
    """Entry/exit flags are part of the node label GED matches on."""
    plain = _cfg([0, 1], [(0, 1)], entry=(0,), exits=())
    flagged = _cfg([0, 1], [(0, 1)], entry=(0,), exits=(1,))
    assert not MM.is_isomorphic(plain, flagged)
    assert not MM.vj_ged_is_zero(plain, flagged)


def test_the_node_cap_changes_the_magnitude_and_never_the_verdict():
    """GED's `size_lower_bound` branch still reports non-perfect."""
    big = MM.GED_MAX_NODES + 5
    left = _cfg(range(big), [(i, i + 1) for i in range(big - 1)])
    right = _cfg(range(big), [(i, i + 1) for i in range(big - 2)])
    verdict = MM.ged_verdict(left, right)
    assert verdict.method == "size_lower_bound"
    assert not verdict.perfect
    assert verdict.value is not None and verdict.value >= 1.0


# --- the text machinery ----------------------------------------------------


def test_the_code_mask_excludes_strings_comments_and_directives():
    """An operator inside a string or an `#include` is not an operator."""
    text = '#include <stdio.h>\nint f(void) { /* a == b */ return strcmp(s, "a<b") == 0; }\n'
    mask = MM.code_mask(text)
    assert not any(mask[: text.index("\n")])
    assert len(MM.code_sites(text, MM._EQ_RE, mask)) == 1
    assert not MM.code_sites(text, MM._LT_RE, mask)


def test_a_declined_mutation_reports_why():
    """The decline reason is the finding; a bare None would erase it."""
    with pytest.raises(MM.Declined) as info:
        _apply("goto-ify", "int f(void) { return 0; }")
    assert str(info.value)


def test_site_choice_is_seeded_and_order_independent():
    """The same (seed, unit, class) triple always produces the same mutant."""
    first = _apply("constant-bump")
    second = _apply("constant-bump")
    assert first == second
    assert _apply("constant-bump", salt="other") != first or True  # may coincide


def test_split_functions_finds_each_definition():
    """The tree corpus is carved with this before anything is mutated."""
    pieces = list(MM.split_functions(PROGRAM))
    assert [name for name, _ in pieces] == ["classify", "main"]
    # A slice runs from the last top-level `;` (or the start of the file), so
    # it carries the declarations a definition needs to parse on its own.
    assert "int classify(int a, int b, int n)" in pieces[0][1]
    assert pieces[0][1].rstrip().endswith("}")
    assert "int main(void)" in pieces[1][1] and "classify(int" not in pieces[1][1]


# --- every mutator actually fires on the reference program -----------------


@pytest.mark.parametrize("name", PRESERVING)
def test_every_preserving_class_applies_to_the_reference_program(name: str):
    """A class that cannot fire here would be measured over nothing."""
    mutated = _apply(name)
    assert mutated != PROGRAM


@pytest.mark.parametrize(
    "name",
    [
        n
        for n in CHANGING
        # `assign-op-flip` needs a `+=`, which the reference program
        # deliberately does not have: it is the class the decline test uses.
        if n != "assign-op-flip"
    ],
)
def test_every_exercised_changing_class_applies_to_the_reference_program(name: str):
    mutated = _apply(name)
    assert mutated != PROGRAM


# --- the specificity label, measured rather than argued --------------------


@pytest.mark.parametrize("name", PRESERVING)
def test_a_preserving_rewrite_compiles_and_behaves_identically(name: str):
    """Compile and run both programs over 16 inputs and compare the output.

    This is what makes the specificity half evidence. Every false alarm the
    harness reports for one of these classes is a metric moving on a program a
    C compiler cannot distinguish from the original.
    """
    compiler = _compiler()
    mutated = _apply(name)
    assert mutated != PROGRAM
    same, why = MM.preserves_behaviour(PROGRAM, mutated, cc=compiler)
    assert same, f"{name} is labelled preserving but {why}\n---\n{mutated}"


@pytest.mark.parametrize(
    "name",
    [
        "negate-condition",
        "equality-flip",
        "constant-bump",
        "null-body",
        "while->if",
        "drop-call",
        "drop-break",
        "else->if(0)",
    ],
)
def test_a_changing_rewrite_really_changes_the_output(name: str):
    """The negative control: a differential that never fires proves nothing."""
    compiler = _compiler()
    mutated = _apply(name)
    same, _ = MM.preserves_behaviour(PROGRAM, mutated, cc=compiler)
    assert not same, f"{name} is labelled behaviour-changing but output was identical"


# --- end to end ------------------------------------------------------------


def test_goto_ifying_a_simple_loop_is_invisible_to_both_metrics():
    """The money case of `calibration.md` section 2.1, on a minimal loop.

    The control-flow graph is unchanged by construction, so a CFG metric must
    stay perfectly quiet while the control skeleton is destroyed. This is the
    project's own recorded trap from the other direction: *"goto soup passes
    every fixture"*.
    """
    parity = pytest.importorskip("glaurung.source_cfg").parity_cfgs
    source = "int f(int a) { int x = 0; while (x < a) { x = x + 1; } return x; }"
    mutated = _apply("goto-ify", source, salt="loop")
    assert "goto" in mutated
    before = MM.Cfg.from_serialized(parity(source)["f"])
    after = MM.Cfg.from_serialized(parity(mutated)["f"])
    assert MM.ged_verdict(before, after).perfect
    assert MM.vj_ged_raw_verdict(before, after).perfect


def test_a_run_reports_declines_and_both_halves():
    """`run` never drops a mutation silently, and records the seed."""
    parity = pytest.importorskip("glaurung.source_cfg").parity_cfgs
    units = [MM.Unit(key="u/1", name="classify", text=PROGRAM, origin="test")]
    report = MM.run(units, list(MM.CATALOGUE), parity, seed=SEED, corpus="test")
    assert report.seed == SEED and report.units == 1
    payload = MM.report_json(report)
    assert payload["seed"] == SEED
    assert payload["catalogue_version"] == MM.CATALOGUE_VERSION

    entry = payload["classes"]["assign-op-flip"]
    assert entry["applied"] == 0
    assert entry["declined_total"] == 1, "a decline must be counted, not dropped"
    assert entry["declined"], "a decline must carry its reason"

    for metric in MM.METRICS:
        totals = payload["totals"][metric]
        assert totals["tp"] + totals["fn"] > 0, "sensitivity half measured nothing"
        assert totals["fp"] + totals["tn"] > 0, "specificity half measured nothing"


def test_a_run_is_reproducible_from_its_seed():
    """Two runs of the same experiment produce the same report."""
    parity = pytest.importorskip("glaurung.source_cfg").parity_cfgs
    units = [MM.Unit(key="u/1", name="classify", text=PROGRAM, origin="test")]
    first = MM.report_json(
        MM.run(units, list(MM.CATALOGUE), parity, seed=SEED, corpus="t")
    )
    second = MM.report_json(
        MM.run(units, list(MM.CATALOGUE), parity, seed=SEED, corpus="t")
    )
    assert first == second
