"""Control-skeleton lane: the recovered C must keep the SHAPE of the source.

The execution differential answers "does it behave the same" and
`docs/development/traps.md` records what it cannot answer: goto soup passes every
fixture. The structural lane counts `switch`, `goto` and `break` tokens per
function, which is an absolute count with no reference to the source, and cannot
see a `do`-`while` that became a `while`, an arm that was duplicated, or a
`continue` that became an if/else.

This lane closes that. For every REQUIRED function of every C fixture, in every
declared compile lane, it records the Zhang-Shasha tree edit distance between the
source's control skeleton and the decompiled output's -- the metric
`src/metrics/tree_distance.rs` defines and `python/tests/test_native_metrics.py`
validates. `tools/fixture_structure_census.py` is the census; this file is the
gate over its committed baseline, `tests/decompiler_fixtures/structure_baseline.json`.

Two halves, as in the sibling def-use census:

* **The committed artifact is checked on its own**, needing no build: an
  abstention carries no distance, the rolled-up summaries agree with the cells
  they were rolled up from, the recorded null-decompiler distances still match the
  checked-in sources, and no lane has fallen below the null decompiler.
* **The census is re-run and diffed**, per cell and in both directions. A cell
  whose distance ROSE is a structural regression; one whose distance FELL is a
  real improvement that must be recorded, or the gate would happily let it come
  back.

What this lane does NOT cover is in the census tool's module docstring, and two
parts of it matter when reading a failure. The projection drops every expression
interior, so a flipped comparison or a bumped constant is invisible here by
construction. And at `-O2` the source skeleton is not the decompiler's target --
the compiler restructured the code first -- so the `-O2` cells ratchet movement
without their absolute values being a decompiler-quality reading.

Needs the built fixture matrix (`tests/decompiler_fixtures/build`) and the pinned
`fixture_toolchain` Docker image, exactly as the def-use census does, so it runs
by hand rather than in CI. Refresh with::

    uv run python tools/fixture_structure_census.py --write
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from glaurung._native import metrics

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import fixture_structure_census as C  # ty: ignore[unresolved-import]

BASELINE = C.BASELINE


@pytest.fixture(scope="session")
def committed() -> dict[str, Any]:
    """The committed census."""
    assert BASELINE.is_file(), (
        f"{BASELINE.name} missing -- regenerate with "
        "tools/fixture_structure_census.py --write"
    )
    return json.loads(BASELINE.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def measured() -> dict[str, Any]:
    """A fresh census. Compiles and decompiles the whole C corpus four times."""
    return C.structure_report()


# --- the committed artifact, checked without a build ------------------------


def test_the_baseline_declares_the_projection_it_was_measured_with(committed) -> None:
    """A skeleton-rule change invalidates every number here, so it is recorded.

    `SKELETON_VERSION` is the version of the projection's decisions -- what
    canonicalizes, what is dropped -- and `MAX_SKELETON_NODES` is where the
    metric abstains. A baseline measured under different values is not a
    baseline for this build; it is a different measurement wearing the name.
    """
    assert committed["skeleton_version"] == metrics.SKELETON_VERSION
    assert committed["max_skeleton_nodes"] == metrics.MAX_SKELETON_NODES
    assert committed["null_decompiler_c"] == C.NULL_DECOMPILER_C


def test_no_abstention_was_recorded_as_a_zero(committed) -> None:
    """The invariant the whole metric programme is built on.

    Above `MAX_SKELETON_NODES` the distance is `None`. Recorded as `0` it would
    read as a perfect structural match for a function nobody measured, and would
    then be indistinguishable from a real one in every rollup that followed.
    """
    problems = []
    for key, cell in sorted(committed["cells"].items()):
        status = cell["status"]
        assert status in C.STATUSES, f"{key}: unknown status {status!r}"
        if status == "scored":
            if "distance" not in cell:
                problems.append(f"{key}: scored with no distance")
        elif "distance" in cell:
            problems.append(f"{key}: {status} but carries distance {cell['distance']}")
    assert not problems, "ABSTENTIONS COLLAPSED INTO SCORES:\n  " + "\n  ".join(
        problems
    )
    # ...and the corpus really does exercise the abstention, so this invariant
    # is not being asserted over a set that never contains one.
    assert any(cell["status"] == "abstained" for cell in committed["cells"].values()), (
        "no abstention in the census: check the cap is still reachable"
    )


def test_the_committed_summaries_agree_with_the_committed_cells(committed) -> None:
    """The rollups are derived, so a hand-edited baseline contradicts itself.

    Every number the report prints comes from `lane_summary` and
    `band_summary`; both are recomputable from `cells`. Recomputing them here is
    what makes a baseline that was edited rather than regenerated fail.
    """
    lanes: dict[str, dict[str, int]] = {}
    bands: dict[str, dict[str, dict[str, int]]] = {}
    for key in sorted(committed["cells"]):
        _fixture, cc, opt, _name = key.split(":")
        cell = committed["cells"][key]
        lane = f"{cc}:{opt}"
        C.accumulate(lanes.setdefault(lane, C.empty_summary()), cell)
        band = C.band_for(cell.get("source_nodes", 0))
        C.accumulate(
            bands.setdefault(lane, {}).setdefault(band, C.empty_summary()), cell
        )
    assert lanes == committed["lane_summary"]
    assert bands == committed["band_summary"]


def test_the_recorded_null_baseline_still_matches_the_checked_in_sources(
    committed,
) -> None:
    """Reproject every source and check the recorded source side, with no build.

    `source_nodes` and `null_distance` depend on the checked-in `.c` files and
    the projection alone -- not on the decompiler, the compiler or the built
    matrix. So they can be recomputed here in a second, and a source edit or a
    projection change that silently moved the floor under the whole census
    fails HERE rather than being absorbed into the next regeneration.
    """
    null = C.null_skeleton()
    assert null.render() == "(seq return)" and len(null) == 2

    projected: dict[str, Any] = {}
    problems = []
    for key, cell in sorted(committed["cells"].items()):
        fixture, _cc, _opt, name = key.split(":")
        if fixture not in projected:
            source = C.c_source(fixture)
            assert source is not None, f"{fixture}: no C source, but cells recorded"
            projected[fixture] = metrics.skeletons(source.read_text(encoding="utf-8"))
        skeleton = projected[fixture].get(name)
        if skeleton is None:
            if cell["status"] != "no_source_function":
                problems.append(
                    f"{key}: absent from the source, recorded as {cell['status']}"
                )
            continue
        if cell.get("source_nodes") != len(skeleton):
            problems.append(
                f"{key}: source_nodes {cell.get('source_nodes')} recorded, "
                f"{len(skeleton)} projected now"
            )
        expected = metrics.tree_edit_distance(skeleton, null)
        if cell.get("null_distance") != expected:
            problems.append(
                f"{key}: null_distance {cell.get('null_distance')} recorded, "
                f"{expected} now"
            )
    assert not problems, (
        "THE SOURCE SIDE OF THE CENSUS MOVED -- the null baseline and every "
        "score in the committed census are relative to it:\n  " + "\n  ".join(problems)
    )


def test_the_null_decompiler_does_not_beat_us_in_any_lane(committed) -> None:
    """The floor, published and enforced.

    `what-ged-measures.md` measured a "decompiler" emitting
    `int f(void) { return 0; }` scoring 27.24% GED-perfect on the published
    DecBench corpus, above six real columns. The same trap is live here: 12.8%
    of this corpus's scored cells have a source skeleton of exactly
    `(seq return)`, so a null decompiler is exactly structurally right on all of
    them. A lane whose skill score goes negative is a lane the null beats, and
    no aggregate mean would say so.

    The per-band picture is deliberately NOT asserted: at `2-3` the null is
    already ahead of three of the four lanes, which is the census's own reported
    finding and is ratcheted per cell rather than hidden behind a threshold here.
    """
    beaten = {
        lane: (
            C.rate(bucket["exact"], bucket["scored"]),
            C.rate(bucket["null_exact"], bucket["scored"]),
        )
        for lane, bucket in sorted(committed["lane_summary"].items())
        if C.skill(bucket) <= 0.0
    }
    assert not beaten, (
        "THE NULL DECOMPILER IS AT OR ABOVE US, corpus-wide, in: "
        + ", ".join(
            f"{lane} ({ours:.2f}% exact vs null {null:.2f}%)"
            for lane, (ours, null) in beaten.items()
        )
    )


def test_the_population_the_census_cannot_measure_is_named(committed) -> None:
    """A denominator with an unstated exclusion is not a denominator.

    The projection front end parses C, so the corpus's C++, Rust, Go and
    assembly fixtures have no source skeleton to compare against. They are
    listed rather than dropped, and every listed fixture must really lack a C
    source -- otherwise the census quietly shrank into an easier one.
    """
    excluded = committed["excluded_fixtures"]
    assert excluded == sorted(excluded)
    for entry in excluded:
        fixture = entry.split(":")[0]
        assert C.c_source(fixture) is None, f"{fixture} has a C source but was excluded"
    censused = {key.split(":")[0] for key in committed["cells"]}
    assert not censused & {entry.split(":")[0] for entry in excluded}


# --- the census, re-run -----------------------------------------------------


@pytest.mark.slow
def test_every_declared_lane_was_actually_censused(measured) -> None:
    """A lane that failed to build contributes no cells.

    Which reads exactly like a lane with nothing wrong. Fail on the omission
    rather than on its consequence.
    """
    assert measured["problems"] == [], (
        "lanes the census could not measure:\n  " + "\n  ".join(measured["problems"])
    )


@pytest.mark.slow
def test_the_census_covers_the_whole_recorded_matrix(measured, committed) -> None:
    """Every recorded cell must still be present, or the gate shrank."""
    missing = sorted(set(committed["cells"]) - set(measured["cells"]))
    assert not missing, (
        f"{len(missing)} recorded cell(s) absent from this census: {missing[:10]}"
    )


@pytest.mark.slow
def test_the_toolchain_matches_the_one_the_census_was_recorded_against(
    measured, committed
) -> None:
    """Decompiler output follows the compiled binary.

    Compared across compiler releases this baseline is not a gate, it is a
    snapshot of one machine -- the same reason the def-use and execution lanes
    pin the fingerprint.
    """
    assert measured[C.TOOLCHAIN_KEY] == committed[C.TOOLCHAIN_KEY], (
        "compile toolchain differs from the one the census was recorded "
        f"against; recorded={committed[C.TOOLCHAIN_KEY]} "
        f"current={measured[C.TOOLCHAIN_KEY]}"
    )


@pytest.mark.slow
def test_no_function_became_structurally_worse(measured, committed) -> None:
    """The ratchet. More edits from the source than last time is a regression.

    So is a cell that stopped being scored: a function that used to be measured
    and is now `not_emitted`, `unparsed` or `abstained` has lost its number, and
    a lost number is not a neutral event.
    """
    moved = C.movements(measured, committed)
    assert not moved["regressions"], (
        "STRUCTURAL REGRESSIONS -- the recovered C is a worse match for the "
        "shape of its source than it was:\n  " + "\n  ".join(moved["regressions"])
    )


@pytest.mark.slow
def test_the_recovered_construct_mix_is_the_one_that_was_recorded(
    measured, committed
) -> None:
    """Which construct moved, named -- the per-cell ratchet says only that one did.

    `kind_totals` counts every skeleton node kind on both sides of the scored
    cells. It is the readable half of a failure: "goto 612 -> 640" says a
    structuring change leaked gotos, where forty cell lines say only that forty
    functions moved. Counts, not booleans, for the same reason the structural
    lane's readability census is counts.
    """
    problems = []
    for lane, sides in sorted(committed["kind_totals"].items()):
        current = measured["kind_totals"].get(lane)
        if current is None:
            problems.append(f"{lane}: MISSING from the census")
            continue
        for side, recorded in sorted(sides.items()):
            now = current[side]
            for kind in sorted(set(recorded) | set(now)):
                if recorded.get(kind, 0) != now.get(kind, 0):
                    problems.append(
                        f"{lane} {side} {kind}: {recorded.get(kind, 0)} -> "
                        f"{now.get(kind, 0)}"
                    )
    assert not problems, (
        "THE RECOVERED CONSTRUCT MIX MOVED -- refresh structure_baseline.json "
        "with `uv run python tools/fixture_structure_census.py --write` once "
        "the movement is understood:\n  " + "\n  ".join(problems)
    )


@pytest.mark.slow
def test_improvements_require_a_baseline_refresh(measured, committed) -> None:
    """The other half of the ratchet.

    A cell that got structurally closer to its source must be recorded as such,
    or the gate would let it slide back unnoticed.
    """
    moved = C.movements(measured, committed)
    assert not moved["improvements"], (
        "STRUCTURAL IMPROVEMENTS -- refresh structure_baseline.json with "
        "`uv run python tools/fixture_structure_census.py --write` to "
        "ratchet:\n  " + "\n  ".join(moved["improvements"])
    )
