#!/usr/bin/env python3
"""Control-skeleton census: how far our recovered C is from the source it came from.

WHAT THIS MEASURES
------------------
For every REQUIRED function of every C fixture, in every declared compile lane,
this compares two control skeletons -- the projection
`src/metrics/tree_distance.rs` defines -- and records the Zhang--Shasha tree edit
distance between them:

* the **source** skeleton, projected from the checked-in
  `tests/decompiler_fixtures/src/*.c`, and
* the **decompiled** skeleton, projected from the `decbench`-style render of the
  same function out of the compiled object.

A skeleton keeps every control construct by kind (`if`/`then`/`else`, `while`,
`do_while`, `switch`, `case`, `break`, `continue`, `goto`, a label, `return`), a
statement count and a three-way statement kind, and drops every expression
interior. So the number here is a *structuring* number: it moves when a `while`
becomes a `do`-`while`, when an `if`/`else` becomes two `goto`s, when an arm is
duplicated -- and it does not move when a variable is renamed, a constant is
bumped or a comparison is flipped.

WHY THIS GATE AND NOT ANOTHER
-----------------------------
`docs/development/traps.md` records that the execution differential is blind to
structure: goto soup passes every fixture. The structural lane counts `switch`,
`goto` and `break` tokens per function (`tests/decompiler_fixtures/structural.py`,
`readability`), which is an *absolute* count with no reference to what the source
did, and cannot see a loop that changed kind or an arm that was duplicated.
Neither lane can answer "is the recovered control structure the same shape as the
one the compiler was given".

Measured at `f15d179e`, `03_loop_shapes:gcc:O0` makes the case on its own. The
execution differential passes all six functions and the readability census
records no `goto` for four of them, while this census scores:

    for_sum              1.00   (seq assign assign (while assign expr) return)
    nested_pairs         0.90   one trailing statement kind differs
    loop_continue        0.60   `continue` recovered as an if/else
    while_reload_header  0.20   the loop test became a `break` inside the body
    dowhile_atleastonce  0.00   a `do`-`while` became a `while` with two breaks
    loop_break           0.00   goto soup: 12 edits against a 10-node source

`dowhile_atleastonce` and `loop_break` are structurally wrong at `-O0` and every
existing gate is green on them.

The two sibling metrics were considered. `byte_match` over the recompiled
fixtures would measure our recompilation's register allocation and instruction
selection at least as much as the decompiler -- the semantic half of that
question is already answered, exactly, by the execution differential. And
`type_match` needs per-function DWARF ground truth beside our recovered stack
variables, which is a data-plumbing project rather than a gate, and its
null-baseline weakness is already recorded (`76aab1cb`). The structural hole is
the one nothing covers.

ABSTENTION
----------
`tree_edit_distance` returns `None` above `MAX_SKELETON_NODES` (2048). That is a
recorded `abstained` status carrying no distance -- never a zero. A cell also
records `not_emitted` (the decompiler produced no such function) and `unparsed`
(it produced one whose render did not project) separately, because a coverage
gap and a bad score are different failures and collapsing either into `0.0` is
how a shared denominator rots (`docs/design/metrics-research/`).

THE NULL BASELINE
-----------------
Every cell carries `null_distance`: the distance from the source skeleton to
`NULL_DECOMPILER_C`'s, the two-node `(seq return)` that a "decompiler" emitting
`int f(void) { return 0; }` produces. `what-ged-measures.md` measured that such a
decompiler scores 27.24% GED-perfect on the published DecBench corpus, above six
real columns; a gate that reported one undifferentiated mean without saying where
the floor is would be repeating that. The report prints Glaurung's rate, the null
rate and the skill score `(ours - null) / (1 - null)` per size band.

STRATIFICATION
--------------
Bands are `tools/metric_stratify.py`'s, unchanged, so the two censuses' bands read
against each other. They are applied here to SOURCE SKELETON node count rather
than source CFG node count, which is a different scale: the null decompiler's
output is one CFG node but two skeleton nodes, so the band it saturates here is
`2-3`, not `1`.

POPULATION, AND WHAT IS NOT COVERED
-----------------------------------
C fixtures only (196 of the corpus's 213 declared fixtures). The projection front
end parses C; the 10 C++, 7 Rust and 5 Go fixtures have no source skeleton to
compare against and are listed in `excluded_fixtures` rather than dropped
silently. Lanes are `fixture_harness.REQUIRED_MATRIX` -- gcc/clang x O0/O2 --
host x86-64 only; no cross-architecture lane is measured here.

At `-O2` the source skeleton is **not** the decompiler's target: the compiler
unrolled, inlined and rotated the loops before the decompiler ever saw them, so a
low score there is a joint statement about the compiler and the decompiler. Those
lanes are censused and ratcheted anyway -- a movement is still a movement, and
`-O2` is where goto soup happens -- but the level is reported separately and the
absolute `-O2` numbers must not be read as decompiler quality.

Refresh::

    uv run python tools/fixture_structure_census.py --write
    uv run python tools/fixture_structure_census.py --report
    uv run python tools/fixture_structure_census.py --report --json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))

import build_guard as BG  # ty: ignore[unresolved-import]
import fixture_harness as H  # ty: ignore[unresolved-import]
import fixture_toolchain as TC  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]
import metric_stratify as MS  # ty: ignore[unresolved-import]

from glaurung._native import metrics

#: The checked-in fixture sources. Not the gitignored `build/` tree.
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"

#: The committed census.
BASELINE = ROOT / "tests" / "decompiler_fixtures" / "structure_baseline.json"

#: Reserved key holding the compile toolchain identity, as in the sibling maps.
TOOLCHAIN_KEY = H.TOOLCHAIN_KEY

#: The output of the null decompiler `what-ged-measures.md` section 2 defines:
#: a constant-returning body, which is the single most common recovered shape a
#: metric can be saturated by. Its skeleton is `(seq return)`, two nodes.
NULL_DECOMPILER_C = "int glaurung_null_decompiler(void) { return 0; }"

#: Every status a cell may carry. `scored` is the only one with a `distance`.
STATUSES = ("scored", "abstained", "not_emitted", "unparsed", "no_source_function")

#: Size bands, in report order. `metric_stratify.BAND_ORDER` with a `0` band in
#: front of it: that tool buckets source CFG node counts, whose minimum is 1,
#: and a skeleton can legitimately have zero nodes (a function with no body) or
#: none at all (`no_source_function`). `metric_stratify.band_for` maps both onto
#: its open-ended `>60` tail, which would file the smallest cells in the corpus
#: under the largest band, so those get their own bucket here.
BAND_ORDER: tuple[str, ...] = ("0",) + MS.BAND_ORDER


def band_for(source_nodes: int) -> str:
    """Bucket a source skeleton's node count into one of `BAND_ORDER`'s bands.

    Args:
        source_nodes: Nodes in the source skeleton; 0 when there is none.

    Returns:
        The band label.
    """
    return "0" if source_nodes < 1 else MS.band_for(source_nodes)


#: The decbench render's per-function provenance header. The same format is
#: parsed in `tests/decompiler_fixtures/structural.py` and `defuse.py`; this
#: census does not reuse either because both switch `GLAURUNG_VERIFY_DEFS=1` on,
#: and the artifact this metric must score is the default render, not the
#: instrumented one.
_HDR = re.compile(r"(?m)^// glaurung: (\S+) @ 0x[0-9a-fA-F]+\s*$")

_NULL_SKELETON: Any = None


def null_skeleton() -> Any:
    """The null decompiler's control skeleton, projected once per process.

    Returns:
        The two-node `(seq return)` skeleton of `NULL_DECOMPILER_C`.
    """
    global _NULL_SKELETON
    if _NULL_SKELETON is None:
        _NULL_SKELETON = metrics.skeletons(NULL_DECOMPILER_C)[
            "glaurung_null_decompiler"
        ]
    return _NULL_SKELETON


def c_source(stem: str) -> Path | None:
    """The fixture's C source, or None when it is written in another language.

    Args:
        stem: The fixture name, as keyed in `manifest.REQUIRED_FUNCTIONS`.

    Returns:
        The `.c` path, or None for the C++, Rust, Go and assembly fixtures the
        skeleton projection has no front end for.
    """
    candidate = SRC / f"{stem}.c"
    return candidate if candidate.is_file() else None


def excluded_fixtures() -> list[str]:
    """Declared fixtures this census cannot measure, and why, sorted.

    Returns:
        `"<fixture>:<suffix>"` for every declared fixture with no C source.
    """
    out = []
    for stem in sorted(M.REQUIRED_FUNCTIONS):
        if c_source(stem) is not None:
            continue
        found = sorted(p.suffix for p in SRC.glob(f"{stem}.*") if p.stem == stem)
        out.append(f"{stem}:{','.join(found) if found else 'no-source'}")
    return out


def decompile_functions(so: Path, timeout: int = 600) -> dict[str, str]:
    """Decompile every function of one object at the `decbench` style.

    Args:
        so: The compiled fixture.
        timeout: Seconds to allow the CLI.

    Returns:
        `{function name: the rendered block, header comment included}`.

    Raises:
        RuntimeError: The CLI exited nonzero. The census fails the lane closed
            rather than recording a lane with no functions, which would read
            exactly like a lane whose functions were all perfect.
    """
    run = subprocess.run(
        [
            BG.glaurung_bin(),
            "decompile",
            str(so),
            "--all",
            "--limit",
            "1000",
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if run.returncode != 0:
        raise RuntimeError(f"glaurung decompile: {run.stderr.strip()[-200:]}")
    text = run.stdout
    found = list(_HDR.finditer(text))
    return {
        match.group(1): text[
            match.start() : (
                found[index + 1].start() if index + 1 < len(found) else len(text)
            )
        ]
        for index, match in enumerate(found)
    }


def cell_for(
    source_skeleton: Any,
    block: str | None,
    function: str,
    kinds: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """Score one function of one lane.

    Args:
        source_skeleton: The source projection, or None when the source parse
            produced no definition of this name.
        block: The rendered decompilation, or None when nothing was emitted.
        function: The function's name, used to pick it out of the block.
        kinds: When given, `{"source": {...}, "decompiled": {...}}` node-kind
            tallies to fold this cell into. Only `scored` cells contribute, so
            the tallies share the distance totals' denominator exactly.

    Returns:
        A cell carrying a `status` from `STATUSES`, integer node counts where
        they exist, and a `distance` only when the status is `scored`.
    """
    if source_skeleton is None:
        return {"status": "no_source_function"}
    cell: dict[str, Any] = {
        "source_nodes": len(source_skeleton),
        "null_distance": metrics.tree_edit_distance(source_skeleton, null_skeleton()),
    }
    truncated = ["source"] if source_skeleton.truncated else []
    if block is None:
        cell["status"] = "not_emitted"
    else:
        decompiled = metrics.skeletons(block).get(function)
        if decompiled is None:
            cell["status"] = "unparsed"
        else:
            if decompiled.truncated:
                truncated.append("decompiled")
            cell["decompiled_nodes"] = len(decompiled)
            distance = metrics.tree_edit_distance(source_skeleton, decompiled)
            if distance is None:
                # Above MAX_SKELETON_NODES. An abstention, carrying no distance:
                # a zero here would be a made-up score for a function nobody
                # measured.
                cell["status"] = "abstained"
            else:
                cell["status"] = "scored"
                cell["distance"] = distance
                if kinds is not None:
                    for side, skeleton in (
                        ("source", source_skeleton),
                        ("decompiled", decompiled),
                    ):
                        for kind, count in skeleton.census().items():
                            kinds[side][kind] = kinds[side].get(kind, 0) + count
    if truncated:
        cell["truncated"] = truncated
    return cell


def _lane(
    job: tuple[str, str, str],
) -> tuple[str, dict[str, dict[str, Any]] | None, str, dict[str, dict[str, int]]]:
    """Census one `(fixture, compiler, optimisation)` lane in a worker process."""
    fixture, cc, opt = job
    key = f"{fixture}:{cc}:{opt}"
    src = c_source(fixture)
    if src is None:
        return key, None, "no-c-source", {"source": {}, "decompiled": {}}
    so, error = H.compile_fixture(src, cc, opt)
    if so is None:
        return key, None, f"compile-failed: {error}", {"source": {}, "decompiled": {}}
    try:
        blocks = decompile_functions(so)
    except subprocess.TimeoutExpired:
        return key, None, "decompile-timeout", {"source": {}, "decompiled": {}}
    except RuntimeError as failure:
        return (
            key,
            None,
            f"decompile-failed: {failure}",
            {"source": {}, "decompiled": {}},
        )
    source_skeletons = metrics.skeletons(src.read_text(encoding="utf-8"))
    kinds: dict[str, dict[str, int]] = {"source": {}, "decompiled": {}}
    cells = {
        name: cell_for(source_skeletons.get(name), blocks.get(name), name, kinds)
        for name in sorted(M.REQUIRED_FUNCTIONS.get(fixture, ()))
    }
    return key, cells, "", kinds


def jobs() -> list[tuple[str, str, str]]:
    """Every `(fixture, compiler, optimisation)` lane this census declares."""
    out: list[tuple[str, str, str]] = []
    for fixture in sorted(M.REQUIRED_FUNCTIONS):
        src = c_source(fixture)
        if src is None:
            continue
        out.extend((fixture, cc, opt) for cc, opt in H.matrix_for(src))
    return out


def empty_summary() -> dict[str, int]:
    """A zeroed rollup bucket, shared by the lane and band summaries."""
    bucket = {status: 0 for status in STATUSES}
    bucket.update(
        cells=0,
        exact=0,
        distance_total=0,
        source_nodes_total=0,
        decompiled_nodes_total=0,
        null_exact=0,
        null_distance_total=0,
    )
    return bucket


def accumulate(bucket: dict[str, int], cell: dict[str, Any]) -> None:
    """Fold one cell into a rollup bucket.

    Only `scored` cells contribute to the distance and node totals, and the null
    totals are accumulated over exactly that same set, so the two columns of the
    report always share a denominator.
    """
    bucket["cells"] += 1
    bucket[cell["status"]] += 1
    if cell["status"] != "scored":
        return
    bucket["distance_total"] += cell["distance"]
    bucket["source_nodes_total"] += cell["source_nodes"]
    bucket["decompiled_nodes_total"] += cell["decompiled_nodes"]
    bucket["exact"] += 1 if cell["distance"] == 0 else 0
    null = cell["null_distance"]
    if null is not None:
        bucket["null_distance_total"] += null
        bucket["null_exact"] += 1 if null == 0 else 0


def structure_report(max_workers: int | None = None) -> dict[str, Any]:
    """Census every declared C lane and return the committed-baseline shape.

    Args:
        max_workers: Lanes to run concurrently; `fixture_harness.default_jobs()`
            when None.

    Returns:
        The census. `problems` is part of it rather than an exception: a lane
        that failed to build contributes no cells, which reads exactly like a
        lane with nothing wrong, so the gate has to be able to see the omission.
    """
    if max_workers is None:
        max_workers = H.default_jobs()
    cells: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    kind_totals: dict[str, dict[str, dict[str, int]]] = {}
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        for key, per_function, error, kinds in pool.map(_lane, jobs()):
            if per_function is None:
                problems.append(f"{key}: {error}")
                continue
            for name, cell in per_function.items():
                cells[f"{key}:{name}"] = cell
            lane = ":".join(key.split(":")[1:])
            totals = kind_totals.setdefault(lane, {"source": {}, "decompiled": {}})
            for side, counted in kinds.items():
                for kind, count in counted.items():
                    totals[side][kind] = totals[side].get(kind, 0) + count

    lane_summary: dict[str, dict[str, int]] = {}
    band_summary: dict[str, dict[str, dict[str, int]]] = {}
    for key in sorted(cells):
        _fixture, cc, opt, _name = key.split(":")
        cell = cells[key]
        lane = f"{cc}:{opt}"
        accumulate(lane_summary.setdefault(lane, empty_summary()), cell)
        band = band_for(cell.get("source_nodes", 0))
        per_band = band_summary.setdefault(lane, {})
        accumulate(per_band.setdefault(band, empty_summary()), cell)

    return {
        TOOLCHAIN_KEY: TC.fingerprint(),
        "skeleton_version": metrics.SKELETON_VERSION,
        "max_skeleton_nodes": metrics.MAX_SKELETON_NODES,
        "null_decompiler_c": NULL_DECOMPILER_C,
        "excluded_fixtures": excluded_fixtures(),
        "cells": {key: cells[key] for key in sorted(cells)},
        "lane_summary": {lane: lane_summary[lane] for lane in sorted(lane_summary)},
        "kind_totals": {
            lane: {
                side: {kind: counted[kind] for kind in sorted(counted)}
                for side, counted in sorted(sides.items())
            }
            for lane, sides in sorted(kind_totals.items())
        },
        "band_summary": {
            lane: {band: bands[band] for band in sorted(bands)}
            for lane, bands in sorted(band_summary.items())
        },
        "problems": sorted(problems),
    }


# --- reading a census -------------------------------------------------------


def rate(numerator: int, denominator: int) -> float:
    """`numerator / denominator` as a percentage, or 0.0 on an empty set."""
    return 100.0 * numerator / denominator if denominator else 0.0


def mean_score(bucket: dict[str, int]) -> float:
    """Pooled skeleton score `1 - sum(distance) / sum(source nodes)`.

    Pooled rather than a mean of per-cell scores, and *unclamped*: the per-cell
    score saturates at 0.0 (`skeleton_score` clamps, and goto-ified output goes
    straight through the floor), so a mean of clamped scores hides how much
    worse than "completely wrong" a lane is. A negative number here is a real
    reading and is printed as one.

    Args:
        bucket: A lane or band rollup.

    Returns:
        The pooled score over the scored cells of that bucket.
    """
    total = bucket["source_nodes_total"]
    return 1.0 - bucket["distance_total"] / total if total else 0.0


def skill(bucket: dict[str, int]) -> float:
    """`(ours - null) / (1 - null)` on exact-match rates, as `metric_stratify`.

    The fraction of the distance between the null decompiler's floor and a
    perfect score that this bucket actually closed: 0 for output
    indistinguishable from `int f(void) { return 0; }`, negative for output the
    null beats, 1 only for exact structural recovery everywhere.

    Args:
        bucket: A lane or band rollup.

    Returns:
        The skill score, or 0.0 when the bucket has no scored cells or the null
        is already perfect on all of them.
    """
    scored = bucket["scored"]
    ours = rate(bucket["exact"], scored)
    null = rate(bucket["null_exact"], scored)
    return (ours - null) / (100.0 - null) if scored and null < 100.0 else 0.0


def render_report(report: dict[str, Any]) -> str:
    """A deterministic text report: per lane, then per lane and size band.

    Args:
        report: A census, freshly measured or read from the baseline.

    Returns:
        The report, ready to print. Every row is derived from `cells`, so the
        text and the committed integers cannot disagree.
    """
    lines = [
        f"control-skeleton census - skeleton v{report['skeleton_version']}, "
        f"cap {report['max_skeleton_nodes']} nodes",
        f"toolchain: {json.dumps(report[TOOLCHAIN_KEY], sort_keys=True)}",
        f"excluded (no C source): {len(report['excluded_fixtures'])} fixtures",
        "",
        f"{'lane':<12}{'cells':>7}{'scored':>8}{'exact%':>9}{'null%':>8}"
        f"{'skill':>8}{'pooled':>9}{'abst':>6}{'n/emit':>8}{'unpars':>8}",
    ]
    for lane, bucket in sorted(report["lane_summary"].items()):
        lines.append(
            f"{lane:<12}{bucket['cells']:>7}{bucket['scored']:>8}"
            f"{rate(bucket['exact'], bucket['scored']):>9.2f}"
            f"{rate(bucket['null_exact'], bucket['scored']):>8.2f}"
            f"{skill(bucket):>8.3f}{mean_score(bucket):>9.3f}"
            f"{bucket['abstained']:>6}{bucket['not_emitted']:>8}"
            f"{bucket['unparsed']:>8}"
        )
    lines.append("")
    lines.append("by source-skeleton size band (bands: tools/metric_stratify.py)")
    lines.append(
        f"{'lane':<12}{'band':>8}{'scored':>8}{'exact%':>9}{'null%':>8}"
        f"{'skill':>8}{'pooled':>9}"
    )
    for lane, bands in sorted(report["band_summary"].items()):
        for band in BAND_ORDER:
            bucket = bands.get(band)
            if bucket is None or bucket["cells"] == 0:
                continue
            lines.append(
                f"{lane:<12}{band:>8}{bucket['scored']:>8}"
                f"{rate(bucket['exact'], bucket['scored']):>9.2f}"
                f"{rate(bucket['null_exact'], bucket['scored']):>8.2f}"
                f"{skill(bucket):>8.3f}{mean_score(bucket):>9.3f}"
            )
    lines.append("")
    lines.append(
        "construct recovery over the scored cells - source count vs recovered count"
    )
    lines.append(f"{'lane':<12}{'kind':>10}{'source':>9}{'decomp':>9}{'delta':>9}")
    for lane, sides in sorted(report["kind_totals"].items()):
        source, decompiled = sides["source"], sides["decompiled"]
        for kind in sorted(
            set(source) | set(decompiled),
            key=lambda k: (-abs(decompiled.get(k, 0) - source.get(k, 0)), k),
        ):
            here, there = source.get(kind, 0), decompiled.get(kind, 0)
            if here == there:
                continue
            lines.append(f"{lane:<12}{kind:>10}{here:>9}{there:>9}{there - here:>+9}")
    if report["problems"]:
        lines.append("")
        lines.append(f"problems ({len(report['problems'])}):")
        lines.extend(f"  {problem}" for problem in report["problems"])
    return "\n".join(lines)


def movements(report: dict[str, Any], previous: dict[str, Any]) -> dict[str, list[str]]:
    """Compare a fresh census against a committed one, both directions.

    Args:
        report: The freshly measured census.
        previous: The committed baseline.

    Returns:
        `{"regressions": [...], "improvements": [...], "missing": [...]}`, each
        sorted. A cell whose distance ROSE, or which stopped being scored, is a
        regression; the reverse is an improvement, which the gate reports too so
        that a fix cannot silently slide back.
    """
    regressions: list[str] = []
    improvements: list[str] = []
    missing: list[str] = []
    for key, was in sorted(previous.get("cells", {}).items()):
        now = report["cells"].get(key)
        if now is None:
            missing.append(f"{key}: absent from this census")
            continue
        if was["status"] == "scored" and now["status"] == "scored":
            if now["distance"] > was["distance"]:
                regressions.append(
                    f"{key}: {was['distance']} -> {now['distance']} edits from "
                    f"source ({was['source_nodes']} source nodes)"
                )
            elif now["distance"] < was["distance"]:
                improvements.append(
                    f"{key}: {was['distance']} -> {now['distance']} edits from source"
                )
        elif was["status"] != now["status"]:
            moved = f"{key}: {was['status']} -> {now['status']}"
            if was["status"] == "scored":
                regressions.append(moved)
            else:
                improvements.append(moved)
    for key in sorted(set(report["cells"]) - set(previous.get("cells", {}))):
        improvements.append(f"{key}: new cell ({report['cells'][key]['status']})")
    return {
        "regressions": sorted(regressions),
        "improvements": sorted(improvements),
        "missing": sorted(missing),
    }


def load(path: Path) -> dict[str, Any] | None:
    """The committed baseline, or None when it does not exist yet.

    A baseline that exists but cannot be read is not the same thing as no
    baseline and must never be treated as one: that would hand the writer an
    empty comparison and let any regression through on a corrupted file.

    Args:
        path: The baseline to read.

    Returns:
        The parsed census, or None when the file is absent.

    Raises:
        OSError: The file exists but could not be read.
        json.JSONDecodeError: The file exists but is not JSON.
    """
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, report: dict[str, Any]) -> None:
    """Write a census as sorted, newline-terminated JSON.

    Args:
        path: Where to write.
        report: The census to commit.
    """
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    """Measure the corpus, print it, and optionally commit it.

    Args:
        argv: Command line, or None for `sys.argv[1:]`.

    Returns:
        A process exit code. 1 when a regression would be written without
        `--allow-regressions`, 2 when the census itself is incomplete.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="commit the census")
    parser.add_argument("--report", action="store_true", help="print the table")
    parser.add_argument("--json", action="store_true", help="print the census as JSON")
    parser.add_argument("--jobs", type=int, default=None, help="parallel lanes")
    parser.add_argument("--baseline", type=Path, default=BASELINE, help="baseline path")
    parser.add_argument(
        "--allow-regressions",
        action="store_true",
        help="write even though cells got structurally worse; say why in the commit",
    )
    args = parser.parse_args(argv)

    # Refuse to record a state that omits a declared fixture, for the same
    # reason the sibling writers do: a silently shortened census reads as clean.
    M.assert_fixtures_declared()
    report = structure_report(max_workers=args.jobs)
    if args.report or not (args.json or args.write):
        print(render_report(report))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    if report["problems"]:
        print("census is incomplete; refusing to act on it:", file=sys.stderr)
        for problem in report["problems"]:
            print(f"  {problem}", file=sys.stderr)
        return 2
    if not args.write:
        return 0

    previous = load(args.baseline)
    if previous is None:
        print(
            "NOTE: no existing baseline, so nothing was compared. If the file "
            "was deleted rather than never written, restore it from git and "
            "rerun.",
            file=sys.stderr,
        )
        write(args.baseline, report)
        return 0
    moved = movements(report, previous)
    for line in moved["improvements"]:
        print(f"IMPROVED {line}")
    for line in moved["missing"]:
        print(f"MISSING  {line}", file=sys.stderr)
    if moved["regressions"] and not args.allow_regressions:
        print(
            "REFUSING TO RECORD A STRUCTURAL REGRESSION. Each line below is "
            "recovered C that is a worse shape\nthan the source it came from "
            "than it used to be. Investigate first; pass --allow-regressions "
            "only\nwith a reason in the commit message.\n",
            file=sys.stderr,
        )
        for line in moved["regressions"]:
            print(f"  {line}", file=sys.stderr)
        return 1
    for line in moved["regressions"]:
        print(f"ACCEPTED REGRESSION {line}")
    write(args.baseline, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
