#!/usr/bin/env python3
"""Stratify DecBench's published GED perfect-rate by source CFG size.

`docs/design/metrics-research/what-ged-measures.md` measures that the `ged`
column's scoreboard aggregation (`perfect_percentage`) is dominated by
functions with no branches: a "decompiler" that emits
`int f(void) { return 0; }` for every function scores 27.24% GED-perfect --
fifth of fifteen published columns, above Ghidra, Binary Ninja, r2dec,
Phoenix, dewolf and every LLM entry -- purely because a quarter of the corpus
has a one-node, zero-edge, entry-and-exit CFG, which is exactly what a
constant-return function parses to. That document's first recommendation
(section 7, item 1) is that this needs no new metric, only a stratified
report and a standing null-baseline number. This tool is that report.

Usage::

    uv run python tools/metric_stratify.py \\
        ~/.cache/glaurung/decbench-full/published_function_results.json \\
        --tree ~/.cache/glaurung/decbench-full/tree
    uv run python tools/metric_stratify.py <results.json> --tree <tree> --json

Both `<results.json>` and `--tree` default to the paths above, so a bare
invocation reproduces the design document's numbers.

Size bands
----------
Node-count bands are `1`, `2-3`, `4-7`, `8-15`, `16-31`, `32-60`, `>60` --
identical to `tools/source_cfg_census.py`'s `_bucket`, so this tool's
per-band totals can be cross-checked against that census's
`node_count_buckets`, and identical to the seven bands
`what-ged-measures.md` section 3 already reports pooled perfect-rates for,
so this tool's per-decompiler numbers can be checked against that document's
already-published pooled ones. The boundaries are not arbitrary: `1` is
load-bearing because it is the only band the null decompiler can ever score
in (its output is always exactly one node), and each doubling of node count
roughly halves the pooled perfect-rate in the published data (90.4% at 1,
35.8% at 2-3, 20.3% at 4-7, 8.7% at 8-15, 3.4% at 16-31, 1.1% at 32-60,
0.44% above 60), so the bands mark where the metric's behaviour actually
changes rather than slicing it at round numbers.

The null baseline
------------------
`NULL_SHAPE` below is the CFG that a `return <constant>;` function parses to
under this corpus's Joern/pyjoern convention -- one node, no edges, flagged
as both the function's entry and its exit block (confirmed for Glaurung's
own front end in `what-ged-measures.md` section 2.1). That shape is fixed;
what is NOT fixed, and is never hard-coded here, is what fraction of a given
corpus has exactly that shape -- this tool counts it from whatever
`--tree` it is pointed at, so pointing it at a different DecBench export (a
different config, a future dataset revision) recomputes the baseline rather
than reusing the figure this docstring quotes.

The above-the-null headline
----------------------------
Every decompiler in the report gets three numbers: `perfect%` (its perfect
count over the SAME denominator as the null baseline -- every function with
a non-degenerate published source CFG, not just the ones this decompiler was
scored on, so coverage gaps count against a column exactly as they do on
DecBench's own Union scoreboard), `excess pts` (`perfect% - null%`, how many
raw percentage points a column clears the floor by), and `skill` (the
headline this tool commits to).

`skill` is a forecast-verification-style skill score,
`(perfect% - null%) / (100% - null%)`: the fraction of the *distance between
the floor and a perfect score* that a column actually closed. It is 0 for a
column indistinguishable from `return 0;`, negative for a column that is
outscored by it, and 1 only for a column that is GED-perfect on the entire
corpus. `excess pts` is reported alongside it because it is the more
legible number for a single run, but it is not this tool's headline:
`excess pts` conflates two different things that `skill` keeps apart --
how far a column is from the floor, and how much floor-to-ceiling room there
was to begin with. A corpus with a lower null baseline (fewer trivial
functions) leaves more percentage points of headroom for the same amount of
genuine improvement, so raw excess is not comparable across differently
composed corpora (a smaller `--tree` slice, a future dataset revision with a
different trivial-function share) the way `skill` is. On any single run the
two rankings agree -- `skill` is `excess pts` divided by the same positive
constant, `100 - null%`, for every column -- so `skill` costs nothing here
and buys comparability everywhere else. A per-band mean of excess (weighting
every size band equally regardless of how many corpus functions land in it)
was also considered and rejected: it would answer a different question
(how a column does on an unweighted mix of complexity classes) from the one
the null baseline is built to answer (how much of this corpus's actual,
size-skewed difficulty a column resolved), and the per-band table already
printed below answers the complexity-class question directly, in full,
without collapsing it into one number.

Streaming
---------
`published_function_results.json` is ~301 MB. `iter_named_array` below
never calls `json.load`/`json.loads` on the whole document: it walks the
top-level object's keys with `json.JSONDecoder.raw_decode`, fully decoding
(and discarding) the small preamble keys, then decodes the `groups` array
one element at a time, so peak memory is bounded by one group's JSON text
(one binary's worth of functions) plus a read buffer, not by the file. The
`tree`'s per-binary `source_cfgs/*.json` files (337 MB total, 10 MB at the
largest) are read whole one at a time, matching `tools/source_cfg_census.py`
-- each is small enough on its own, and only five small fields per function
are kept, so nothing from `labels` (the multi-megabyte statement dump that
`vj_ged` never reads either) survives past the file that held it.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

#: Same node-count boundaries as `tools/source_cfg_census.py::_bucket` -- see
#: the "Size bands" section of the module docstring for why these and not a
#: finer or coarser split.
SIZE_BANDS: tuple[tuple[int, int], ...] = (
    (1, 1),
    (2, 3),
    (4, 7),
    (8, 15),
    (16, 31),
    (32, 60),
)

#: Band labels in report order, including the open-ended tail band.
BAND_ORDER: tuple[str, ...] = tuple(
    (str(lo) if lo == hi else f"{lo}-{hi}") for lo, hi in SIZE_BANDS
) + (">60",)


def band_for(node_count: int) -> str:
    """Bucket a source CFG's node count into one of `BAND_ORDER`'s bands."""
    for lo, hi in SIZE_BANDS:
        if lo <= node_count <= hi:
            return str(lo) if lo == hi else f"{lo}-{hi}"
    return ">60"


class NullShape(NamedTuple):
    """The CFG a trivial constant-return function parses to. See the "The
    null baseline" section of the module docstring."""

    nodes: int
    edges: int
    has_entry: bool
    has_exit: bool


#: See `NullShape` and the module docstring. Fixed by what Joern/pyjoern
#: emits for `int f(void) { return 0; }`; the *count* of corpus functions
#: matching it is always computed at runtime, never hard-coded.
NULL_SHAPE = NullShape(nodes=1, edges=0, has_entry=True, has_exit=True)


class SourceCfgShape(NamedTuple):
    """The four fields of a published source CFG that this tool needs.

    Deliberately excludes `labels` (the per-block statement dump) -- see the
    module docstring's "Streaming" section.
    """

    nodes: int
    edges: int
    has_entry: bool
    has_exit: bool
    degenerate: bool


FunctionKey = tuple[str, str, str, str]  # (opt_level, project, binary, function)


def load_source_shapes(tree: Path) -> dict[FunctionKey, SourceCfgShape]:
    """Index every published source CFG's shape by `(opt, project, binary, function)`.

    Reads `<tree>/<opt>/<project>/source_cfgs/<binary>.json` one file at a
    time (largest observed: ~10 MB), matching
    `tools/source_cfg_census.py::census`'s I/O pattern. Only the four small
    fields captured in `SourceCfgShape` are retained per function; each
    file's parsed `dict` (including its `labels`) is dropped once its
    functions are indexed.

    Args:
        tree: Root of a materialized DecBench tree
            (`~/.cache/glaurung/decbench-full/tree`).

    Returns:
        Mapping from `(opt_level, project, binary, function)` to that
        function's source CFG shape.
    """
    shapes: dict[FunctionKey, SourceCfgShape] = {}
    for path in sorted(tree.glob("*/*/source_cfgs/*.json")):
        data = json.loads(path.read_text())
        opt = data.get("opt") or path.parts[-4]
        project = data.get("project") or path.parts[-3]
        binary = data.get("binary") or path.stem
        for name, func in data["functions"].items():
            shapes[(opt, project, binary, name)] = SourceCfgShape(
                nodes=len(func["nodes"]),
                edges=len(func["edges"]),
                has_entry=bool(func["entry"]),
                has_exit=bool(func["exit"]),
                degenerate=bool(func.get("degenerate", False)),
            )
    return shapes


# --- Streaming JSON: read `published_function_results.json` without json.load ---

_WHITESPACE_AND_SEPARATORS = " \t\r\n,"

#: Top-level keys this tool refuses to fully-decode-and-discard while
#: searching for a smaller key (see `read_top_level_scalar`) -- they are the
#: corpus's large arrays, and decoding one whole just to skip past it would
#: defeat the point of streaming.
_UNSAFE_TO_SKIP = frozenset({"groups", "samples"})


def _read_more(handle: Any, buf: str, chunk_size: int) -> str:
    """Append the next chunk of `handle` to `buf`, raising on genuine EOF."""
    chunk = handle.read(chunk_size)
    if not chunk:
        raise ValueError("unexpected end of file while streaming JSON")
    return buf + chunk


def _skip_ws(buf: str, pos: int, handle: Any, chunk_size: int) -> tuple[str, int]:
    """Advance `pos` past whitespace and `,` separators, refilling `buf` as needed."""
    while True:
        while pos < len(buf) and buf[pos] in _WHITESPACE_AND_SEPARATORS:
            pos += 1
        if pos < len(buf):
            return buf, pos
        buf = _read_more(handle, buf, chunk_size)


def _decode(
    buf: str, pos: int, handle: Any, chunk_size: int, decoder: json.JSONDecoder
) -> tuple[Any, str, int]:
    """`decoder.raw_decode(buf, pos)`, refilling `buf` until the result is
    provably not truncated.

    A `raw_decode` that ends exactly at `len(buf)` might really continue
    past it -- true only for bare literals (numbers, `true`/`false`/`null`),
    since strings/objects/arrays cannot successfully decode without their
    closing delimiter already being present in `buf`. When that happens,
    read one more chunk and re-decode from the same `pos` before trusting
    the result.
    """
    while True:
        try:
            value, end = decoder.raw_decode(buf, pos)
        except json.JSONDecodeError:
            buf = _read_more(handle, buf, chunk_size)
            continue
        if end == len(buf):
            chunk = handle.read(chunk_size)
            if chunk:
                buf += chunk
                continue
        return value, buf, end


def read_top_level_scalar(path: Path, key: str, chunk_size: int = 1 << 20) -> Any:
    """Read one top-level value from a large JSON document by key, cheaply.

    Walks the document's top-level object key by key, in file order, fully
    decoding (and discarding) every value that is not `key`. Safe only for
    keys whose own value, and every other top-level value that precedes it,
    is small -- it refuses to skip past `"groups"` or `"samples"` (see
    `_UNSAFE_TO_SKIP`) while still searching, since skipping means decoding
    the value in full.

    Args:
        path: Path to the JSON document.
        key: Top-level key to read.
        chunk_size: Bytes to read per refill.

    Returns:
        The decoded value of `document[key]`.

    Raises:
        KeyError: `key` is not present before the document's large arrays.
        ValueError: The document is not a JSON object, or is malformed.
    """
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as handle:
        buf = handle.read(chunk_size)
        pos = 0
        buf, pos = _skip_ws(buf, pos, handle, chunk_size)
        if not buf or buf[pos] != "{":
            raise ValueError(f"{path}: expected a top-level JSON object")
        pos += 1
        while True:
            buf, pos = _skip_ws(buf, pos, handle, chunk_size)
            if buf[pos] == "}":
                raise KeyError(f"{path}: key {key!r} not found")
            name, buf, pos = _decode(buf, pos, handle, chunk_size, decoder)
            buf, pos = _skip_ws(buf, pos, handle, chunk_size)
            if buf[pos] != ":":
                raise ValueError(f"{path}: expected ':' after key {name!r}")
            pos += 1
            buf, pos = _skip_ws(buf, pos, handle, chunk_size)
            if name == key:
                value, buf, pos = _decode(buf, pos, handle, chunk_size, decoder)
                return value
            if name in _UNSAFE_TO_SKIP:
                raise KeyError(
                    f"{path}: key {key!r} not found before the large {name!r} array"
                )
            _value, buf, pos = _decode(buf, pos, handle, chunk_size, decoder)


def iter_named_array(
    path: Path, key: str, chunk_size: int = 1 << 20
) -> Iterator[dict[str, Any]]:
    """Yield each element of `document[key]`, a JSON array of objects.

    Reads `path` incrementally: locates the array the same way
    `read_top_level_scalar` locates a scalar (skipping small preceding
    top-level values), then decodes and yields the array's elements one at a
    time via `json.JSONDecoder.raw_decode`. `json.load` is never called on
    `path`, so peak memory is bounded by the largest single element plus a
    read buffer of at most `chunk_size` extra bytes, never by the file's
    full size.

    Args:
        path: Path to the JSON document.
        key: Top-level key whose value is a JSON array.
        chunk_size: Bytes to read per refill.

    Yields:
        Each decoded element of the array, in document order.

    Raises:
        KeyError: `key` was not found among the top-level keys.
        ValueError: `document[key]` exists but is not a JSON array, or the
            document is malformed.
    """
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as handle:
        buf = handle.read(chunk_size)
        pos = 0
        buf, pos = _skip_ws(buf, pos, handle, chunk_size)
        if not buf or buf[pos] != "{":
            raise ValueError(f"{path}: expected a top-level JSON object")
        pos += 1
        while True:
            buf, pos = _skip_ws(buf, pos, handle, chunk_size)
            if buf[pos] == "}":
                raise KeyError(f"{path}: key {key!r} not found")
            name, buf, pos = _decode(buf, pos, handle, chunk_size, decoder)
            buf, pos = _skip_ws(buf, pos, handle, chunk_size)
            if buf[pos] != ":":
                raise ValueError(f"{path}: expected ':' after key {name!r}")
            pos += 1
            buf, pos = _skip_ws(buf, pos, handle, chunk_size)
            if name == key:
                break
            _value, buf, pos = _decode(buf, pos, handle, chunk_size, decoder)
        if buf[pos] != "[":
            raise ValueError(f"{path}: key {key!r} is not a JSON array")
        pos += 1
        while True:
            buf, pos = _skip_ws(buf, pos, handle, chunk_size)
            if buf[pos] == "]":
                return
            element, buf, pos = _decode(buf, pos, handle, chunk_size, decoder)
            yield element
            if pos > chunk_size:
                buf = buf[pos:]
                pos = 0


# --- Aggregation ---


def _matches_null(shape: SourceCfgShape) -> bool:
    return (
        shape.nodes == NULL_SHAPE.nodes
        and shape.edges == NULL_SHAPE.edges
        and shape.has_entry == NULL_SHAPE.has_entry
        and shape.has_exit == NULL_SHAPE.has_exit
    )


def stratify(
    results_path: Path,
    tree: Path,
    metric: str = "ged",
    chunk_size: int = 1 << 20,
) -> dict[str, Any]:
    """Build the stratified, null-baselined report.

    Args:
        results_path: Path to `published_function_results.json`.
        tree: Root of the matching materialized DecBench tree.
        metric: Which per-function metric key to score (`"ged"` by default;
            see `document["metrics"]` for the alternatives DecBench publishes).
        chunk_size: Streaming read chunk size, in bytes.

    Returns:
        A JSON-serializable report dict. See `main`/`_print_report` for the
        fields, or run with `--json` to inspect the shape directly.
    """
    shapes = load_source_shapes(tree)

    perfect_values = read_top_level_scalar(
        results_path, "perfect_values", chunk_size=chunk_size
    )
    if metric not in perfect_values:
        raise KeyError(
            f"{results_path}: perfect_values has no {metric!r} entry "
            f"(has: {sorted(perfect_values)})"
        )
    perfect_value = float(perfect_values[metric])

    band_totals: dict[str, int] = dict.fromkeys(BAND_ORDER, 0)
    null_perfect_by_band: dict[str, int] = dict.fromkeys(BAND_ORDER, 0)
    perfect_by_band: dict[str, dict[str, int]] = {b: {} for b in BAND_ORDER}
    scored_by_band: dict[str, dict[str, int]] = {b: {} for b in BAND_ORDER}
    all_decompilers: set[str] = set()

    n_groups = 0
    n_functions_seen = 0
    n_no_source = 0
    n_degenerate = 0

    for group in iter_named_array(results_path, "groups", chunk_size=chunk_size):
        n_groups += 1
        opt = group["opt_level"]
        project = group["project"]
        binary = group["binary"]
        for fn in group["functions"]:
            n_functions_seen += 1
            key: FunctionKey = (opt, project, binary, fn["function"])
            shape = shapes.get(key)
            if shape is None:
                n_no_source += 1
                continue
            if shape.degenerate:
                n_degenerate += 1
                continue

            band = band_for(shape.nodes)
            band_totals[band] += 1
            if _matches_null(shape):
                null_perfect_by_band[band] += 1

            values = fn.get("values", {})
            all_decompilers.update(values)
            for dec, metrics in values.items():
                value = metrics.get(metric)
                if value is None:
                    continue
                scored_by_band[band][dec] = scored_by_band[band].get(dec, 0) + 1
                if float(value) == perfect_value:
                    perfect_by_band[band][dec] = perfect_by_band[band].get(dec, 0) + 1

    n_scored_population = sum(band_totals.values())
    null_perfect_total = sum(null_perfect_by_band.values())
    null_pct = (
        100.0 * null_perfect_total / n_scored_population if n_scored_population else 0.0
    )

    decompilers: dict[str, Any] = {}
    for dec in sorted(all_decompilers):
        perfect_total = sum(perfect_by_band[b].get(dec, 0) for b in BAND_ORDER)
        scored_total = sum(scored_by_band[b].get(dec, 0) for b in BAND_ORDER)
        perfect_pct_common = (
            100.0 * perfect_total / n_scored_population if n_scored_population else 0.0
        )
        perfect_pct_own = 100.0 * perfect_total / scored_total if scored_total else None
        coverage_pct = (
            100.0 * scored_total / n_scored_population if n_scored_population else 0.0
        )
        excess_pts = perfect_pct_common - null_pct
        headroom = 100.0 - null_pct
        skill_score = excess_pts / headroom if headroom > 0 else 0.0

        perfect_pct_common_by_band = {
            b: (
                100.0 * perfect_by_band[b].get(dec, 0) / band_totals[b]
                if band_totals[b]
                else 0.0
            )
            for b in BAND_ORDER
        }

        decompilers[dec] = {
            "scored_total": scored_total,
            "coverage_pct": coverage_pct,
            "perfect_total": perfect_total,
            "perfect_pct_common": perfect_pct_common,
            "perfect_pct_own": perfect_pct_own,
            "perfect_by_band": {b: perfect_by_band[b].get(dec, 0) for b in BAND_ORDER},
            "scored_by_band": {b: scored_by_band[b].get(dec, 0) for b in BAND_ORDER},
            "perfect_pct_common_by_band": perfect_pct_common_by_band,
            "excess_pts": excess_pts,
            "skill_score": skill_score,
        }

    ranking_raw = sorted(
        decompilers, key=lambda d: (-decompilers[d]["perfect_pct_common"], d)
    )
    ranking_skill = sorted(
        decompilers, key=lambda d: (-decompilers[d]["skill_score"], d)
    )
    # Own-denominator ranking: perfect / that column's own scored count, the
    # figure closest to what DecBench's published scoreboard reports per
    # column. Printed alongside the other two so the report can show plainly
    # how much a coverage-blind ranking (this one) can diverge from a
    # same-population one (`ranking_raw`/`ranking_skill`) -- a column with
    # very low coverage (e.g. an agentic entrant scored on a few hundred of
    # 89,014 functions) can rank near the top here and near the bottom there.
    ranking_own = sorted(
        decompilers,
        key=lambda d: (-(decompilers[d]["perfect_pct_own"] or -1.0), d),
    )

    return {
        "results_path": str(results_path),
        "tree": str(tree),
        "metric": metric,
        "perfect_value": perfect_value,
        "null_shape": {
            "nodes": NULL_SHAPE.nodes,
            "edges": NULL_SHAPE.edges,
            "entry": NULL_SHAPE.has_entry,
            "exit": NULL_SHAPE.has_exit,
        },
        "population": {
            "groups": n_groups,
            "functions_seen": n_functions_seen,
            "functions_without_source_cfg": n_no_source,
            "functions_degenerate": n_degenerate,
            "functions_scored_population": n_scored_population,
        },
        "size_bands": list(BAND_ORDER),
        "band_totals": band_totals,
        "null": {
            "perfect_by_band": null_perfect_by_band,
            "perfect_total": null_perfect_total,
            "perfect_pct": null_pct,
        },
        "decompilers": decompilers,
        "ranking_raw": ranking_raw,
        "ranking_skill": ranking_skill,
        "ranking_own": ranking_own,
    }


# --- CLI ---

_DEFAULT_RESULTS = (
    Path.home()
    / ".cache"
    / "glaurung"
    / "decbench-full"
    / "published_function_results.json"
)
_DEFAULT_TREE = Path.home() / ".cache" / "glaurung" / "decbench-full" / "tree"


def _print_report(report: dict[str, Any]) -> None:
    pop = report["population"]
    print(f"results                {report['results_path']}")
    print(f"tree                   {report['tree']}")
    print(
        f"metric                 {report['metric']} (perfect == {report['perfect_value']})"
    )
    ns = report["null_shape"]
    print(
        f"null shape             nodes={ns['nodes']} edges={ns['edges']} "
        f"entry={ns['entry']} exit={ns['exit']}"
    )
    print(f"groups                 {pop['groups']}")
    print(f"functions seen         {pop['functions_seen']}")
    print(f"  no published source  {pop['functions_without_source_cfg']}")
    print(f"  degenerate source    {pop['functions_degenerate']}")
    print(f"  scored population N  {pop['functions_scored_population']}")
    print()

    decs = sorted(report["decompilers"])
    n_total = pop["functions_scored_population"]

    def _dec_label(d: str) -> str:
        return d[:9]

    header = f"{'band':<8} {'N':>7} {'NULL%':>7}" + "".join(
        f" {_dec_label(d):>9}" for d in decs
    )
    print(header)
    for band in report["size_bands"]:
        n = report["band_totals"][band]
        null_pct = 100.0 * report["null"]["perfect_by_band"][band] / n if n else 0.0
        row = f"{band:<8} {n:>7} {null_pct:>6.1f}%"
        for d in decs:
            v = report["decompilers"][d]["perfect_pct_common_by_band"][band]
            row += f" {v:>8.1f}%"
        print(row)
    print("-" * len(header))
    row = f"{'overall':<8} {n_total:>7} {report['null']['perfect_pct']:>6.1f}%"
    for d in decs:
        row += f" {report['decompilers'][d]['perfect_pct_common']:>8.1f}%"
    print(row)
    print()

    print(
        f"{'decompiler':<14} {'scored':>7} {'coverage':>9} {'perfect':>8} "
        f"{'own%':>8} {'perfect%':>9} {'excess pts':>11} {'skill':>7}"
    )
    for d in report["ranking_skill"]:
        r = report["decompilers"][d]
        own = (
            f"{r['perfect_pct_own']:>7.2f}%"
            if r["perfect_pct_own"] is not None
            else f"{'n/a':>8}"
        )
        print(
            f"{d:<14} {r['scored_total']:>7} {r['coverage_pct']:>8.1f}% "
            f"{r['perfect_total']:>8} {own} {r['perfect_pct_common']:>8.2f}% "
            f"{r['excess_pts']:>+10.2f} {r['skill_score']:>+7.3f}"
        )
    print(
        "  ('own%' = perfect / that column's own scored count -- DecBench's "
        "published-scoreboard style; 'perfect%' = perfect / the same N every "
        "column and the null baseline share, i.e. coverage counts against you)"
    )
    print()
    print("ranked by own-denominator perfect% (DecBench scoreboard style):")
    print("  " + ", ".join(report["ranking_own"]))
    print("ranked by same-population perfect% (against null's denominator):")
    print("  " + ", ".join(report["ranking_raw"]))
    print("ranked by skill above null (same ranking as above; see docstring):")
    print("  " + ", ".join(report["ranking_skill"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Stratify DecBench's GED perfect-rate by source CFG size, and report "
            "every column against the return-0 null baseline."
        )
    )
    parser.add_argument(
        "results",
        type=Path,
        nargs="?",
        default=_DEFAULT_RESULTS,
        help=f"published_function_results.json to stream (default: {_DEFAULT_RESULTS})",
    )
    parser.add_argument(
        "--tree",
        type=Path,
        default=_DEFAULT_TREE,
        help=f"materialized DecBench tree holding source_cfgs/*.json (default: {_DEFAULT_TREE})",
    )
    parser.add_argument(
        "--metric",
        default="ged",
        help="per-function metric key to score (default: ged)",
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1 << 20,
        help="streaming read chunk size in bytes (default: 1 MiB)",
    )
    args = parser.parse_args(argv)

    if not args.results.is_file():
        print(f"no such file: {args.results}", file=sys.stderr)
        return 2
    if not args.tree.is_dir():
        print(f"no such tree: {args.tree}", file=sys.stderr)
        return 2

    report = stratify(
        args.results,
        args.tree,
        metric=args.metric,
        chunk_size=args.chunk_size,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
