#!/usr/bin/env python3
"""Score a full-corpus run against DecBench's published numbers.

WHY. Glaurung's published full-corpus row is `82 / 94,267 = 0.09%`, rank 11 of
13. That is not a measurement of the decompiler: the row scores a 250-function
SAMPLE-SET submission against the full corpus denominator, and the proof is that
the numerator is bit-identical in both views -- 82 perfect of 250 attempted on
the sample set, 82 perfect of 94,267 on the leaderboard. Every function we never
submitted counts as a miss.

(`total_functions_evaluated` is `0` for our row, but it is `0` for all thirteen
columns including angr at rank 3, so it is an unpopulated field and not
evidence of anything.)

This reads the `function_results.json` that `decbench evaluate-tree` writes over
a full-corpus tree and reports the same statistics the published scoreboard
reports, so the two are directly comparable.

DEFINITIONS, taken from the published file rather than assumed:
`perfect_values` gives the per-metric target (`ged` 0.0, `type_match` 1.0,
`byte_match` 1.0). "Union" is the fraction of functions perfect on at least one
metric -- the leaderboard headline.

    tools/decbench_compare_full.py <tree>/function_results.json \
        --published ~/.cache/glaurung/decbench-full/published_function_results.json \
        --column glaurung-<sha>
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def load(path: pathlib.Path) -> dict:
    with path.open() as handle:
        return json.load(handle)


def tally(results: dict, column: str, perfect: dict[str, float]) -> dict:
    """Per-metric perfect counts and the Union, over functions actually scored.

    `scored` counts functions where this column produced a value for the metric
    at all. Reporting a perfect count without it is what makes 82/94,267 look
    like a decompiler result instead of a coverage artifact.
    """
    out = {m: {"perfect": 0, "scored": 0} for m in perfect}
    union_perfect = 0
    union_scored = 0
    for group in results.get("groups", []):
        for function in group.get("functions", []):
            values = (function.get("values") or {}).get(column)
            if not values:
                continue
            any_metric = False
            any_perfect = False
            for metric, target in perfect.items():
                value = values.get(metric)
                if value is None:
                    continue
                any_metric = True
                out[metric]["scored"] += 1
                if abs(float(value) - float(target)) < 1e-9:
                    out[metric]["perfect"] += 1
                    any_perfect = True
            if any_metric:
                union_scored += 1
                union_perfect += 1 if any_perfect else 0
    out["_union"] = {"perfect": union_perfect, "scored": union_scored}
    return out


def pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:.2f}%" if d else "   -  "


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results", type=pathlib.Path, help="function_results.json from evaluate-tree"
    )
    parser.add_argument("--published", type=pathlib.Path, required=True)
    parser.add_argument("--column", required=True, help="our decompiler column name")
    parser.add_argument(
        "--leaderboard-denominator",
        type=int,
        default=0,
        help=(
            "fixed historical reference only; not a merged DecBench denominator "
            "(default: omit)"
        ),
    )
    args = parser.parse_args()

    published = load(args.published)
    perfect = published["perfect_values"]

    ours = load(args.results)
    mine = tally(ours, args.column, perfect)
    if not mine["_union"]["scored"]:
        print(
            f"column {args.column!r} scored nothing in {args.results}", file=sys.stderr
        )
        cols = sorted(
            {
                c
                for g in ours.get("groups", [])
                for f in g.get("functions", [])
                for c in (f.get("values") or {})
            }
        )
        print(f"columns present: {cols}", file=sys.stderr)
        return 2

    print(f"OUR RUN   column={args.column}   file={args.results}")
    print(f"{'metric':<14}{'perfect':>9}{'scored':>9}{'rate':>9}")
    for metric in list(perfect) + ["_union"]:
        entry = mine[metric]
        label = "UNION" if metric == "_union" else metric
        print(
            f"  {label:<12}{entry['perfect']:>9}{entry['scored']:>9}{pct(entry['perfect'], entry['scored']):>9}"
        )

    # A new column can make previously unmeasurable functions measurable, which
    # changes the shared denominator for EVERY column. A fixed denominator is
    # therefore only a historical reference, never a leaderboard recomputation.
    if args.leaderboard_denominator:
        d = args.leaderboard_denominator
        u = mine["_union"]["perfect"]
        print(
            f"\nFIXED-DENOMINATOR REFERENCE (NOT A MERGED LEADERBOARD) (perfect / {d:,})"
        )
        print(f"  glaurung {u:>9}{d:>10}{pct(u, d):>9}")

    print(
        "\nFor a comparable merged leaderboard, use tools/decbench_audit_full.py "
        "on the raw evaluated fragments."
    )

    print(
        f"\nPUBLISHED, same corpus ({published.get('decompiler_versions', {}).get('glaurung', '?')})"
    )
    print(f"{'decompiler':<14}{'perfect':>9}{'scored':>9}{'rate':>9}")
    for column in published["decompilers"]:
        entry = tally(published, column, perfect)["_union"]
        mark = "  <- glaurung as published" if column == "glaurung" else ""
        print(
            f"  {column:<12}{entry['perfect']:>9}{entry['scored']:>9}{pct(entry['perfect'], entry['scored']):>9}{mark}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
