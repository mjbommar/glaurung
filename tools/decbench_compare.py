#!/usr/bin/env python3
"""Head-to-head DecBench metrics across decompilers, per lane and per program.

Produce the inputs with `tools/decbench_matrix.py --json --backend <name>`, then:

    tools/decbench_compare.py glaurung=g.json ghidra=gh.json angr=a.json

**Why more than one comparator.** angr was the only decompiler this project had
ever measured against, and it is the weakest credible one in the set. A number
that looks survivable against angr says nothing about whether the output is
usable, and choosing the comparator that flatters the result is a way of not
asking the question. Ghidra is the production reference an analyst would
actually open.

**What the metrics do and do not know.** GED is graph edit distance to the source
CFG (lower is better); `type_match` and `byte_match` are similarities (higher is
better). None of them knows whether the code is CORRECT — `structs:dist2` formerly
scored a perfect GED of 0.0 while its body read undefined locals. Read them
alongside the execution differential (`tools/dectest.py`, `tools/roundtrip_review.py`),
never instead of it.

A cell missing on one side only is reported, not skipped: a decompiler that
produces no result for a program silently improves its own mean by leaving
itself out, which has happened here before.
"""

from __future__ import annotations

import json
import statistics
import sys

METRICS = (("ged", False), ("type_match", True), ("byte_match", True))
TOOLCHAIN_KEY = "__toolchain__"


def load(spec: str) -> tuple[str, dict]:
    name, _, path = spec.partition("=")
    if not path:
        raise SystemExit(f"expected name=path, got {spec!r}")
    with open(path) as fh:
        data = json.load(fh)
    return name, {k: v for k, v in data.items() if k != TOOLCHAIN_KEY}


def fmt(v, better: bool, best: float | None) -> str:
    if v is None:
        return "    -"
    s = f"{v:6.3f}" if v < 100 else f"{v:6.1f}"
    return f"**{s.strip()}**" if best is not None and v == best else s


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise SystemExit(__doc__)
    backends = [load(a) for a in argv[1:]]
    names = [n for n, _ in backends]

    all_cells = sorted({c for _, d in backends for c in d})
    lanes = sorted({":".join(c.split(":")[1:]) for c in all_cells})

    # --- coverage first: a missing cell is a finding, not an absence ----------
    gaps = []
    for cell in all_cells:
        missing = [
            n for n, d in backends if cell not in d or "error" in d.get(cell, {})
        ]
        if missing and len(missing) < len(backends):
            gaps.append((cell, missing))
    if gaps:
        print(f"## Cells missing on some side only ({len(gaps)})\n")
        for cell, missing in gaps:
            print(f"* `{cell}` — no result from {', '.join(missing)}")
        print()

    def mean_of(d: dict, cells, metric: str) -> float | None:
        vals = [d[c][metric] for c in cells if c in d and d[c].get(metric) is not None]
        return statistics.mean(vals) if vals else None

    print("## Per lane\n")
    hdr = "| lane | metric | " + " | ".join(names) + " |"
    print(hdr)
    print("|" + "---|" * (len(names) + 2))
    for lane in lanes:
        cells = [c for c in all_cells if c.endswith(":" + lane)]
        for metric, higher in METRICS:
            vals = [mean_of(d, cells, metric) for _, d in backends]
            real = [v for v in vals if v is not None]
            best = (max(real) if higher else min(real)) if real else None
            row = " | ".join(fmt(v, higher, best) for v in vals)
            print(f"| {lane} | {metric} | {row} |")

    print("\n## Overall\n")
    print("| metric | " + " | ".join(names) + " |")
    print("|" + "---|" * (len(names) + 1))
    for metric, higher in METRICS:
        vals = [mean_of(d, all_cells, metric) for _, d in backends]
        real = [v for v in vals if v is not None]
        best = (max(real) if higher else min(real)) if real else None
        print(f"| {metric} | " + " | ".join(fmt(v, higher, best) for v in vals) + " |")

    # --- where we lose worst, which is the only actionable part --------------
    if len(backends) >= 2:
        mine, others = backends[0], backends[1:]
        print(f"\n## Worst GED gaps for {mine[0]} (per cell)\n")
        rows = []
        for cell in all_cells:
            a = mine[1].get(cell, {}).get("ged")
            if a is None:
                continue
            for name, d in others:
                b = d.get(cell, {}).get("ged")
                if b is not None and a > b:
                    rows.append((a - b, cell, name, a, b))
        rows.sort(reverse=True)
        if not rows:
            print(f"None — {mine[0]} is at least as good on every scored cell.")
        for delta, cell, name, a, b in rows[:15]:
            print(f"* `{cell}` — {mine[0]} {a} vs {name} {b}  (+{delta:.1f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
