#!/usr/bin/env python3
"""Render the scored results as markdown tables.

    report.py <outdir> [--filter substr] [--title "..."]

Best value per row is bolded, with the direction declared per metric — a table
where "higher is better" is left to the reader is a table that will be misread.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import TOOLS, agg, analyze

# (key, label, higher_is_better or None for "no direction — descriptive only")
ROWS = [
    ("success_rate", "decompile success rate (of GT functions)", True),
    ("recall_dwarf", "function-discovery recall vs DWARF", True),
    ("recall_fde", "function-discovery recall vs .eh_frame", True),
    ("argc_exact_rate", "prototype arg-count exactly right", True),
    ("proto_parse_rate", "emitted a parseable C prototype", True),
    ("mean_loc", "mean lines per function", None),
    ("mean_decls", "mean local declarations per function", None),
    ("mean_goto_per_100loc", "gotos per 100 lines", False),
    ("mean_leak_per_100loc", "machine leakage per 100 lines", False),
    ("mean_leak_register", "  ...raw registers per function", False),
    ("mean_leak_flag", "  ...condition flags per function", False),
    ("mean_leak_unrecovered", "  ...unrecovered/warning markers", False),
    ("mean_leak_undefined_type", "  ...undefined-width types", False),
    ("mean_named_calls", "resolved callee names per function", True),
    ("mean_strings", "string literals per function", True),
    ("total_s", "mean wall clock per binary (s)", False),
    ("analyze_s", "  ...of which one-time analysis (s)", None),
]


def fmt(v, best: bool) -> str:
    if v is None:
        return "—"
    s = f"{v:.3f}" if abs(v) < 100 else f"{v:.1f}"
    return f"**{s}**" if best else s


def table(overall: dict, tools: list[str]) -> str:
    out = ["| metric | " + " | ".join(tools) + " |", "|" + "---|" * (len(tools) + 1)]
    for key, label, higher in ROWS:
        vals = [overall.get(t, {}).get(key) for t in tools]
        real = [v for v in vals if v is not None]
        best = None
        if higher is not None and real:
            best = max(real) if higher else min(real)
        arrow = "" if higher is None else (" ↑" if higher else " ↓")
        cells = " | ".join(fmt(v, best is not None and v == best) for v in vals)
        out.append(f"| {label}{arrow} | {cells} |")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--filter", default="")
    ap.add_argument("--title", default=None)
    ap.add_argument("--tools", default=",".join(TOOLS))
    ap.add_argument("--per-tag", action="store_true")
    args = ap.parse_args()

    per_tag = analyze(Path(args.outdir))
    # Comma-separated substrings, ALL of which must appear: "strip_,arm64"
    # selects the stripped AArch64 cells without also dragging in the
    # unstripped twins, which would average two different experiments together.
    needles = [s for s in args.filter.split(",") if s]
    tags = [t for t in sorted(per_tag) if all(n in t for n in needles)]
    if not tags:
        print(f"no tags matching {args.filter!r}")
        return 1
    tools = args.tools.split(",")
    overall = agg(per_tag, tags)
    if args.title:
        print(f"### {args.title}\n")
    print(f"*{len(tags)} binaries: {', '.join(tags)}*\n")
    print(table(overall, tools))
    metric_counts = ", ".join(
        f"{tool}={overall.get(tool, {}).get('produced', 0)}" for tool in tools
    )
    argc_counts = ", ".join(
        f"{tool}={overall.get(tool, {}).get('n_argc_scored', 0)}" for tool in tools
    )
    print(
        "\n*Function metrics are micro-averaged over produced functions "
        f"({metric_counts}); prototype exactness denominators: {argc_counts}. "
        "Timing remains a per-binary mean.*"
    )

    if args.per_tag:
        print("\n#### success rate per binary\n")
        print("| binary | arch | GT fns | " + " | ".join(tools) + " |")
        print("|" + "---|" * (len(tools) + 3))
        for tag in tags:
            g = per_tag[tag]["gt"]
            cells = []
            for t in tools:
                d = per_tag[tag]["tools"].get(t, {})
                if d.get("missing"):
                    cells.append("—")
                else:
                    n, p = d.get("n_targets", 0), d.get("produced", 0)
                    cells.append(f"{p}/{n}")
            print(
                f"| {tag} | {g['arch']} | {g['dwarf'] or g['fde']} | "
                + " | ".join(cells)
                + " |"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
