#!/usr/bin/env python3
"""Print every tool's C for one ground-truth function, with its DWARF signature.

    sidebyside.py <outdir> <tag> <va-or-name> [--max-lines N]

The metrics describe the artifact; this prints it. Any claim in the writeup
about readability has to survive being read next to the actual output, which is
the check no aggregate performs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

TOOLS = ("glaurung", "ghidra", "angr", "retdec")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("tag")
    ap.add_argument("target")
    ap.add_argument("--max-lines", type=int, default=60)
    args = ap.parse_args()
    out = Path(args.outdir)

    gt = json.loads((out / f"gt_{args.tag}.json").read_text())
    by_name = {f["name"]: f for f in gt["dwarf"]}
    if args.target in by_name:
        g = by_name[args.target]
    else:
        va = int(args.target, 0)
        g = next((f for f in gt["dwarf"] if f["va"] == va), None)
    if g is None:
        print(f"no ground-truth function {args.target} in {args.tag}")
        return 1

    print("=" * 78)
    print(
        f"DWARF ground truth: {g['ret']} {g['name']}({', '.join(g['params']) or 'void'})"
    )
    print(f"  entry VA {hex(g['va'])}   binary {args.tag}   arch {gt['arch']}")
    print("=" * 78)

    for tool in TOOLS:
        p = out / f"{tool}_{args.tag}.json"
        if not p.exists():
            print(f"\n----- {tool}: no result file -----")
            continue
        data = json.loads(p.read_text())
        f = next((x for x in data.get("functions", []) if x["va"] == g["va"]), None)
        print(f"\n{'-' * 30} {tool} {'-' * 30}")
        if f is None:
            print(
                f"  (did not return this VA; tool reported "
                f"{len(data.get('functions', []))} functions)"
            )
            continue
        if not f.get("code"):
            print(f"  STATUS: {f.get('status')}")
            continue
        print(f"  name={f.get('name')}  status={f.get('status')}")
        lines = f["code"].splitlines()
        for ln in lines[: args.max_lines]:
            print("  " + ln)
        if len(lines) > args.max_lines:
            print(f"  ... [{len(lines) - args.max_lines} more lines]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
