#!/usr/bin/env python3
"""Regenerate tests/decompiler_fixtures/defuse_baseline.json.

The def-before-use lane compares the current decompiler's reported violations to
this committed census and fails on ANY change — a new violation OR a resolved
one — so the gate ratchets. Run this only after independently confirming a change
is real, never to make a red gate green.

    tools/gen_defuse_baseline.py            # write the baseline
    tools/gen_defuse_baseline.py --dry-run  # print the census, write nothing
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import defuse as D  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]

OUT = ROOT / "tests" / "decompiler_fixtures" / "defuse_baseline.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print, do not write")
    parser.add_argument("--jobs", type=int, default=None, help="parallel lanes")
    args = parser.parse_args()

    # Refuse to record a state that omits a declared fixture, for the same reason
    # the structural writer does: a silently shortened census reads as "clean".
    M.assert_fixtures_declared()
    report = D.defuse_report(max_workers=args.jobs)
    if report["problems"]:
        print("refusing to write a census with unbuilt lanes:", file=sys.stderr)
        for problem in report["problems"]:
            print(f"  {problem}", file=sys.stderr)
        return 1

    summary = D.summarize(report)
    print(
        f"REQUIRED: {summary['required_violations']} violation(s) in "
        f"{summary['required_functions_with_violations']} of "
        f"{summary['required_functions']} function-lanes "
        f"({summary['not_emitted']} not emitted)"
    )
    for lane, totals in sorted(report["lane_totals"].items()):
        print(
            f"  {lane:12s} {totals['violations']:6d} violation(s) in "
            f"{totals['functions_with_violations']:5d} of "
            f"{totals['functions_emitted']:5d} emitted function(s)"
        )
    if args.dry_run:
        return 0
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
