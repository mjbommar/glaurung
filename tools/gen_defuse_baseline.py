#!/usr/bin/env python3
"""Regenerate tests/decompiler_fixtures/defuse_baseline.json.

The def-before-use lane compares the current decompiler's reported violations to
this committed census and fails on ANY change — a new violation OR a resolved
one — so the gate ratchets. Run this only after independently confirming a change
is real, never to make a red gate green.

Lowering a ceiling and adding cells for a new fixture are free. Raising one is
not: `tools/defuse_ratchet.py` refuses the write unless the caller names the
movement and says why, and records that acceptance inside the baseline so the
next person to regenerate inherits it.

    tools/gen_defuse_baseline.py            # write the baseline
    tools/gen_defuse_baseline.py --dry-run  # print the census, write nothing
    tools/gen_defuse_baseline.py --accept-regression 'rustc:O0=+10: <why>'
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))
import defuse as D  # ty: ignore[unresolved-import]
import defuse_ratchet as R  # ty: ignore[unresolved-import]
import manifest as M  # ty: ignore[unresolved-import]

OUT = ROOT / "tests" / "decompiler_fixtures" / "defuse_baseline.json"


def _load(path: Path) -> dict | None:
    """The committed baseline, or None when the file does not exist yet.

    A baseline that EXISTS but cannot be read is not the same thing as no
    baseline, and must never be treated as one: that would hand the guard an
    empty comparison and let any rise through on a corrupted file. Raises
    instead, and `main` turns it into a refusal.

    Raises:
        OSError: The file exists but could not be read.
        json.JSONDecodeError: The file exists but is not the census shape.
    """
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def guard(report: dict, previous: dict | None, accepted_args: list[str]) -> int | None:
    """Refuse an upward move that nobody asked for; annotate the ones they did.

    Mutates ``report`` in place to carry the accepted-regression history forward.

    Args:
        report: The freshly measured census, about to be written.
        previous: The committed baseline, or None on a first write.
        accepted_args: Raw ``--accept-regression`` strings.

    Returns:
        A process exit code when the write must be refused, otherwise None.
    """
    try:
        accepted = R.parse_acceptances(accepted_args)
    except R.AcceptSyntaxError as error:
        print(f"{error}", file=sys.stderr)
        return 2
    if previous is None:
        if accepted:
            print(
                "no committed baseline to compare against; "
                "--accept-regression has nothing to accept",
                file=sys.stderr,
            )
            return 2
        # Say this out loud. Deleting the file is the obvious way around a
        # refusal, and `be307496` predicted exactly that ("blocking would only
        # teach people to delete the file"). Writing from nothing is legitimate
        # for a first baseline and is a laundered regression otherwise, and the
        # two are indistinguishable from here — so name it rather than guess.
        print(
            "NOTE: no existing baseline, so nothing was compared and no ceiling "
            "was checked.\n      If the file was deleted rather than never "
            "written, restore it from git and rerun:\n      the accepted-"
            "regression history does not survive a rewrite from nothing.",
            file=sys.stderr,
        )
        return None
    regressions = R.find_regressions(report, previous)
    records, problems = R.apply_acceptances(regressions, accepted)
    if problems:
        print(
            "REFUSING TO RAISE THE DEF-BEFORE-USE CEILING.\n"
            "A regeneration may LOWER any ceiling and ADD cells for free. These "
            "movements go the wrong way,\nand this writer is the documented fix "
            "for the OTHER half of the ratchet, so an unguarded rewrite here is\n"
            "how a real regression becomes the new normal without anyone reading "
            "it:\n",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEach one is a wrong-code bug in emitted C: the recovered function "
            "reads a value the machine never\nproduced. Investigate first. If the "
            "movement is genuinely accepted, say so and say why.",
            file=sys.stderr,
        )
        return 1
    report["accepted_regressions"] = R.carry_forward(previous, records)
    for record in records:
        print(
            f"ACCEPTED {record['key']}/{record['measure']}: "
            f"{record['from']} -> {record['to']} — {record['reason']}"
        )
    for line in R.drift_lines(report["accepted_regressions"]):
        print(line)
    return None


def main(argv: list[str] | None = None) -> int:
    """Measure the corpus and write the baseline, guarding the upward direction."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print, do not write")
    parser.add_argument("--jobs", type=int, default=None, help="parallel lanes")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=OUT,
        help="the baseline to compare against and write (as the sibling tools take)",
    )
    parser.add_argument(
        "--accept-regression",
        action="append",
        default=[],
        metavar="'LANE[/MEASURE]=+DELTA: reason'",
        help="deliberately raise one ceiling; recorded in the baseline",
    )
    args = parser.parse_args(argv)

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
    # The guard talks on stderr; without this its refusal interleaves ahead of
    # the per-lane table it is talking about.
    sys.stdout.flush()
    try:
        previous = _load(args.baseline)
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"refusing to write: {args.baseline} exists but cannot be read as a "
            f"census ({error}). Restore it from git rather than regenerating over "
            "a ceiling nobody can see.",
            file=sys.stderr,
        )
        return 2
    refusal = guard(report, previous, args.accept_regression)
    if refusal is not None:
        return refusal
    if args.dry_run:
        return 0
    args.baseline.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.baseline}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
