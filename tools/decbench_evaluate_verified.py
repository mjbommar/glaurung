#!/usr/bin/env python3
"""Evaluate a DecBench tree and PROVE every binary was actually scored.

WHY THIS EXISTS. `decbench evaluate-tree` records a per-binary evaluation
failure as an *empty* result file -- `binary = "bzip2"` and nothing else -- with
no error on stderr and exit code 0. The functions in that binary then carry no
value, and every downstream tally counts them as unscored. Because our own
published row is already a coverage artifact, a silently under-covered run is
the one failure mode that would look exactly like the thing we are trying to
correct.

The drop is NOT deterministic and NOT a function of the flags. The same command
that produced a 17-byte `bzip2.toml` under load produced a 14,045-byte one on a
quiet machine. Treat it as load sensitivity: evaluate, then verify, then re-run
whatever came back empty, and refuse to report a number until the empty set is
itself empty.

Usage:
    python tools/decbench_evaluate_verified.py TREE --decompiler glaurung-<sha>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

# A result file that holds only `binary = "..."` is a silent failure, not a
# binary with nothing to say: every binary in the corpus has functions.
MIN_USEFUL_KEYS = 2


def evaluated_path(tree: Path, opt: str, project: str, binary: str) -> Path:
    return tree / opt / project / "evaluated" / f"{binary}.toml"


def binaries(tree: Path, column: str) -> list[tuple[str, str, str]]:
    """Every (opt, project, binary) we produced a decompiled artifact for.

    Scoped to the DECOMPILED set, not the compiled set: a binary this run never
    decompiled is out of scope, not a silent evaluation failure. Conflating the
    two turns "we only decompiled a slice" into 16 phantom failures.
    """
    out = []
    for art in sorted(tree.glob(f"*/*/decompiled/{column}_*.c")):
        project_dir = art.parent.parent
        stem = art.name[len(column) + 1 : -len(".c")]
        out.append((project_dir.parent.name, project_dir.name, stem))
    return out


def empty_results(
    tree: Path, want: list[tuple[str, str, str]]
) -> list[tuple[str, str, str]]:
    """Those whose evaluated TOML is missing or carries no metric keys."""
    bad = []
    for opt, project, binary in want:
        p = evaluated_path(tree, opt, project, binary)
        if not p.exists():
            bad.append((opt, project, binary))
            continue
        try:
            keys = tomllib.loads(p.read_text())
        except tomllib.TOMLDecodeError:
            bad.append((opt, project, binary))
            continue
        if len(keys) < MIN_USEFUL_KEYS:
            bad.append((opt, project, binary))
    return bad


def run_evaluate(
    decbench: Path, tree: Path, column: str, jobs: int, opts: list[str] | None
) -> int:
    """One `evaluate-tree` pass. No `-m`: the default is ALL metrics, and the
    published Union is over all three -- restricting them can only lose
    perfect functions."""
    cmd = [str(decbench), "evaluate-tree", str(tree), "-d", column]
    if jobs <= 1:
        cmd.append("--no-parallel")
    else:
        cmd += ["-j", str(jobs)]
    for o in opts or []:
        cmd += ["-O", o]
    print(f"  $ {' '.join(cmd[:6])} ...", flush=True)
    return subprocess.run(cmd, check=False).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tree", type=Path)
    ap.add_argument(
        "--decompiler", required=True, help="column name, e.g. glaurung-229fbb1"
    )
    ap.add_argument(
        "--decbench", type=Path, default=None, help="path to the decbench entrypoint"
    )
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument(
        "--retries", type=int, default=3, help="serial repair passes over the empty set"
    )
    ap.add_argument(
        "--report", type=Path, default=None, help="write a completeness report here"
    )
    args = ap.parse_args()

    decbench = args.decbench or (args.tree.parent / "decbench/.venv/bin/decbench")
    if not decbench.exists():
        print(f"error: decbench not found at {decbench}", file=sys.stderr)
        return 2

    want = binaries(args.tree, args.decompiler)
    print(f"{len(want)} binaries decompiled by {args.decompiler}")

    print("\n=== pass 1: parallel ===")
    run_evaluate(decbench, args.tree, args.decompiler, args.jobs, None)

    bad = empty_results(args.tree, want)
    print(
        f"\nafter pass 1: {len(want) - len(bad)}/{len(want)} binaries scored, {len(bad)} empty"
    )

    # Repair serially. The drop is load-sensitive, so the repair pass runs the
    # opt levels that came back empty with no parallelism at all.
    for attempt in range(1, args.retries + 1):
        if not bad:
            break
        opts = sorted({o for o, _, _ in bad})
        print(f"\n=== repair pass {attempt}: {len(bad)} empty, serial over {opts} ===")
        run_evaluate(decbench, args.tree, args.decompiler, 1, opts)
        bad = empty_results(args.tree, want)
        print(f"after repair {attempt}: {len(bad)} still empty")

    scored = len(want) - len(bad)
    report = {
        "decompiler": args.decompiler,
        "binaries_total": len(want),
        "binaries_scored": scored,
        "binaries_empty": len(bad),
        "complete": not bad,
        "empty": [{"opt": o, "project": p, "binary": b} for o, p, b in bad],
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"\nreport -> {args.report}")

    print(
        f"\n{'COMPLETE' if not bad else 'INCOMPLETE'}: {scored}/{len(want)} binaries scored"
    )
    if bad:
        print(
            "These binaries produced empty results and are NOT in the score:",
            file=sys.stderr,
        )
        for o, p, b in bad[:20]:
            print(f"  {o}/{p}/{b}", file=sys.stderr)
        print(
            "Refusing to certify the run. Re-run on a quiet machine.", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
