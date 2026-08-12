#!/usr/bin/env python3
"""Score the frozen 250-function DecBench holdout and refuse a regression.

WHY THIS EXISTS
---------------
`tools/decbench_matrix.py --check` guards 56 synthetic fixture cells. The
leaderboard is scored on a different population: 250 functions across 224 real
binaries. Those two can move in opposite directions, and they did — `byte_match`
on the holdout fell **0.2392 -> 0.2005** across four commits while the 56-cell
matrix, the 656-case execution differential and the whole Rust suite stayed
green. A 16 % loss on an official metric reached `master` unnoticed because
nothing scored the thing the leaderboard actually scores.

This is that gate. Run it before any submission, and before any push that
touches recovery.

WHAT IT DOES
------------
1. extract  — decompile the holdout at the current build (static analysis only)
2. package  — zip it the way the kit expects
3. ingest   — add it to an ISOLATED copy of the materialized tree as a column
4. score    — recompute byte_match and type_match over that column
5. compare  — against `tests/decbench_holdout_baseline.json`, refusing a drop

SAFETY
------
Several holdout binaries are compiled-from-source malware (theZoo corpus).
Nothing here executes them: decompilation is static, and the only thing ever
compiled is the *recovered C*. The tree is copied before ingest so the shared
benchmark tree is never mutated.

USAGE
-----
    tools/decbench_holdout.py --check          # fail on regression
    tools/decbench_holdout.py --write-baseline # accept current as the new floor
    tools/decbench_holdout.py --score-only     # print, compare nothing
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests" / "decbench_holdout_baseline.json"

#: Where the external eval kit and the DecBench checkout live. Both are large
#: and live outside this repo, so they are located rather than vendored.
KIT = Path.home() / "projects" / "personal" / "decbench-evalkit-sample-set"
TREE = Path.home() / "projects" / "personal" / "decbench-sample-set-glaurung-tree"

#: A drop larger than this on any metric fails `--check`. Scoring is
#: deterministic given the same package, so the tolerance only absorbs
#: floating-point summation order, not real movement.
TOLERANCE = 0.002

METRICS = ("byte_match", "type_match")


def _decbench_dir() -> Path:
    import os

    configured = os.environ.get("DECBENCH_DIR")
    if configured:
        return Path(configured)
    return Path("/nas4/data/workspace-infosec/decbench")


#: `evalkit ingest` re-pickles every project checkpoint in the tree and has
#: been measured at OVER TWO HOURS for a single column on this machine, even
#: against a pristine tree copy and with `--evaluate` off. That is the whole
#: reason `tools/recompile_fidelity.py` exists: this gate is for confirming a
#: submission, not for iterating on a change.
INGEST_TIMEOUT = 6 * 60 * 60


def _run(
    argv: list[str], cwd: Path | None = None, timeout: int = INGEST_TIMEOUT
) -> str:
    done = subprocess.run(
        argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )
    if done.returncode != 0:
        raise SystemExit(
            f"command failed ({done.returncode}): {' '.join(argv)}\n{done.stderr[-4000:]}"
        )
    return done.stdout


def extract_and_package(glaurung: Path, label: str) -> Path:
    """Decompile the holdout at the current build and zip the result."""
    if not KIT.is_dir():
        raise SystemExit(f"eval kit not found at {KIT}")
    out = _run(
        [
            sys.executable,
            str(KIT / "run_glaurung.py"),
            "--glaurung",
            str(glaurung),
            "--jobs",
            "12",
            "--version",
            label,
        ],
        cwd=KIT,
    )
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    if "250/250" not in tail or "224/224" not in tail:
        raise SystemExit(
            f"incomplete extraction — refusing to score a partial run:\n{tail}"
        )
    _run([sys.executable, str(KIT / "package.py")], cwd=KIT)
    packaged = KIT / f"glaurung-results-{label}.zip"
    shutil.copy(KIT / "results.zip", packaged)
    return packaged


def score(package: Path, label: str, scratch: Path) -> dict[str, float]:
    """Ingest into an isolated tree copy and recompute the official metrics."""
    decbench = _decbench_dir()
    if not (decbench / ".venv" / "bin" / "decbench").is_file():
        raise SystemExit(f"no DecBench checkout at {decbench} (set DECBENCH_DIR)")
    tree = scratch / "tree"
    if not tree.exists():
        if not TREE.is_dir():
            raise SystemExit(f"materialized tree not found at {TREE}")
        # Copy so ingest can never mutate the shared benchmark tree. Note the
        # checkpoints store ABSOLUTE paths, so scoring still *reads* the
        # original; only writes are isolated.
        shutil.copytree(TREE, tree, symlinks=True)
    _run(
        [
            str(decbench / ".venv" / "bin" / "decbench"),
            "evalkit",
            "ingest",
            str(package),
            str(tree),
            "--id",
            label,
            "--version",
            label,
            "--force",
        ],
        cwd=decbench,
    )
    python = str(decbench / ".venv" / "bin" / "python")
    _run([python, "scripts/reeval_bytematch.py", str(tree)], cwd=decbench)
    _run([python, "scripts/reeval_typematch.py", str(tree), "--emit"], cwd=decbench)
    return {
        "byte_match": _mean_bytematch(tree, label),
        "type_match": _mean_typematch(tree, label),
    }


def _mean_bytematch(tree: Path, label: str) -> float:
    raw = json.loads((tree / "byte_match_new.json").read_text())
    per: dict[str, list[float]] = defaultdict(list)
    for key, value in raw.items():
        parts = key.split("::")
        score_value = value["value"] if isinstance(value, dict) else value
        per[parts[3]].append(0.0 if score_value is None else float(score_value))
    if label not in per:
        raise SystemExit(f"no byte_match rows for column {label!r}")
    values = per[label]
    return sum(values) / len(values)


def _mean_typematch(tree: Path, label: str) -> float:
    raw = json.loads((tree / "type_match_new.json").read_text())
    if label not in raw:
        raise SystemExit(f"no type_match rows for column {label!r}")
    values = [entry["value"] for entry in raw[label].values()]
    return sum(values) / len(values)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail on a regression")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--label", default="glaurung-candidate")
    ap.add_argument("--scratch", type=Path, default=Path("/tmp/decbench-holdout"))
    ap.add_argument(
        "--package",
        type=Path,
        help="score an existing results.zip instead of extracting a fresh one",
    )
    args = ap.parse_args()

    glaurung = ROOT / ".venv" / "bin" / "glaurung"
    if not glaurung.is_file():
        glaurung = Path(shutil.which("glaurung") or "glaurung")

    args.scratch.mkdir(parents=True, exist_ok=True)
    package = args.package or extract_and_package(glaurung, args.label)
    print(f"package: {package}")
    current = score(package, args.label, args.scratch)

    print()
    print(f"{'metric':12} {'score':>9}")
    for metric in METRICS:
        print(f"{metric:12} {current[metric]:9.4f}")

    if args.write_baseline:
        BASELINE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        print(f"\nwrote {BASELINE}")
        return 0

    if args.score_only or not args.check:
        return 0

    if not BASELINE.is_file():
        raise SystemExit(
            f"no baseline at {BASELINE} — establish one with --write-baseline first"
        )
    baseline = json.loads(BASELINE.read_text())
    regressions = [
        f"  {metric}: {baseline[metric]:.4f} -> {current[metric]:.4f} "
        f"({current[metric] - baseline[metric]:+.4f})"
        for metric in METRICS
        if current[metric] < baseline[metric] - TOLERANCE
    ]
    print()
    if regressions:
        print("HOLDOUT REGRESSIONS:")
        print("\n".join(regressions))
        return 1
    print("HOLDOUT: no regression against the committed baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
