#!/usr/bin/env python3
"""Run every decompiler over one sample binary against a shared function set.

    drive.py <binary> <outdir> [--gtsource dwarf|fde] [--limit N] [--tools a,b]

Each tool is asked for the SAME function entry VAs, taken from the binary's own
ground truth, so the comparison is per-function and not per-tool-opinion. A tool
that simply fails to find a function still gets a row (`not_found`) rather than
quietly shrinking its own denominator.

Wall clock is recorded split into analyse vs decompile where the tool exposes
the distinction, because "Ghidra is slower" is usually a statement about its
one-time auto-analysis, not about per-function decompilation.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from config import DECBENCH_PY, GHIDRA_DIR, GLAURUNG_BIN, RETDEC_BIN


def sh(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-3000:]
    except subprocess.TimeoutExpired:
        return -9, f"HARNESS TIMEOUT after {timeout}s"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("outdir")
    ap.add_argument(
        "--gtbinary",
        default=None,
        help=(
            "Binary to read ground truth FROM, when it differs from the one being "
            "decompiled. Used for the stripped twins: stripping removes the DWARF "
            "but moves no code, so the unstripped copy still describes the stripped "
            "one exactly. Without this a stripped run would have an empty ground "
            "truth and score 100%% on nothing."
        ),
    )
    ap.add_argument("--gtsource", default="dwarf", choices=("dwarf", "fde"))
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--tools", default="glaurung,ghidra,angr,retdec")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--tag", default=None)
    args = ap.parse_args()

    binary = Path(args.binary)
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    tag = args.tag or binary.name

    gt_binary = Path(args.gtbinary) if args.gtbinary else binary
    gt_path = out / f"gt_{tag}.json"
    with open(gt_path, "w") as fh:
        p = subprocess.run(
            [DECBENCH_PY, str(HERE / "gt.py"), str(gt_binary)], stdout=fh, timeout=300
        )
    if p.returncode != 0:
        print(f"GT FAILED for {gt_binary}", file=sys.stderr)
        return 1
    gt = json.loads(gt_path.read_text())

    if args.gtsource == "dwarf":
        entries = [f["va"] for f in gt["dwarf"]]
    else:
        entries = [f["va"] for f in gt["fde"]]
    entries = sorted(set(entries))

    # Even stride, not the first N. bash has 2345 FDEs and its lowest 40
    # addresses are a contiguous run of 29-to-46-byte stubs; sampling those
    # measured how each tool treats one unrepresentative thunk table and
    # reported angr as finding 4 of 40 functions in a binary where it actually
    # located 2259 of 2345. A stride spreads the sample over the whole image
    # and stays deterministic, so runs remain comparable.
    if len(entries) > args.limit:
        step = len(entries) / args.limit
        entries = [entries[int(i * step)] for i in range(args.limit)]
    if not entries:
        print(f"no ground-truth functions for {binary}", file=sys.stderr)
        return 2
    vas = ",".join(hex(v) for v in entries)

    tools = args.tools.split(",")
    summary = {
        "binary": str(binary),
        "tag": tag,
        "gt": args.gtsource,
        "n_targets": len(entries),
    }

    if "glaurung" in tools:
        _rc, log = sh(
            [
                sys.executable,
                str(HERE / "run_glaurung.py"),
                GLAURUNG_BIN,
                str(binary),
                str(out / f"glaurung_{tag}.json"),
                "--vas",
                vas,
                "--timeout",
                str(args.timeout),
            ],
            args.timeout + 120,
        )
        summary["glaurung_log"] = log[-300:]
    if "ghidra" in tools:
        _rc, log = sh(
            [
                DECBENCH_PY,
                str(HERE / "run_ghidra.py"),
                GHIDRA_DIR,
                str(binary),
                str(out / f"ghidra_{tag}.json"),
                "--vas",
                vas,
            ],
            args.timeout + 300,
        )
        summary["ghidra_log"] = log[-300:]
    if "angr" in tools:
        _rc, log = sh(
            [
                DECBENCH_PY,
                str(HERE / "run_angr.py"),
                str(binary),
                str(out / f"angr_{tag}.json"),
                "--vas",
                vas,
            ],
            args.timeout + 120,
        )
        summary["angr_log"] = log[-300:]
    if "retdec" in tools:
        _rc, log = sh(
            [
                sys.executable,
                str(HERE / "run_retdec.py"),
                RETDEC_BIN,
                str(binary),
                str(out / f"retdec_{tag}.json"),
                "--timeout",
                str(args.timeout),
            ],
            args.timeout + 120,
        )
        summary["retdec_log"] = log[-300:]

    (out / f"summary_{tag}.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
