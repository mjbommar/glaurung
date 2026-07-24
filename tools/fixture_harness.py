#!/usr/bin/env python3
"""Compile the decompiler fixture corpus and run the execution-differential gate.

For every fixture in tests/decompiler_fixtures/src/, compile with each available
toolchain/opt-level, then run tools/diff_decompile.py and aggregate pass/fail.

This is the semantic-correctness driver for the decompiler: unlike DecBench's
type/GED/byte metrics, a failure here means the decompilation is behaviourally
WRONG. Run after any structurer / lowering change.

Usage:
    python tools/fixture_harness.py [--opt O0,O2] [--cc gcc,clang] [glob]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
DIFF = ROOT / "tools" / "diff_decompile.py"


def compile_one(src: Path, cc: str, opt: str) -> Path | None:
    BUILD.mkdir(parents=True, exist_ok=True)
    is_cpp = src.suffix == ".cpp"
    compiler = ("g++" if cc == "gcc" else "clang++") if is_cpp else cc
    out = BUILD / f"{src.stem}-{cc}-{opt}.so"
    cmd = [compiler, "-shared", "-fPIC", "-g", f"-{opt}", "-w", "-o", str(out), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  [build skip] {src.name} {cc} {opt}: {r.stderr.strip().splitlines()[-1] if r.stderr else '?'}")
        return None
    return out


def run_diff(binary: Path, src: Path) -> tuple[int, int, list[str]]:
    r = subprocess.run(
        [sys.executable, str(DIFF), str(binary), str(src), "--trials", "48"],
        capture_output=True, text=True, timeout=600,
    )
    passes = fails = 0
    detail: list[str] = []
    for line in r.stdout.splitlines():
        if line.startswith("PASS"):
            passes += 1
        elif line.startswith("FAIL"):
            fails += 1
            detail.append(line)
    return passes, fails, detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("glob", nargs="?", default="*.c*")
    ap.add_argument("--opt", default="O0")
    ap.add_argument("--cc", default="gcc")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    opts = args.opt.split(",")
    ccs = args.cc.split(",")
    srcs = sorted(SRC.glob(args.glob))
    if not srcs:
        print(f"no fixtures matching {args.glob} in {SRC}", file=sys.stderr)
        return 2

    grand_pass = grand_fail = 0
    for src in srcs:
        for cc in ccs:
            for opt in opts:
                binary = compile_one(src, cc, opt)
                if binary is None:
                    continue
                p, f, detail = run_diff(binary, src)
                grand_pass += p
                grand_fail += f
                flag = "" if f == 0 else "  <-- FAILURES"
                print(f"{src.stem:32s} {cc:5s} {opt:4s}  {p:3d} pass  {f:3d} fail{flag}")
                if args.verbose or f:
                    for d in detail:
                        print(f"      {d}")
    print(f"\n=== TOTAL: {grand_pass} pass, {grand_fail} fail ===")
    return 1 if grand_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
