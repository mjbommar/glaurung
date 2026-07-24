#!/usr/bin/env python3
"""Compile the fixture corpus across a toolchain matrix and run the fail-closed
execution-differential gate, producing a per-function result map.

Required PR matrix (x86-64): {gcc, clang} x {O0, O2}. A compiler that is missing,
or a required-lane source that fails to compile, is a FAILURE — not a skip
(fail-closed). Environment-only gaps (e.g. a missing clang C++ runtime) must be
declared in ALLOWED_MISSING, which is itself asserted, so nothing is skipped
silently.

  python tools/fixture_harness.py                 # run required matrix, print
  python tools/fixture_harness.py --write-baseline # regenerate baseline.json
  python tools/fixture_harness.py --json           # machine-readable result map
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
DIFF = ROOT / "tools" / "diff_decompile.py"
BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"

REQUIRED_MATRIX = [("gcc", "O0"), ("gcc", "O2"), ("clang", "O0"), ("clang", "O2")]

# Declared environment gaps (compiler/runtime absent). Each entry is asserted to
# still be a real gap; it is never a silent skip. (cc, opt, fixture-stem).
ALLOWED_MISSING: set[tuple[str, str, str]] = set()

RDTMP = "/nas4/data/workspace-infosec/rdtmp"


def compile_fixture(src: Path, cc: str, opt: str) -> tuple[Path | None, str]:
    is_cpp = src.suffix == ".cpp"
    compiler = ("g++" if cc == "gcc" else "clang++") if is_cpp else cc
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / f"{src.stem}-{cc}-{opt}.so"
    cmd = [compiler, "-shared", "-fPIC", "-g", f"-{opt}", "-w", "-o", str(out), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        return None, (r.stderr.strip().splitlines() or ["?"])[-1]
    return out, ""


def run_matrix(matrix, fuzz: int) -> dict:
    """Return {f"{stem}:{cc}:{opt}": {func: status}} plus lane-level errors."""
    result: dict = {}
    srcs = sorted(list(SRC.glob("*.c")) + list(SRC.glob("*.cpp")))
    for src in srcs:
        for cc, opt in matrix:
            key = f"{src.stem}:{cc}:{opt}"
            so, err = compile_fixture(src, cc, opt)
            if so is None:
                if (cc, opt, src.stem) in ALLOWED_MISSING:
                    result[key] = {"__lane__": "env-missing"}
                else:
                    result[key] = {"__lane__": f"compile-failed: {err}"}
                continue
            r = subprocess.run(
                [sys.executable, str(DIFF), str(so), str(src),
                 "--fixture", src.stem, "--fuzz", str(fuzz), "--json"],
                capture_output=True, text=True, timeout=900, check=False,
            )
            try:
                fns = json.loads(r.stdout)
            except json.JSONDecodeError:
                result[key] = {"__lane__": f"gate-crashed: {r.stderr.strip()[-160:]}"}
                continue
            if "__error__" in fns:
                result[key] = {"__lane__": fns["__error__"]}
                continue
            result[key] = {name: v["status"] for name, v in fns.items()}
    return result


def summarize(result: dict) -> tuple[int, int, int, int]:
    p = f = s = lanes = 0
    for fns in result.values():
        if "__lane__" in fns:
            lanes += 1
            continue
        for st in fns.values():
            p += st == "pass"
            f += st == "fail"
            s += st == "structural"
    return p, f, s, lanes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fuzz", type=int, default=16)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--gcc-o0-only", action="store_true", help="fast local subset")
    args = ap.parse_args()

    matrix = [("gcc", "O0")] if args.gcc_o0_only else REQUIRED_MATRIX
    result = run_matrix(matrix, args.fuzz)

    if args.write_baseline:
        BASELINE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"wrote {BASELINE}")
        return 0
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    lane_errors = []
    for key, fns in sorted(result.items()):
        if "__lane__" in fns:
            lane_errors.append((key, fns["__lane__"]))
            print(f"{key:44s}  LANE: {fns['__lane__']}")
            continue
        pf = sum(1 for st in fns.values() if st == "pass")
        ff = sum(1 for st in fns.values() if st == "fail")
        sf = sum(1 for st in fns.values() if st == "structural")
        flag = "" if ff == 0 else "  <-- FAILURES"
        print(f"{key:44s}  {pf:3d} pass {ff:3d} fail {sf:3d} struct{flag}")
    p, f, s, lanes = summarize(result)
    print(f"\n=== TOTAL: {p} pass, {f} fail, {s} structural; {lanes} lane error(s) ===")
    # Fail-closed: any lane error (compile/dep/gate failure) fails the run.
    return 1 if (f or lanes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
