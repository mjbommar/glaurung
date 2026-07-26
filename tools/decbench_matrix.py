#!/usr/bin/env python3
"""Per-cell DecBench metric ratchet over the committed corpus.

Runs the real `decbench evaluate` pipeline for every
`(program, compiler, opt)` triple — 14 x {gcc, clang} x {O0, O2} = 56 cells — and
compares each cell against a committed baseline.

Why per-cell and not the mean. The aggregate hides motion: one program getting
much worse while another improves leaves the mean flat, and a cell that produces
NO result at all silently *improves* the mean by leaving itself out. Both happened
in this repository. `recursion-gcc-O2` scored no GED for a while because we named
the function `fib_localalias`; the O2 mean read 10.40 over 27 binaries and looked
like a win against angr's 14.46, when including the binary put us at 14.42 — a tie.
A missing cell is a regression here, not an absence.

Local only: needs the DecBench fork on PATH (`decbench evaluate`), which hosted CI
does not have. Run it from `scripts/local-ci.sh` alongside the fixture matrix.

  tools/decbench_matrix.py --json > current.json
  tools/decbench_matrix.py --check
  tools/decbench_matrix.py --write-baseline
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decbench_corpus" / "src"
BASELINE = ROOT / "tests" / "decbench_corpus" / "baseline.json"
TOOLCHAIN_KEY = "__toolchain__"

COMPILERS = ("gcc", "clang")
OPTS = {"O0": ["-O0"], "O2": ["-O2"]}
METRIC_RE = re.compile(r"^\s+(ged|type_match|byte_match):\s+([0-9.]+)\s+\(mean\)")

# A metric may move slightly with an unrelated toolchain patch; a cell only fails
# when it moves by more than this. GED is a count, so it is compared exactly.
TOLERANCE = {"ged": 0.0, "type_match": 0.005, "byte_match": 0.005}


def decbench_dir() -> Path | None:
    """Where the DecBench fork is checked out. `decbench evaluate` must run with
    that as its cwd (it resolves its own data relative to it)."""
    env = os.environ.get("DECBENCH_DIR")
    return Path(env) if env else None


def toolchain_fingerprint() -> dict:
    """What compiled the corpus. A metric measured under a different compiler is
    not comparable, so the baseline records this and `--check` refuses to compare
    across a change rather than reporting phantom regressions."""
    def first_line(cmd: list[str]) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return (r.stdout or r.stderr).splitlines()[0].strip()
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return f"unavailable: {exc}"

    return {
        "gcc": first_line(["gcc", "--version"]),
        "clang": first_line(["clang", "--version"]),
    }


def compile_cell(program: str, compiler: str, opt: str, outdir: Path) -> Path | None:
    src = SRC / f"{program}.c"
    out = outdir / f"{program}-{compiler}-{opt}.so"
    r = subprocess.run(
        [compiler, "-shared", "-fPIC", "-g", *OPTS[opt], "-o", str(out), str(src)],
        capture_output=True,
        text=True,
    )
    return out if r.returncode == 0 else None


def evaluate(binary: Path, source: Path, backend: str, results: Path, cwd: Path) -> dict:
    """One cell's metrics. A metric the pipeline did not produce is recorded as
    None rather than omitted, so `--check` can tell "worse" from "gone"."""
    env = dict(os.environ, GLAURUNG_BIN=shutil.which("glaurung") or "", NO_COLOR="1")
    env.pop("FORCE_COLOR", None)
    out: dict[str, float | None] = {"ged": None, "type_match": None, "byte_match": None}
    try:
        p = subprocess.run(
            ["decbench", "evaluate", str(binary), "-s", str(source),
             "-d", backend, "-o", str(results)],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=900,
        )
    except subprocess.TimeoutExpired:
        return out | {"error": "timeout"}
    for line in p.stdout.splitlines():
        m = METRIC_RE.match(line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def run_matrix(backend: str, workdir: Path, cwd: Path) -> dict:
    result: dict = {TOOLCHAIN_KEY: toolchain_fingerprint()}
    programs = sorted(p.stem for p in SRC.glob("*.c"))
    results = workdir / "results"
    for program in programs:
        for compiler in COMPILERS:
            for opt in OPTS:
                key = f"{program}:{compiler}:{opt}"
                so = compile_cell(program, compiler, opt, workdir)
                if so is None:
                    result[key] = {"error": "build failed"}
                    print(f"  {key:34s} BUILD FAILED", flush=True)
                    continue
                cell = evaluate(so, SRC / f"{program}.c", backend, results, cwd)
                result[key] = cell
                shown = " ".join(
                    f"{k}={'-' if cell.get(k) is None else cell[k]}"
                    for k in ("ged", "type_match", "byte_match")
                )
                print(f"  {key:34s} {shown}", flush=True)
    return result


def cells(report: dict) -> dict:
    return {k: v for k, v in report.items() if k != TOOLCHAIN_KEY}


def check(current: dict, baseline: dict) -> list[str]:
    """Per-cell regressions. A metric that vanished counts as one."""
    problems: list[str] = []
    if current.get(TOOLCHAIN_KEY) != baseline.get(TOOLCHAIN_KEY):
        return [
            "toolchain fingerprint differs from the baseline — these metrics are "
            f"not comparable.\n    baseline: {baseline.get(TOOLCHAIN_KEY)}\n"
            f"    current:  {current.get(TOOLCHAIN_KEY)}"
        ]
    for key, base in sorted(cells(baseline).items()):
        cur = cells(current).get(key)
        if cur is None:
            problems.append(f"{key}: MISSING from the current run")
            continue
        for metric, tol in TOLERANCE.items():
            b, c = base.get(metric), cur.get(metric)
            if b is None:
                continue  # never scored here; nothing to regress from
            if c is None:
                problems.append(f"{key}.{metric}: {b} -> GONE (no longer scored)")
                continue
            # GED is a distance: lower is better. The other two are similarities.
            worse = (c > b + tol) if metric == "ged" else (c < b - tol)
            if worse:
                problems.append(f"{key}.{metric}: {b} -> {c}")
    for key in sorted(set(cells(current)) - set(cells(baseline))):
        problems.append(f"{key}: present in the run but absent from the baseline")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="print the report")
    ap.add_argument("--check", action="store_true", help="compare against the baseline")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--backend", default="glaurung", help="glaurung | angr | …")
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args()

    cwd = decbench_dir()
    if cwd is None or not cwd.is_dir():
        print(
            "DECBENCH_DIR is not set to a DecBench checkout. This gate needs the "
            "fork's `decbench evaluate`; it is local-only by design.",
            file=sys.stderr,
        )
        return 3

    import tempfile

    with tempfile.TemporaryDirectory(dir=args.workdir) as td:
        report = run_matrix(args.backend, Path(td), cwd)

    if args.write_baseline:
        missing = [k for k, v in cells(report).items() if "error" in v]
        if missing:
            print("REFUSING to write a baseline with failed cells:", file=sys.stderr)
            for k in missing:
                print(f"  {k}", file=sys.stderr)
            return 1
        BASELINE.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"wrote {BASELINE}")
        return 0

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))

    if args.check:
        if not BASELINE.exists():
            print(f"no baseline at {BASELINE}", file=sys.stderr)
            return 1
        problems = check(report, json.loads(BASELINE.read_text()))
        if problems:
            print(f"\nDECBENCH MATRIX REGRESSIONS ({len(problems)}):", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        print(f"\nno per-cell regressions across {len(cells(report))} cells")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
