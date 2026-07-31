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
import fnmatch
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from build_guard import glaurung_bin

ROOT = TOOLS.parent
SRC = ROOT / "tests" / "decbench_corpus" / "src"
FIXTURE_SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
BASELINE = ROOT / "tests" / "decbench_corpus" / "baseline.json"
GLAURUNG_ADAPTER = ROOT / "tools" / "decbench_glaurung.py"
TOOLCHAIN_KEY = "__toolchain__"

COMPILERS = ("gcc", "clang")
OPTS = {"O0": ["-O0"], "O2": ["-O2"]}
METRIC_RE = re.compile(r"^\s+(ged|type_match|byte_match):\s+([0-9.]+)\s+\(mean\)")

# A metric may move slightly with an unrelated toolchain patch; a cell only fails
# when it moves by more than this. GED is a count, so it is compared exactly.
TOLERANCE = {"ged": 0.0, "type_match": 0.005, "byte_match": 0.005}
MAX_DEFAULT_JOBS = 4
CURRICULUM_PROGRAMS = tuple(
    f"{number:02d}_{name}"
    for number, name in (
        (15, "binary_search_tree"),
        (16, "red_black_tree"),
        (17, "hash_table"),
        (18, "binary_heap"),
        (19, "disjoint_set"),
        (20, "graph_bfs"),
        (21, "graph_dfs"),
        (22, "dijkstra"),
        (23, "topological_sort"),
        (24, "merge_sort"),
        (25, "kmp_search"),
        (26, "sparse_matrix"),
        (27, "newton_raphson"),
        (28, "euler_ode"),
        (29, "polynomial"),
        (30, "finite_difference"),
    )
)


def corpus_source(name: str) -> Path:
    """Return the source directory for a named, reviewable corpus."""
    if name == "decbench":
        return SRC
    if name == "curriculum":
        return FIXTURE_SRC
    raise ValueError(f"unknown corpus: {name}")


def corpus_programs(name: str) -> list[str]:
    """Return the exact programs in a named corpus.

    The curriculum shares a directory with bug fixtures, so a broad ``*.c``
    scan would silently turn a 16-project comparison into a different corpus.
    Keep its membership explicit and fail if a committed member disappears.
    """
    source = corpus_source(name)
    if name == "decbench":
        programs = sorted(path.stem for path in source.glob("*.c"))
    else:
        programs = list(CURRICULUM_PROGRAMS)
    missing = [
        program for program in programs if not (source / f"{program}.c").is_file()
    ]
    if missing:
        raise FileNotFoundError(f"{name} corpus is missing: {', '.join(missing)}")
    return programs


def default_jobs(cpu_count: int | None = None) -> int:
    """Return a conservative default for concurrent Joern subprocesses."""
    available = os.cpu_count() if cpu_count is None else cpu_count
    return max(1, min(MAX_DEFAULT_JOBS, available or 1))


def positive_int(value: str) -> int:
    """Parse a strictly positive worker count for argparse."""
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def cell_workdir(workdir: Path, key: str) -> Path:
    """Return the isolated mutable directory for one matrix cell."""
    return workdir / "cells" / key.replace(":", "-")


def decbench_dir() -> Path | None:
    """Where the DecBench fork is checked out. `decbench evaluate` must run with
    that as its cwd (it resolves its own data relative to it)."""
    env = os.environ.get("DECBENCH_DIR")
    return Path(env) if env else None


def decbench_command(cwd: Path, backend: str) -> list[str]:
    """Return the evaluator command for ``backend``.

    DecBench intentionally only imports its in-tree backends; it has no entry
    point discovery for external plugins.  Glaurung therefore owns a tiny
    adapter launcher which registers the backend before delegating to the real
    DecBench CLI.  Reference backends continue through the stock executable.
    """
    if backend != "glaurung":
        return ["decbench"]

    configured = os.environ.get("DECBENCH_PYTHON")
    candidates = [Path(configured)] if configured else []
    candidates += [cwd / ".venv" / "bin" / "python", cwd / ".venv" / "bin" / "python3"]
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate), str(GLAURUNG_ADAPTER)]
    raise FileNotFoundError(
        f"Glaurung's DecBench adapter needs DECBENCH_PYTHON or {cwd}/.venv/bin/python"
    )


def toolchain_fingerprint() -> dict:
    """What compiled the corpus. A metric measured under a different compiler is
    not comparable, so the baseline records this and `--check` refuses to compare
    across a change rather than reporting phantom regressions."""

    def first_line(cmd: list[str]) -> str:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False
            )
            return (r.stdout or r.stderr).splitlines()[0].strip()
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return f"unavailable: {exc}"

    return {
        "gcc": first_line(["gcc", "--version"]),
        "clang": first_line(["clang", "--version"]),
    }


def compile_cell(
    program: str,
    compiler: str,
    opt: str,
    outdir: Path,
    source_dir: Path = SRC,
) -> Path | None:
    src = source_dir / f"{program}.c"
    out = outdir / f"{program}-{compiler}-{opt}.so"
    r = subprocess.run(
        [compiler, "-shared", "-fPIC", "-g", *OPTS[opt], "-o", str(out), str(src)],
        capture_output=True,
        text=True,
        check=False,
    )
    return out if r.returncode == 0 else None


def evaluate(
    binary: Path, source: Path, backend: str, results: Path, cwd: Path
) -> dict:
    """Run one cell and fail closed on evaluator errors or an empty report.

    An individual absent metric remains ``None`` so ``--check`` can tell "worse"
    from "gone". All three absent is not a valid evaluation, even when a broken
    backend exits zero.
    """
    env = evaluator_environment(backend)
    out: dict[str, float | None] = {"ged": None, "type_match": None, "byte_match": None}
    try:
        p = subprocess.run(
            [
                *decbench_command(cwd, backend),
                "evaluate",
                str(binary),
                "-s",
                str(source),
                "-d",
                backend,
                "-o",
                str(results),
            ],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return out | {"error": "timeout"}
    for line in p.stdout.splitlines():
        m = METRIC_RE.match(line)
        if m:
            out[m.group(1)] = float(m.group(2))
    diagnostic = " ".join((p.stderr.strip() or p.stdout.strip() or "no output").split())
    diagnostic = diagnostic[-500:]
    if p.returncode != 0:
        return out | {"error": f"decbench exit {p.returncode}: {diagnostic}"}
    if all(value is None for value in out.values()):
        return out | {"error": f"decbench produced no metrics: {diagnostic}"}
    return out


def evaluator_environment(backend: str) -> dict[str, str]:
    """Return a deterministic subprocess environment for one backend."""
    env = dict(os.environ, NO_COLOR="1")
    if backend == "glaurung":
        env["GLAURUNG_BIN"] = glaurung_bin()
    env.pop("FORCE_COLOR", None)
    return env


def all_cell_keys(
    source_dir: Path = SRC, programs: list[str] | tuple[str, ...] | None = None
) -> list[str]:
    selected = (
        sorted(path.stem for path in source_dir.glob("*.c"))
        if programs is None
        else list(programs)
    )
    return [
        f"{program}:{compiler}:{opt}"
        for program in selected
        for compiler in COMPILERS
        for opt in OPTS
    ]


def select_cells(
    patterns=None,
    source_dir: Path = SRC,
    programs: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    """Cell keys matching any `program:compiler:opt` glob.

    A full run is 56 cells, each spawning a Joern JVM to compute a graph edit
    distance. It historically took about 37 minutes serially; `--jobs` now runs
    isolated cells concurrently. A change aimed at one program can still be
    measured against only that program. Fail-closed, exactly as
    `tools/dectest.py` is: a pattern matching nothing is an error, because
    "0 cells, no regressions" reads like success.
    """
    keys = all_cell_keys(source_dir, programs)
    if not patterns:
        return keys
    chosen: list[str] = []
    for pat in patterns:
        # A bare program name means the whole program, not a literal key.
        expanded = pat if ":" in pat else f"{pat}:*:*"
        hits = fnmatch.filter(keys, expanded)
        if not hits:
            raise SystemExit(
                f"--only {pat!r} matches no cell. Programs: "
                + ", ".join(sorted({k.split(":")[0] for k in keys}))
            )
        chosen += [k for k in hits if k not in chosen]
    return chosen


def run_cell(
    key: str, backend: str, workdir: Path, cwd: Path, source_dir: Path = SRC
) -> dict:
    """Compile and evaluate one independent matrix cell."""
    program, compiler, opt = key.split(":")
    cell_dir = cell_workdir(workdir, key)
    cell_dir.mkdir(parents=True, exist_ok=True)
    so = compile_cell(program, compiler, opt, cell_dir, source_dir)
    if so is None:
        return {"error": "build failed"}
    return evaluate(so, source_dir / f"{program}.c", backend, cell_dir / "results", cwd)


def print_cell(key: str, cell: dict) -> None:
    """Print one stable, compact cell result as soon as it completes."""
    if error := cell.get("error"):
        print(f"  {key:34s} ERROR {error}", flush=True)
        return
    shown = " ".join(
        f"{metric}={'-' if cell.get(metric) is None else cell[metric]}"
        for metric in ("ged", "type_match", "byte_match")
    )
    print(f"  {key:34s} {shown}", flush=True)


def run_matrix(
    backend: str,
    workdir: Path,
    cwd: Path,
    only=None,
    jobs: int | None = None,
    source_dir: Path = SRC,
    programs: list[str] | tuple[str, ...] | None = None,
) -> dict:
    result: dict = {TOOLCHAIN_KEY: toolchain_fingerprint()}
    keys = select_cells(only, source_dir, programs)
    worker_count = default_jobs() if jobs is None else jobs
    if worker_count == 1:
        for key in keys:
            result[key] = run_cell(key, backend, workdir, cwd, source_dir)
            print_cell(key, result[key])
        return result

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {
            pool.submit(run_cell, key, backend, workdir, cwd, source_dir): key
            for key in keys
        }
        for future in as_completed(futures):
            key = futures[future]
            result[key] = future.result()
            print_cell(key, result[key])
    return result


def cells(report: dict) -> dict:
    return {k: v for k, v in report.items() if k != TOOLCHAIN_KEY}


def cell_errors(report: dict) -> list[tuple[str, str]]:
    """Return every failed cell so every command mode can fail closed."""
    return [
        (key, str(cell["error"]))
        for key, cell in sorted(cells(report).items())
        if "error" in cell
    ]


def check(current: dict, baseline: dict, scoped: bool = False) -> list[str]:
    """Per-cell regressions. A metric that vanished counts as one.

    `scoped` says the run deliberately covered a subset, so a baseline cell that
    is absent is expected rather than a missing result. Every other rule is
    unchanged: within the cells that DID run, a regression is still a regression.
    """
    problems: list[str] = []
    if current.get(TOOLCHAIN_KEY) != baseline.get(TOOLCHAIN_KEY):
        return [
            (
                "toolchain fingerprint differs from the baseline — these metrics are "
                f"not comparable.\n    baseline: {baseline.get(TOOLCHAIN_KEY)}\n"
                f"    current:  {current.get(TOOLCHAIN_KEY)}"
            )
        ]
    for key, base in sorted(cells(baseline).items()):
        cur = cells(current).get(key)
        if cur is None:
            if not scoped:
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
    ap.add_argument(
        "--corpus",
        choices=("decbench", "curriculum"),
        default="decbench",
        help="source corpus to compile and score (default: decbench)",
    )
    ap.add_argument("--workdir", default=None)
    ap.add_argument(
        "--jobs",
        type=positive_int,
        default=positive_int(
            os.environ.get("GLAURUNG_DECBENCH_JOBS", str(default_jobs()))
        ),
        help="concurrent isolated cells (default: 4 or available CPUs; "
        "GLAURUNG_DECBENCH_JOBS overrides)",
    )
    ap.add_argument(
        "--only",
        action="append",
        default=None,
        help="cell glob `program[:compiler[:opt]]`, repeatable "
        "(e.g. --only statemachine --only '*:clang:O0'). "
        "A scoped run cannot write a baseline.",
    )
    ap.add_argument(
        "--list", action="store_true", help="print the selected cells and exit"
    )
    args = ap.parse_args()
    source_dir = corpus_source(args.corpus)
    programs = corpus_programs(args.corpus)

    if args.list:
        for key in select_cells(args.only, source_dir, programs):
            print(key)
        return 0
    if (args.only or args.corpus != "decbench") and args.write_baseline:
        print(
            "REFUSING: the committed baseline belongs to a full decbench-corpus run; "
            "a scoped or curriculum run cannot overwrite it.",
            file=sys.stderr,
        )
        return 1

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
        report = run_matrix(
            args.backend,
            Path(td),
            cwd,
            only=args.only,
            jobs=args.jobs,
            source_dir=source_dir,
            programs=programs,
        )

    if args.write_baseline:
        failures = cell_errors(report)
        if failures:
            print("REFUSING to write a baseline with failed cells:", file=sys.stderr)
            for key, error in failures:
                print(f"  {key}: {error}", file=sys.stderr)
            return 1
        BASELINE.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"wrote {BASELINE}")
        return 0

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))

    failures = cell_errors(report)
    if failures:
        print(f"\nDECBENCH MATRIX ERRORS ({len(failures)}):", file=sys.stderr)
        for key, error in failures:
            print(f"  {key}: {error}", file=sys.stderr)
        return 1

    if args.check:
        if args.corpus != "decbench":
            print(
                "--check currently compares only the committed decbench baseline; "
                "use --json for a curriculum comparison.",
                file=sys.stderr,
            )
            return 2
        if not BASELINE.exists():
            print(f"no baseline at {BASELINE}", file=sys.stderr)
            return 1
        problems = check(
            report, json.loads(BASELINE.read_text()), scoped=bool(args.only)
        )
        if problems:
            print(f"\nDECBENCH MATRIX REGRESSIONS ({len(problems)}):", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        n, total = len(cells(report)), len(all_cell_keys(source_dir, programs))
        scope = "SCOPED" if args.only else "FULL MATRIX"
        print(f"\n{scope}: no per-cell regressions across {n} of {total} cells")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
