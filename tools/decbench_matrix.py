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
DECOMPILE_HELPER = ROOT / "tools" / "decbench_decompile.py"
TOOLCHAIN_KEY = "__toolchain__"
DECOMPILE_JSON_PREFIX = "__GLAURUNG_DECOMPILATION_JSON__="

COMPILERS = ("gcc", "clang")
OPTS = {"O0": ["-O0"], "O2": ["-O2"]}
METRIC_RE = re.compile(r"^\s+(ged|type_match|byte_match):\s+([0-9.]+)\s+\(mean\)")
FUNCTION_MARKER_RE = re.compile(
    r"^// Function: .+ @ 0x([0-9a-fA-F]+)\s*$", re.MULTILINE
)

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
        local = cwd / ".venv" / "bin" / "decbench"
        return [str(local)] if local.is_file() else ["decbench"]

    configured = os.environ.get("DECBENCH_PYTHON")
    candidates = [Path(configured)] if configured else []
    candidates += [cwd / ".venv" / "bin" / "python", cwd / ".venv" / "bin" / "python3"]
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate), str(GLAURUNG_ADAPTER)]
    raise FileNotFoundError(
        f"Glaurung's DecBench adapter needs DECBENCH_PYTHON or {cwd}/.venv/bin/python"
    )


def decbench_python(cwd: Path) -> str:
    """Resolve the interpreter containing DecBench and its backend dependencies."""
    configured = os.environ.get("DECBENCH_PYTHON")
    candidates = [Path(configured)] if configured else []
    candidates += [cwd / ".venv" / "bin" / "python", cwd / ".venv" / "bin" / "python3"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(
        f"behavior-only mode needs DECBENCH_PYTHON or {cwd}/.venv/bin/python"
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


def parse_decompiled_functions(combined_c: str) -> dict[int, str]:
    """Split DecBench's combined C artifact into exact address-keyed functions."""
    matches = list(FUNCTION_MARKER_RE.finditer(combined_c))
    parsed: dict[int, str] = {}
    for index, match in enumerate(matches):
        address = int(match.group(1), 16)
        if address in parsed:
            raise ValueError(f"duplicate decompiled address 0x{address:x}")
        end = (
            matches[index + 1].start() if index + 1 < len(matches) else len(combined_c)
        )
        code = combined_c[match.end() : end].strip()
        if not code:
            raise ValueError(f"empty decompiled function at 0x{address:x}")
        parsed[address] = code
    if not parsed:
        raise ValueError("combined C artifact has no function markers")
    return parsed


def behavior_required_functions(manifest, fixture: str) -> list[str]:
    """Return the exact semantic roots for any supported source corpus."""
    for catalog in (
        manifest.DECBENCH_PROJECTS,
        manifest.CURRICULUM_PROJECTS,
        manifest.REQUIRED_FUNCTIONS,
    ):
        if fixture in catalog:
            return list(catalog[fixture])
    return []


def behavior_problems(
    verdicts: dict,
    required: list[str],
    fixture: str | None = None,
    manifest=None,
) -> list[str]:
    """Return every absent or unacceptable required behavioral verdict.

    ``structural`` is weaker than execution and therefore fails by default.  It
    is accepted only when the exact function contract explicitly says execution
    is unsafe (currently the recursive linked-list nodes the generic harness
    cannot construct without following fuzz integers as pointers).
    """
    problems: list[str] = []
    for function in required:
        verdict = verdicts.get(function)
        if verdict is None:
            problems.append(f"{function}: missing verdict")
            continue
        status = verdict.get("status")
        structurally_exempt = (
            status == "structural"
            and fixture is not None
            and manifest is not None
            and bool(manifest.override(fixture, function).get("skip_exec"))
        )
        if status != "pass" and not structurally_exempt:
            detail = verdict.get("detail", "no detail")
            problems.append(f"{function}: {status or 'invalid'} ({detail})")
    return problems


def run_behavior(
    binary: Path,
    source: Path,
    fixture: str,
    decompiled: dict[int, str],
) -> tuple[dict, list[str]]:
    """Execute injected decompiler output using the canonical fixture contract."""
    import diff_decompile as differential

    required = behavior_required_functions(differential.M, fixture)
    if not required:
        return {}, [f"{fixture}: no required-function contract"]
    verdicts = differential.run(
        str(binary),
        str(source),
        fixture,
        seed=1234,
        fuzz=differential.M.FIXTURE_FUZZ,
        only=set(required),
        decompiled_by_va=decompiled,
    )
    return verdicts, behavior_problems(verdicts, required, fixture, differential.M)


def evaluate_behavior(
    binary: Path,
    source: Path,
    fixture: str,
    backend: str,
    results: Path,
) -> tuple[dict, list[str]]:
    """Recompile and execute one backend artifact against the original binary."""
    artifact_dir = results / "single_binary"
    artifacts = sorted(artifact_dir.glob(f"*_{binary.stem}.c"))
    if len(artifacts) != 1:
        return {}, [
            (
                f"{backend}: expected one combined C artifact for {binary.name}, "
                f"found {len(artifacts)}"
            )
        ]

    try:
        decompiled = parse_decompiled_functions(artifacts[0].read_text())
    except (OSError, ValueError) as exc:
        return {}, [f"{backend}: invalid combined C artifact ({exc})"]
    return run_behavior(binary, source, fixture, decompiled)


def decompile_backend(
    binary: Path,
    fixture: str,
    backend: str,
    output: Path,
    cwd: Path,
) -> tuple[dict[int, str], str | None]:
    """Run only the requested DecBench backend, without Joern metric extraction."""
    import diff_decompile as differential

    required = behavior_required_functions(differential.M, fixture)
    if not required:
        return {}, f"{fixture}: no required-function contract"
    # Required exports may call file-local helpers. Request every function that
    # exists in the exact input ELF so the behavioral harness can close those
    # calls using the same backend. Restricting this to the exported roots left
    # hash_slot/find_root unresolved and understated comparator correctness.
    requested = list(
        dict.fromkeys([*required, *differential.defined_functions(str(binary))])
    )
    command = [
        decbench_python(cwd),
        str(DECOMPILE_HELPER),
        str(binary),
        backend,
        str(output),
    ]
    for function in requested:
        command += ["--function", function]
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            env=evaluator_environment(backend),
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {}, f"{backend}: decompilation timeout"
    if process.returncode != 0:
        diagnostic = " ".join((process.stderr or process.stdout or "no output").split())
        return (
            {},
            f"{backend}: decompilation exit {process.returncode}: {diagnostic[-500:]}",
        )
    payload_line = next(
        (
            line[len(DECOMPILE_JSON_PREFIX) :]
            for line in reversed(process.stdout.splitlines())
            if line.startswith(DECOMPILE_JSON_PREFIX)
        ),
        None,
    )
    if payload_line is None:
        return {}, f"{backend}: decompilation produced no JSON payload"
    try:
        payload = json.loads(payload_line)
        functions = payload["functions"]
        decompiled = {
            int(function["address"]): str(function["code"])
            for function in functions
            if isinstance(function, dict)
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return {}, f"{backend}: malformed decompilation payload ({exc})"
    if not decompiled:
        return {}, f"{backend}: decompilation produced zero functions"
    return decompiled, None


def evaluate_behavior_only(
    binary: Path,
    source: Path,
    fixture: str,
    backend: str,
    results: Path,
    cwd: Path,
) -> dict:
    """Decompiler -> C -> rebuilt binary -> execution, with no graph metrics."""
    decompiled, error = decompile_backend(binary, fixture, backend, results, cwd)
    if error is not None:
        return {"behavior": {}, "error": error}
    verdicts, problems = run_behavior(binary, source, fixture, decompiled)
    result = {"behavior": verdicts}
    if problems:
        result["error"] = "behavior: " + "; ".join(problems)
    return result


def evaluate(
    binary: Path,
    source: Path,
    backend: str,
    results: Path,
    cwd: Path,
    behavior_fixture: str | None = None,
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
    if behavior_fixture is not None:
        verdicts, problems = evaluate_behavior(
            binary, source, behavior_fixture, backend, results
        )
        out["behavior"] = verdicts
        if problems:
            out["error"] = "behavior: " + "; ".join(problems)
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
    key: str,
    backend: str,
    workdir: Path,
    cwd: Path,
    source_dir: Path = SRC,
    behavior: bool = False,
    behavior_only: bool = False,
) -> dict:
    """Compile and evaluate one independent matrix cell."""
    program, compiler, opt = key.split(":")
    cell_dir = cell_workdir(workdir, key)
    cell_dir.mkdir(parents=True, exist_ok=True)
    so = compile_cell(program, compiler, opt, cell_dir, source_dir)
    if so is None:
        return {"error": "build failed"}
    source = source_dir / f"{program}.c"
    results = cell_dir / "results"
    if behavior_only:
        return evaluate_behavior_only(so, source, program, backend, results, cwd)
    return evaluate(
        so,
        source,
        backend,
        results,
        cwd,
        behavior_fixture=program if behavior else None,
    )


def print_cell(key: str, cell: dict) -> None:
    """Print one stable, compact cell result as soon as it completes."""
    if error := cell.get("error"):
        print(f"  {key:34s} ERROR {error}", flush=True)
        return
    if behavior := cell.get("behavior"):
        passed = sum(verdict.get("status") == "pass" for verdict in behavior.values())
        structural = sum(
            verdict.get("status") == "structural" for verdict in behavior.values()
        )
        if not any(cell.get(metric) is not None for metric in TOLERANCE):
            print(
                f"  {key:34s} behavior={passed} pass, "
                f"{structural} structural / {len(behavior)} required",
                flush=True,
            )
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
    behavior: bool = False,
    behavior_only: bool = False,
) -> dict:
    result: dict = {TOOLCHAIN_KEY: toolchain_fingerprint()}
    keys = select_cells(only, source_dir, programs)
    worker_count = default_jobs() if jobs is None else jobs
    if worker_count == 1:
        for key in keys:
            result[key] = run_cell(
                key,
                backend,
                workdir,
                cwd,
                source_dir,
                behavior=behavior,
                behavior_only=behavior_only,
            )
            print_cell(key, result[key])
        return result

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {
            pool.submit(
                run_cell,
                key,
                backend,
                workdir,
                cwd,
                source_dir,
                behavior,
                behavior_only,
            ): key
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
    ap.add_argument(
        "--behavior",
        action="store_true",
        help="also rebuild and execute each backend's decompiled C",
    )
    ap.add_argument(
        "--behavior-only",
        action="store_true",
        help="decompile/rebuild/execute cells without repeating graph metrics",
    )
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

    if args.behavior_only:
        args.behavior = True

    if args.behavior_only and (args.check or args.write_baseline):
        print(
            "--behavior-only cannot compare or write the metric baseline",
            file=sys.stderr,
        )
        return 2

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
            behavior=args.behavior,
            behavior_only=args.behavior_only,
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
