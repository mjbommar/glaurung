#!/usr/bin/env python3
"""Measure cold/warm decompilation, RSS, object parses, and shared-pass timings.

Each case is ``NAME=PATH@VA``. Cold measurement uses a fresh Python process;
warm measurement repeats the same decompilation in one second fresh process.
The native profiler remains opt-in and output-transparent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline_profile_report import build_report, parse_trace

SCHEMA = "glaurung-decompiler-profile-v1"
WORKER_SCHEMA = "glaurung-decompiler-profile-worker-v1"
JsonObject = dict[str, Any]


class DecompilerProfileError(ValueError):
    """Raised when a requested profile cannot produce trustworthy evidence."""


@dataclass(frozen=True)
class Case:
    """One named binary/function measurement target."""

    name: str
    path: Path
    entry_va: int


def parse_case(value: str) -> Case:
    """Parse and validate one ``NAME=PATH@VA`` case."""
    try:
        name, target = value.split("=", 1)
        path_text, va_text = target.rsplit("@", 1)
        entry_va = int(va_text, 0)
    except (ValueError, TypeError) as error:
        raise DecompilerProfileError(
            f"invalid case {value!r}; expected NAME=PATH@VA"
        ) from error
    if not name or not path_text or entry_va < 0:
        raise DecompilerProfileError(f"invalid case {value!r}; expected NAME=PATH@VA")
    path = Path(path_text).resolve()
    if not path.is_file():
        raise DecompilerProfileError(f"case binary does not exist: {path}")
    return Case(name=name, path=path, entry_va=entry_va)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _worker(path: Path, entry_va: int, iterations: int) -> int:
    import glaurung as g

    durations: list[int] = []
    output_hashes: list[str] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        output = g.ir.decompile_at(str(path), entry_va, style="decbench")
        durations.append(time.perf_counter_ns() - started)
        output_hashes.append(hashlib.sha256(output.encode()).hexdigest())
    payload = {
        "schema": WORKER_SCHEMA,
        "decompile_ns": durations,
        "output_sha256": output_hashes,
        "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def _run_worker(case: Case, iterations: int) -> JsonObject:
    environment = os.environ.copy()
    environment["GLAURUNG_PIPELINE_PROFILE"] = "1"
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        str(case.path),
        hex(case.entry_va),
        str(iterations),
    ]
    started = time.perf_counter_ns()
    result = subprocess.run(
        command,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    process_wall_ns = time.perf_counter_ns() - started
    if result.returncode != 0:
        raise DecompilerProfileError(
            f"{case.name}: worker failed ({result.returncode}): {result.stderr.strip()}"
        )
    try:
        worker = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise DecompilerProfileError(f"{case.name}: invalid worker JSON") from error
    if not isinstance(worker, dict) or worker.get("schema") != WORKER_SCHEMA:
        raise DecompilerProfileError(f"{case.name}: unsupported worker result")
    profile = build_report(parse_trace(result.stderr.splitlines()))
    runs = profile["runs"]
    if len(runs) != iterations:
        raise DecompilerProfileError(
            f"{case.name}: expected {iterations} completed runs, found {len(runs)}"
        )
    functions = profile["functions"]
    if not functions:
        raise DecompilerProfileError(f"{case.name}: no function-stage evidence")
    stage_duration_ns: dict[str, int] = {}
    for function in functions:
        for stage, duration in function["stage_duration_ns"].items():
            stage_duration_ns[stage] = stage_duration_ns.get(stage, 0) + duration
    durations = worker.get("decompile_ns")
    hashes = worker.get("output_sha256")
    max_rss_kib = worker.get("max_rss_kib")
    if (
        not isinstance(durations, list)
        or len(durations) != iterations
        or not all(isinstance(value, int) and value >= 0 for value in durations)
        or not isinstance(hashes, list)
        or len(hashes) != iterations
        or not all(isinstance(value, str) and value for value in hashes)
        or not isinstance(max_rss_kib, int)
        or max_rss_kib <= 0
    ):
        raise DecompilerProfileError(f"{case.name}: malformed worker measurements")
    return {
        "process_wall_ns": process_wall_ns,
        "decompile_ns": durations,
        "decompile_median_ns": int(statistics.median(durations)),
        "max_rss_kib": max_rss_kib,
        "object_parse_count": [run["object_parse_count"] for run in runs],
        "native_run_ns": [run["duration_ns"] for run in runs],
        "output_sha256": hashes,
        "stage_duration_ns": dict(sorted(stage_duration_ns.items())),
    }


def _git_provenance(root: Path) -> JsonObject:
    def run(*arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"

    return {
        "revision": run("rev-parse", "HEAD"),
        "dirty": bool(run("status", "--porcelain")),
    }


def build_benchmark(cases: list[Case], warm_runs: int, root: Path) -> JsonObject:
    """Run each case in isolated cold and warm worker processes."""
    if not cases:
        raise DecompilerProfileError("at least one --case is required")
    if warm_runs < 1:
        raise DecompilerProfileError("--warm-runs must be positive")
    results = []
    for case in cases:
        cold = _run_worker(case, 1)
        warm = _run_worker(case, warm_runs)
        results.append(
            {
                "name": case.name,
                "path": str(case.path),
                "entry_va": hex(case.entry_va),
                "binary_size": case.path.stat().st_size,
                "binary_sha256": _sha256(case.path),
                "cold": cold,
                "warm": warm,
            }
        )
    return {
        "schema": SCHEMA,
        "clock": "time.perf_counter_ns",
        "rss_unit": "KiB on Linux (resource.ru_maxrss)",
        "warm_runs": warm_runs,
        "allocations": {
            "status": "unavailable",
            "reason": "the production Python extension exposes no allocator counter",
        },
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "executable": sys.executable,
        },
        "git": _git_provenance(root),
        "cases": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--warm-runs", type=int, default=5)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--worker",
        nargs=3,
        metavar=("PATH", "VA", "ITERATIONS"),
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the profile harness or its isolated worker."""
    args = _parser().parse_args(argv)
    if args.worker is not None:
        path, va, iterations = args.worker
        return _worker(Path(path), int(va, 0), int(iterations))
    try:
        cases = [parse_case(value) for value in args.case]
        report = build_benchmark(cases, args.warm_runs, Path.cwd())
    except (OSError, DecompilerProfileError, ValueError) as error:
        raise SystemExit(f"decompiler profile failed: {error}") from error
    rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
