#!/usr/bin/env python3
"""Compare verified structure-v2 output with production v1 over real fixtures.

The target universe defaults to the ground-truth unwanted-goto rows in
``tests/open_defects/known_failures.json``. Shadow-v2 is a verified subset:
requested VAs absent from its batch result are explicit local declines, not
silently successful functions.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import json
import os
import re
import resource
import subprocess
import time
from pathlib import Path

import glaurung as g

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
INVENTORY = ROOT / "tests" / "open_defects" / "known_failures.json"
GOTO_RE = re.compile(r"\bgoto\s+\w+\s*;")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare production and verified structure-v2 fixture output."
    )
    parser.add_argument(
        "--fixture",
        action="append",
        default=[],
        metavar="GLOB",
        help="limit object basenames by shell-style glob; repeatable",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(4, os.cpu_count() or 1),
        help="number of fixture binaries compared concurrently (default: up to 4)",
    )
    parser.add_argument("--output", type=Path, help="write deterministic JSON here")
    return parser


def _targets(fixtures: list[str]) -> dict[str, list[dict]]:
    payload = json.loads(INVENTORY.read_text())
    selected: dict[str, list[dict]] = {}
    for row in payload["structure"]:
        name = str(row["obj"])
        if fixtures and not any(
            fnmatch.fnmatchcase(name, pattern) for pattern in fixtures
        ):
            continue
        selected.setdefault(name, []).append(row)
    return selected


def _decompile(path: Path, vas: list[int], shadow_v2: bool) -> dict[int, str]:
    rows = g.ir.decompile_many(
        str(path),
        vas,
        style="decbench",
        shadow_v2=shadow_v2,
        max_functions=max(1, len(set(vas))),
    )
    return {int(va): text for _name, va, text, *_extra in rows}


def compare_object(name: str, rows: list[dict]) -> dict:
    """Compare all requested ground-truth rows for one real fixture binary."""
    path = BUILD / name
    vas = list(dict.fromkeys(int(row["va"]) for row in rows))

    started = time.perf_counter()
    production = _decompile(path, vas, False)
    production_seconds = time.perf_counter() - started
    started = time.perf_counter()
    shadow = _decompile(path, vas, True)
    shadow_seconds = time.perf_counter() - started

    comparisons = []
    row_by_va = {int(row["va"]): row for row in rows}
    for va in vas:
        baseline = production.get(va)
        candidate = shadow.get(va)
        baseline_gotos = len(GOTO_RE.findall(baseline or ""))
        candidate_gotos = (
            len(GOTO_RE.findall(candidate)) if candidate is not None else None
        )
        if baseline is None:
            status = "production_missing"
        elif candidate is None:
            status = "shadow_declined"
        elif candidate_gotos < baseline_gotos:
            status = "improved"
        elif candidate_gotos > baseline_gotos:
            status = "regressed"
        else:
            status = "unchanged"
        comparisons.append(
            {
                "fn": row_by_va[va]["fn"],
                "va": va,
                "status": status,
                "production_gotos": baseline_gotos,
                "shadow_gotos": candidate_gotos,
                "production_bytes": len((baseline or "").encode()),
                "shadow_bytes": len(candidate.encode())
                if candidate is not None
                else None,
            }
        )
    return {
        "object": name,
        "requested": len(vas),
        "production_seconds": round(production_seconds, 6),
        "shadow_seconds": round(shadow_seconds, 6),
        "functions": comparisons,
    }


def build_report(targets: dict[str, list[dict]], jobs: int) -> dict:
    """Build one deterministic report while comparing binaries concurrently."""
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    started = time.perf_counter()
    objects = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(compare_object, name, rows): name
            for name, rows in targets.items()
        }
        for future in concurrent.futures.as_completed(futures):
            objects.append(future.result())
    objects.sort(key=lambda item: item["object"])
    functions = [function for obj in objects for function in obj["functions"]]
    status_counts = {
        status: sum(function["status"] == status for function in functions)
        for status in (
            "improved",
            "unchanged",
            "regressed",
            "shadow_declined",
            "production_missing",
        )
    }
    comparable = [
        function
        for function in functions
        if function["shadow_gotos"] is not None
        and function["status"] != "production_missing"
    ]
    return {
        "revision": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "objects": len(objects),
        "requested_functions": len(functions),
        "status_counts": status_counts,
        "production_gotos_comparable": sum(
            function["production_gotos"] for function in comparable
        ),
        "shadow_gotos_comparable": sum(
            function["shadow_gotos"] for function in comparable
        ),
        "production_bytes_comparable": sum(
            function["production_bytes"] for function in comparable
        ),
        "shadow_bytes_comparable": sum(
            function["shadow_bytes"] for function in comparable
        ),
        "production_seconds_sum": round(
            sum(obj["production_seconds"] for obj in objects), 6
        ),
        "shadow_seconds_sum": round(sum(obj["shadow_seconds"] for obj in objects), 6),
        "wall_seconds": round(time.perf_counter() - started, 6),
        "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "results": objects,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.jobs < 1:
        _parser().error("--jobs must be at least 1")
    targets = _targets(args.fixture)
    if not targets:
        _parser().error("no known structure rows matched the fixture filters")
    report = build_report(targets, args.jobs)
    text = json.dumps(report, indent=1) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
