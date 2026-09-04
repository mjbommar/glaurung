#!/usr/bin/env python3
"""Compare production and verified structure-v2 execution over shadow candidates.

The input is a pinned ``structure_v2_compare.py`` JSON report. Only functions
for which that report observed actual shadow output are executable candidates;
a local shadow decline is never silently converted into an execution result.
Both renderings run through ``diff_decompile.run`` with identical fixture
contracts, vectors, compiler, and original object.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import time
from pathlib import Path

import diff_decompile as D

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
SOURCE = ROOT / "tests" / "decompiler_fixtures" / "src"
OBJECT_RE = re.compile(
    r"^(?P<fixture>.+)-(?P<compiler>gcc|clang|rustc)-"
    r"(?P<opt>O[02](?:strip)?)(?:\.dwarf)?\.so$"
)
INFRA_STATUSES = {"missing", "nocases", "timeout"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute production and shadow-v2 outputs from a pinned comparison"
    )
    parser.add_argument("comparison", type=Path)
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(4, os.cpu_count() or 1),
        help="fixture objects executed concurrently (default: up to 4)",
    )
    parser.add_argument("--output", type=Path, help="write deterministic JSON here")
    return parser


def _revision() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _source(fixture: str) -> Path:
    matches = [
        path
        for suffix in (".c", ".cpp", ".rs")
        if (path := SOURCE / f"{fixture}{suffix}").is_file()
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{fixture}: expected one fixture source, found {len(matches)}"
        )
    return matches[0]


def execution_targets(comparison: dict) -> list[dict]:
    """Extract exact object/function candidates without changing the denominator."""
    targets = []
    for obj in comparison.get("results", []):
        name = str(obj["object"])
        match = OBJECT_RE.fullmatch(name)
        if match is None:
            raise ValueError(f"unrecognized fixture object name: {name}")
        functions = sorted(
            str(row["fn"])
            for row in obj.get("functions", [])
            if row.get("shadow_gotos") is not None
            and row.get("status") != "production_missing"
        )
        if functions:
            targets.append(
                {
                    "object": name,
                    "fixture": match.group("fixture"),
                    "compiler": match.group("compiler"),
                    "opt": match.group("opt"),
                    "functions": functions,
                }
            )
    return sorted(targets, key=lambda row: row["object"])


def _status(results: dict, function: str, executable: bool = True) -> tuple[str, str]:
    if not executable:
        return "not_executable", "function is not dynamically exported"
    if "__error__" in results:
        return "infra_error", str(results["__error__"])
    row = results.get(function)
    if row is None:
        return "missing", "function absent from differential result"
    return str(row["status"]), str(row.get("detail", ""))


def execute_target(target: dict, fuzz: int) -> dict:
    """Execute one object's exact candidate functions through both structurers."""
    path = BUILD / target["object"]
    source = _source(target["fixture"])
    exported = D.exported_functions(str(path))
    executable = sorted(set(target["functions"]) & set(exported))
    common = {
        "binary": str(path),
        "source": str(source),
        "fixture": target["fixture"],
        "seed": 1234,
        "fuzz": fuzz,
        "only": set(executable),
        "lane": f"{target['compiler']}:{target['opt']}",
    }
    started = time.perf_counter()
    production = D.run(**common) if executable else {}
    production_seconds = time.perf_counter() - started
    started = time.perf_counter()
    shadow = D.run(**common, shadow_v2=True) if executable else {}
    shadow_seconds = time.perf_counter() - started

    rows = []
    for function in target["functions"]:
        is_executable = function in exported
        production_status, production_detail = _status(
            production, function, is_executable
        )
        shadow_status, shadow_detail = _status(shadow, function, is_executable)
        if not is_executable:
            comparison = "not_executable"
        elif production_status == "pass" and shadow_status != "pass":
            comparison = "regressed"
        elif production_status != "pass" and shadow_status == "pass":
            comparison = "improved"
        elif production_status == shadow_status == "pass":
            comparison = "stable_pass"
        else:
            comparison = "stable_nonpass"
        rows.append(
            {
                "fn": function,
                "comparison": comparison,
                "production_status": production_status,
                "shadow_status": shadow_status,
                "production_detail": production_detail,
                "shadow_detail": shadow_detail,
            }
        )
    return {
        "object": target["object"],
        "fixture": target["fixture"],
        "compiler": target["compiler"],
        "opt": target["opt"],
        "production_seconds": round(production_seconds, 6),
        "shadow_seconds": round(shadow_seconds, 6),
        "functions": rows,
    }


def build_report(comparison: dict, jobs: int, fuzz: int) -> dict:
    """Execute every observed shadow candidate and build deterministic totals."""
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    revision = _revision()
    if comparison.get("revision") != revision:
        raise ValueError(
            f"comparison revision {comparison.get('revision')!r} != HEAD {revision!r}"
        )
    targets = execution_targets(comparison)
    started = time.perf_counter()
    objects = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(execute_target, target, fuzz): target["object"]
            for target in targets
        }
        for future in concurrent.futures.as_completed(futures):
            objects.append(future.result())
    objects.sort(key=lambda row: row["object"])
    functions = [row for obj in objects for row in obj["functions"]]
    counts = {
        status: sum(row["comparison"] == status for row in functions)
        for status in (
            "improved",
            "stable_pass",
            "stable_nonpass",
            "regressed",
            "not_executable",
        )
    }
    infrastructure_findings = sum(
        row[side] == "infra_error" or row[side] in INFRA_STATUSES
        for row in functions
        for side in ("production_status", "shadow_status")
    )
    return {
        "revision": revision,
        "comparison_revision": comparison["revision"],
        "fuzz": fuzz,
        "objects": len(objects),
        "candidate_functions": len(functions),
        "comparison_counts": counts,
        "infrastructure_findings": infrastructure_findings,
        "production_seconds_sum": round(
            sum(obj["production_seconds"] for obj in objects), 6
        ),
        "shadow_seconds_sum": round(sum(obj["shadow_seconds"] for obj in objects), 6),
        "wall_seconds": round(time.perf_counter() - started, 6),
        "results": objects,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.jobs < 1:
        _parser().error("--jobs must be at least 1")
    comparison = json.loads(args.comparison.read_text())
    try:
        report = build_report(comparison, args.jobs, D.M.FIXTURE_FUZZ)
    except ValueError as error:
        _parser().error(str(error))
    text = json.dumps(report, indent=1) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text, end="")
    if report["infrastructure_findings"]:
        return 2
    return 1 if report["comparison_counts"]["regressed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
