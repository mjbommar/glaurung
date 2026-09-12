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
from glaurung._native import metrics

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
INVENTORY = ROOT / "tests" / "open_defects" / "known_failures.json"
SOURCE = ROOT / "tests" / "decompiler_fixtures" / "src"
GOTO_RE = re.compile(r"\bgoto\s+\w+\s*;")
GOTO_TARGET_RE = re.compile(r"\bgoto\s+(\w+)\s*;")
LABEL_RE = re.compile(r"(?m)^\s*(\w+)\s*:(?!:)")
SWITCH_RE = re.compile(r"(?m)^\s*switch\s*\(")

# These are exact shadow-v2 comparison rows, not general fixture waivers.  Each
# property has real-fixture Rust coverage plus execution-differential and
# control-flow evidence in the WP4 report.  The classifier below additionally
# fails closed unless the rendered candidate still has a switch, direct
# transfers, and definitions for every transfer target.
SHADOW_HONEST_GOTO_CONTRACTS: dict[tuple[str, str], str] = {
    (
        "102_duffs_device-gcc-O2.so",
        "duff_copy",
    ): "verified_switch_suffix_entry_shared_region",
    (
        "102_duffs_device-gcc-O2strip.dwarf.so",
        "duff_copy",
    ): "verified_switch_suffix_entry_shared_region",
    (
        "154_wide_switch-clang-O2.so",
        "wide154_dense_effects",
    ): "verified_switch_shared_effect_entry",
    (
        "154_wide_switch-clang-O2strip.dwarf.so",
        "wide154_dense_effects",
    ): "verified_switch_shared_effect_entry",
}


def _honest_goto_property(
    name: str, function: str, status: str, text: str | None
) -> str | None:
    """Return independently reviewed residual-goto evidence, or fail closed."""
    property_name = SHADOW_HONEST_GOTO_CONTRACTS.get((name, function))
    if property_name is None or status != "regressed" or text is None:
        return None
    targets = set(GOTO_TARGET_RE.findall(text))
    labels = set(LABEL_RE.findall(text))
    if not targets or not SWITCH_RE.search(text) or not targets <= labels:
        return None
    return property_name


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


def _source_skeletons(object_name: str) -> dict:
    """Return C source skeletons for one fixture object, or an empty map."""
    fixture = object_name.split("-", 1)[0]
    source = SOURCE / f"{fixture}.c"
    return (
        metrics.skeletons(source.read_text(encoding="utf-8"))
        if source.is_file()
        else {}
    )


def _structure_cell(
    source, production: str | None, shadow: str | None, function: str
) -> dict:
    """Compare production and shadow on one explicit source-relative denominator."""
    if source is None:
        return {"status": "no_c_source"}
    base = {"source_nodes": len(source)}
    if production is None:
        return {**base, "status": "production_missing"}
    if shadow is None:
        return {**base, "status": "shadow_declined"}
    production_tree = metrics.skeletons(production).get(function)
    if production_tree is None:
        return {**base, "status": "production_unparsed"}
    shadow_tree = metrics.skeletons(shadow).get(function)
    if shadow_tree is None:
        return {**base, "status": "shadow_unparsed"}
    production_distance = metrics.tree_edit_distance(source, production_tree)
    shadow_distance = metrics.tree_edit_distance(source, shadow_tree)
    if production_distance is None or shadow_distance is None:
        return {
            **base,
            "status": "abstained",
            "production_nodes": len(production_tree),
            "shadow_nodes": len(shadow_tree),
        }
    delta = shadow_distance - production_distance
    return {
        **base,
        "status": "scored",
        "production_nodes": len(production_tree),
        "shadow_nodes": len(shadow_tree),
        "production_distance": production_distance,
        "shadow_distance": shadow_distance,
        "delta": delta,
        "movement": "improved"
        if delta < 0
        else "regressed"
        if delta > 0
        else "unchanged",
    }


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
    source_skeletons = _source_skeletons(name)

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
        property_name = _honest_goto_property(
            name, row_by_va[va]["fn"], status, candidate
        )
        comparisons.append(
            {
                "fn": row_by_va[va]["fn"],
                "va": va,
                "status": status,
                "classification": (
                    "accepted_honest_goto" if property_name is not None else None
                ),
                "classification_property": property_name,
                "production_gotos": baseline_gotos,
                "shadow_gotos": candidate_gotos,
                "production_bytes": len((baseline or "").encode()),
                "shadow_bytes": len(candidate.encode())
                if candidate is not None
                else None,
                "structure": _structure_cell(
                    source_skeletons.get(row_by_va[va]["fn"]),
                    baseline,
                    candidate,
                    row_by_va[va]["fn"],
                ),
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
    classification_counts = {
        "accepted_honest_goto": sum(
            function["classification"] == "accepted_honest_goto"
            for function in functions
        ),
        "unexplained_regression": sum(
            function["status"] == "regressed" and function["classification"] is None
            for function in functions
        ),
    }
    comparable = [
        function
        for function in functions
        if function["shadow_gotos"] is not None
        and function["status"] != "production_missing"
    ]
    structure_cells = [function.get("structure", {}) for function in functions]
    scored_structure = [
        cell for cell in structure_cells if cell.get("status") == "scored"
    ]
    structure_status_counts = {
        status: sum(cell.get("status") == status for cell in structure_cells)
        for status in (
            "scored",
            "no_c_source",
            "production_missing",
            "shadow_declined",
            "production_unparsed",
            "shadow_unparsed",
            "abstained",
        )
    }
    structure_movement_counts = {
        movement: sum(cell.get("movement") == movement for cell in scored_structure)
        for movement in ("improved", "unchanged", "regressed")
    }
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
        "classification_counts": classification_counts,
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
        "structure_axis": {
            "status_counts": structure_status_counts,
            "movement_counts": structure_movement_counts,
            "production_distance_total": sum(
                cell["production_distance"] for cell in scored_structure
            ),
            "shadow_distance_total": sum(
                cell["shadow_distance"] for cell in scored_structure
            ),
        },
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
