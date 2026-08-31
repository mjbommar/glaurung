#!/usr/bin/env python3
"""Independently audit and merge a full-corpus DecBench result column.

This reads only the published per-function dataset, its pinned manifest, and the
per-binary ``evaluated/*.toml`` fragments.  It deliberately does not consume a
scoreboard or a previously aggregated result.  DecBench's denominator is shared:
a function is included when any decompiler has a finite value for any metric.
Adding a column can therefore change every decompiler's denominator.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import tomllib
from pathlib import Path
from typing import Any


class AuditError(ValueError):
    """The artifacts cannot support a complete, comparable score."""


FunctionKey = tuple[str, str, str, str]
BinaryKey = tuple[str, str, str]
MARKER = re.compile(r"^// Function: (\S+) @ 0x[0-9a-fA-F]+\s*$", re.MULTILINE)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise AuditError(f"expected JSON object: {path}")
    return value


def _finite(value: object) -> bool:
    return isinstance(value, (int, float)) and math.isfinite(value)


def _manifest(tree: Path) -> tuple[set[FunctionKey], set[BinaryKey], dict[str, Any]]:
    raw = _load_json(tree / "sample_set_manifest.json")
    rows = raw.get("functions")
    if not isinstance(rows, list):
        raise AuditError("manifest has no functions list")
    functions: set[FunctionKey] = set()
    for row in rows:
        key = (row["opt"], row["project"], row["binary"], row["function"])
        if key in functions:
            raise AuditError(f"duplicate manifest function: {key}")
        functions.add(key)
    binaries = {key[:3] for key in functions}

    provenance = _load_json(tree / "decbench_dataset_provenance.json")
    if provenance.get("function_count") != len(functions):
        raise AuditError("provenance function_count does not match manifest")
    if provenance.get("binary_count") != len(binaries):
        raise AuditError("provenance binary_count does not match manifest")
    return functions, binaries, provenance


def _published(
    path: Path,
) -> tuple[dict[FunctionKey, dict[str, dict[str, float]]], dict[str, Any]]:
    raw = _load_json(path)
    functions: dict[FunctionKey, dict[str, dict[str, float]]] = {}
    for group in raw.get("groups", []):
        base = (group["opt_level"], group["project"], group["binary"])
        for function in group.get("functions", []):
            key = base + (function["function"],)
            if key in functions:
                raise AuditError(f"duplicate published function: {key}")
            values = function.get("values") or {}
            functions[key] = {
                decompiler: {
                    metric: float(value)
                    for metric, value in (metric_values or {}).items()
                    if _finite(value)
                }
                for decompiler, metric_values in values.items()
            }
    return functions, raw


def _evaluated(
    tree: Path,
    column: str,
    metrics: list[str],
    expected_binaries: set[BinaryKey],
) -> dict[FunctionKey, dict[str, float]]:
    paths = sorted(tree.glob("*/*/evaluated/*.toml"))
    found_binaries = {
        (path.relative_to(tree).parts[0], path.relative_to(tree).parts[1], path.stem)
        for path in paths
    }
    if found_binaries != expected_binaries:
        missing = sorted(expected_binaries - found_binaries)[:5]
        extra = sorted(found_binaries - expected_binaries)[:5]
        raise AuditError(
            f"evaluated binary set mismatch: missing={missing}, extra={extra}"
        )

    values: dict[FunctionKey, dict[str, float]] = {}
    for path in paths:
        parts = path.relative_to(tree).parts
        binary = (parts[0], parts[1], path.stem)
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        found = 0
        for metric in metrics:
            prefix = f"{column}.{metric}.functions."
            for field, value in raw.items():
                if not field.startswith(prefix):
                    continue
                if not _finite(value):
                    raise AuditError(f"non-finite metric in {path}: {field}={value}")
                key = binary + (field[len(prefix) :],)
                metric_values = values.setdefault(key, {})
                if metric in metric_values:
                    raise AuditError(f"duplicate evaluated metric: {key} {metric}")
                metric_values[metric] = float(value)
                found += 1
        if not found:
            raise AuditError(f"evaluated result has no function metrics for {column}: {path}")
    return values


def _artifact_functions(tree: Path, column: str) -> set[FunctionKey]:
    """Read the exact function identities from the stored C artifacts."""
    paths = sorted(tree.glob(f"*/*/decompiled/{column}_*.c"))
    functions: set[FunctionKey] = set()
    for path in paths:
        parts = path.relative_to(tree).parts
        prefix = f"{column}_"
        binary_name = path.stem[len(prefix) :]
        base = (parts[0], parts[1], binary_name)
        names = MARKER.findall(path.read_text(encoding="utf-8", errors="replace"))
        if not names:
            raise AuditError(f"decompiled artifact has no function markers: {path}")
        for name in names:
            key = base + (name,)
            if key in functions:
                raise AuditError(f"duplicate decompiled function marker: {key}")
            functions.add(key)
    return functions


def audit(tree: Path, published_path: Path, column: str) -> dict[str, Any]:
    """Build a fail-closed report using DecBench's shared-denominator policy."""
    manifest, binaries, provenance = _manifest(tree)
    published, published_raw = _published(published_path)
    if set(published) != manifest:
        raise AuditError(
            "published/manifest universe mismatch: "
            f"published_only={len(set(published) - manifest)}, "
            f"manifest_only={len(manifest - set(published))}"
        )

    metrics = list(published_raw.get("metrics") or [])
    targets = published_raw.get("perfect_values") or {}
    if set(metrics) != set(targets):
        raise AuditError("metric list and perfect_values disagree")
    new_values = _evaluated(tree, column, metrics, binaries)
    outside = set(new_values) - manifest
    if outside:
        raise AuditError(f"evaluated functions outside manifest: {sorted(outside)[:5]}")
    artifact_functions = _artifact_functions(tree, column)
    evaluated_without_artifact = set(new_values) - artifact_functions
    if evaluated_without_artifact:
        raise AuditError(
            "evaluated/artifact function mismatch: evaluated without artifact="
            f"{sorted(evaluated_without_artifact)[:5]}"
        )

    published_decompilers = [
        name for name in published_raw.get("decompilers", []) if name != column
    ]
    decompilers = published_decompilers + [column]
    published_measurable: set[FunctionKey] = set()
    new_measurable = set(new_values)
    merged_measurable: set[FunctionKey] = set()
    metric_denominators = {metric: 0 for metric in metrics}
    scores = {
        name: {
            "metrics": {
                metric: {"perfect": 0, "denominator": 0} for metric in metrics
            },
            "union": {"perfect": 0, "denominator": 0},
        }
        for name in decompilers
    }

    for key in sorted(manifest):
        values = dict(published[key])
        values.pop(column, None)
        if key in new_values:
            values[column] = new_values[key]
        old_values = published[key]
        old_any = any(metric_values for metric_values in old_values.values())
        if old_any:
            published_measurable.add(key)

        measurable = {
            metric: any(metric in metric_values for metric_values in values.values())
            for metric in metrics
        }
        any_measurable = any(measurable.values())
        if any_measurable:
            merged_measurable.add(key)
        for metric in metrics:
            if measurable[metric]:
                metric_denominators[metric] += 1
        for name in decompilers:
            own = values.get(name) or {}
            for metric in metrics:
                if not measurable[metric]:
                    continue
                scores[name]["metrics"][metric]["denominator"] += 1
                if metric in own and abs(own[metric] - float(targets[metric])) < 1e-9:
                    scores[name]["metrics"][metric]["perfect"] += 1
            if any_measurable:
                scores[name]["union"]["denominator"] += 1
                if any(
                    measurable[metric]
                    and metric in own
                    and abs(own[metric] - float(targets[metric])) < 1e-9
                    for metric in metrics
                ):
                    scores[name]["union"]["perfect"] += 1

    return {
        "schema_version": 1,
        "column": column,
        "dataset_provenance": provenance,
        "metrics": metrics,
        "perfect_values": targets,
        "universe": {
            "manifest_functions": len(manifest),
            "published_measurable": len(published_measurable),
            "new_scored": len(new_measurable),
            "decompiled_functions": len(artifact_functions),
            "decompiled_without_metrics": len(artifact_functions - new_measurable),
            "new_only_measurable": len(new_measurable - published_measurable),
            "published_only_measurable": len(published_measurable - new_measurable),
            "merged_measurable": len(merged_measurable),
        },
        "metric_denominators": metric_denominators,
        "scores": scores,
    }


def render_json(report: dict[str, Any]) -> str:
    """Render deterministically for review and checksum comparison."""
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    parser.add_argument("--published", type=Path, required=True)
    parser.add_argument("--column", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        rendered = render_json(audit(args.tree, args.published, args.column))
    except (AuditError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        parser.exit(1, f"audit failed: {exc}\n")
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
