#!/usr/bin/env python3
"""Build a fail-closed, deterministic ledger from a DecBench gap report.

The input is the per-function report produced from a materialized DecBench result
tree.  Aggregates in that report are deliberately ignored: this tool recomputes
them from the rows, validates the pinned experiment manifest, and emits canonical
JSON suitable for a before/after diff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

METRICS = ("ged", "type_match", "byte_match")
JsonObject = dict[str, Any]


class LedgerError(ValueError):
    """Raised when score inputs do not match the pinned experiment contract."""


def load_json(path: Path) -> JsonObject:
    """Load a JSON object from ``path``.

    Args:
        path: JSON file to load.

    Returns:
        The decoded top-level object.

    Raises:
        LedgerError: If the file does not contain a JSON object.
    """
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise LedgerError(f"expected a JSON object in {path}")
    return value


def function_key(row: Mapping[str, Any]) -> str:
    """Return the stable identity of one evaluated function row."""
    fields = ("corpus", "project", "opt", "arch", "binary", "function")
    try:
        values = [str(row[field]) for field in fields]
    except KeyError as error:
        raise LedgerError(f"row is missing identity field {error.args[0]!r}") from error
    if any("|" in value for value in values):
        raise LedgerError("function identity fields may not contain '|'")
    return "|".join(values)


def verify_raw_package(path: Path, manifest: Mapping[str, Any]) -> None:
    """Verify the raw submission package named by the manifest.

    Args:
        path: Raw DecBench result ZIP.
        manifest: Pinned experiment manifest.

    Raises:
        LedgerError: If the package is absent or its SHA-256 differs.
    """
    if not path.is_file():
        raise LedgerError(f"raw package does not exist: {path}")
    expected = str(manifest["raw_package"]["sha256"])
    with path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    if digest != expected:
        raise LedgerError(
            f"raw package checksum mismatch: expected {expected}, got {digest}"
        )


def _metric_is_perfect(metric: str, value: float) -> bool:
    return value == (0.0 if metric == "ged" else 1.0)


def _metric_summary(rows: Sequence[Mapping[str, Any]], metric: str) -> JsonObject:
    values = [
        float(value)
        for row in rows
        if (value := row.get("glaurung", {}).get(metric)) is not None
    ]
    if not values:
        return {
            "coverage": 0,
            "missing": len(rows),
            "perfect": 0,
            "perfect_rate": None,
            "mean": None,
            "median": None,
            "zeros": 0,
        }
    perfect = sum(_metric_is_perfect(metric, value) for value in values)
    return {
        "coverage": len(values),
        "missing": len(rows) - len(values),
        "perfect": perfect,
        "perfect_rate": perfect / len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "zeros": sum(value == 0.0 for value in values),
    }


def _union_summary(rows: Sequence[Mapping[str, Any]]) -> JsonObject:
    perfect = sum(
        any(
            value is not None and _metric_is_perfect(metric, float(value))
            for metric in METRICS
            if (value := row.get("glaurung", {}).get(metric)) is not None
        )
        for row in rows
    )
    return {
        "coverage": len(rows),
        "perfect": perfect,
        "perfect_rate": perfect / len(rows) if rows else None,
    }


def _group_summary(rows: Sequence[Mapping[str, Any]]) -> JsonObject:
    return {
        "functions": len(rows),
        "metrics": {metric: _metric_summary(rows, metric) for metric in METRICS},
        "union": _union_summary(rows),
    }


def _dimension(
    rows: Sequence[Mapping[str, Any]], classifier: Callable[[Mapping[str, Any]], str]
) -> JsonObject:
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        groups.setdefault(classifier(row), []).append(row)
    return {name: _group_summary(groups[name]) for name in sorted(groups)}


def _size_bin(row: Mapping[str, Any]) -> str:
    size = int(row["size"])
    if size < 10:
        return "<10"
    if size < 50:
        return "10-49"
    if size < 100:
        return "50-99"
    if size < 250:
        return "100-249"
    return "250+"


def _head_to_head(rows: Sequence[Mapping[str, Any]]) -> JsonObject:
    competitors = sorted(
        {competitor for row in rows for competitor in row.get("published", {})}
    )
    result: JsonObject = {}
    for competitor in competitors:
        result[competitor] = {}
        for metric in METRICS:
            pairs: list[tuple[float, float]] = []
            for row in rows:
                mine = row.get("glaurung", {}).get(metric)
                other = row.get("published", {}).get(competitor, {}).get(metric)
                if mine is not None and other is not None:
                    pairs.append((float(mine), float(other)))
            higher_is_better = metric != "ged"
            better = sum((a > b) if higher_is_better else (a < b) for a, b in pairs)
            worse = sum((a < b) if higher_is_better else (a > b) for a, b in pairs)
            result[competitor][metric] = {
                "coverage": len(pairs),
                "better": better,
                "equal": len(pairs) - better - worse,
                "worse": worse,
                "glaurung_mean": statistics.fmean(a for a, _ in pairs)
                if pairs
                else None,
                "other_mean": statistics.fmean(b for _, b in pairs) if pairs else None,
            }
    return result


def _ranked_canary_keys(
    rows: Sequence[Mapping[str, Any]], metric: str, count: int = 40
) -> list[str]:
    def gap(row: Mapping[str, Any]) -> float:
        mine = row.get("glaurung", {}).get(metric)
        best = row.get("best_other", {}).get(metric)
        if mine is None or best is None:
            return float("-inf")
        return (
            float(mine) - float(best) if metric == "ged" else float(best) - float(mine)
        )

    eligible = [row for row in rows if gap(row) != float("-inf")]
    eligible.sort(key=lambda row: (-gap(row), function_key(row)))
    return [function_key(row) for row in eligible[:count]]


def derive_canaries(rows: Sequence[Mapping[str, Any]]) -> JsonObject:
    """Derive the immutable baseline canary identities from scored rows."""
    perfect = sorted(
        function_key(row)
        for row in rows
        if any(
            value is not None and _metric_is_perfect(metric, float(value))
            for metric in METRICS
            if (value := row.get("glaurung", {}).get(metric)) is not None
        )
    )
    return {
        "worst_ged": _ranked_canary_keys(rows, "ged"),
        "worst_type_match": _ranked_canary_keys(rows, "type_match"),
        "worst_byte_match": _ranked_canary_keys(rows, "byte_match"),
        "current_perfect": perfect,
    }


def _require_equal(name: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        raise LedgerError(f"{name} mismatch: expected {expected!r}, got {actual!r}")


def _validate_provenance(
    report: Mapping[str, Any], manifest: Mapping[str, Any]
) -> None:
    actual = report.get("provenance")
    expected = manifest.get("revisions")
    if not isinstance(actual, dict) or not isinstance(expected, dict):
        raise LedgerError("provenance must be an object")
    # Glaurung is the independent variable. Everything that defines the corpus
    # and scoring semantics must remain pinned across before/after runs.
    for name in ("dataset", "decbench", "functions"):
        _require_equal(f"provenance {name}", actual.get(name), expected.get(name))


def _validated_rows(
    report: Mapping[str, Any], manifest: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    _validate_provenance(report, manifest)
    _require_equal(
        "metric schema", report.get("metric_schema"), manifest.get("metric_schema")
    )
    raw_rows = report.get("rows")
    if not isinstance(raw_rows, list) or not all(
        isinstance(row, dict) for row in raw_rows
    ):
        raise LedgerError("report rows must be an array of objects")
    rows: list[Mapping[str, Any]] = raw_rows
    keys = [function_key(row) for row in rows]
    if len(keys) != len(set(keys)):
        raise LedgerError("report contains duplicate function keys")
    expected_keys = manifest.get("function_keys")
    if not isinstance(expected_keys, list) or not all(
        isinstance(key, str) for key in expected_keys
    ):
        raise LedgerError("manifest function_keys must be an array of strings")
    if len(expected_keys) != len(set(expected_keys)):
        raise LedgerError("manifest contains duplicate function keys")
    if set(keys) != set(expected_keys):
        missing = sorted(set(expected_keys or []) - set(keys))
        extra = sorted(set(keys) - set(expected_keys or []))
        raise LedgerError(
            f"function key mismatch: missing={missing[:3]!r}, extra={extra[:3]!r}, "
            f"expected={len(expected_keys or [])}, actual={len(keys)}"
        )
    return sorted(rows, key=function_key)


def _canary_results(
    rows: Sequence[Mapping[str, Any]], manifest: Mapping[str, Any]
) -> JsonObject:
    by_key = {function_key(row): row for row in rows}
    result: JsonObject = {}
    canaries = manifest.get("canaries")
    if not isinstance(canaries, dict):
        raise LedgerError("manifest canaries must be an object")
    for name, raw_keys in sorted(canaries.items()):
        if not isinstance(raw_keys, list) or not all(
            isinstance(key, str) for key in raw_keys
        ):
            raise LedgerError(f"canary set {name!r} must be an array of keys")
        unknown = [key for key in raw_keys if key not in by_key]
        if unknown:
            raise LedgerError(f"canary set {name!r} has unknown keys: {unknown[:3]!r}")
        result[name] = [
            {"key": key, "metrics": dict(by_key[key].get("glaurung", {}))}
            for key in raw_keys
        ]
    return result


def build_ledger(report: Mapping[str, Any], manifest: Mapping[str, Any]) -> JsonObject:
    """Validate inputs and recompute the complete DecBench score ledger.

    Args:
        report: Per-function gap-analysis rows.
        manifest: Pinned experiment contract.

    Returns:
        A deterministic JSON-compatible score ledger.

    Raises:
        LedgerError: If any revision, schema, identity, or canary differs.
    """
    rows = _validated_rows(report, manifest)
    return {
        "schema_version": 1,
        "baseline_revision": manifest["revisions"]["glaurung"],
        "revisions": report["provenance"],
        "metric_schema": manifest["metric_schema"],
        "tools": manifest["tools"],
        "raw_package": manifest["raw_package"],
        "functions": len(rows),
        "metrics": {metric: _metric_summary(rows, metric) for metric in METRICS},
        "union": _union_summary(rows),
        "dimensions": {
            "arch": _dimension(rows, lambda row: str(row["arch"])),
            "opt": _dimension(rows, lambda row: str(row["opt"])),
            "cfg_size": _dimension(rows, _size_bin),
        },
        "head_to_head": _head_to_head(rows),
        "canaries": _canary_results(rows, manifest),
    }


def check_baseline(ledger: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    """Require a ledger to reproduce the pinned baseline headline exactly.

    Args:
        ledger: Recomputed score ledger.
        manifest: Pinned experiment manifest.

    Raises:
        LedgerError: If the Glaurung revision or a headline count differs.
    """
    expected = manifest["expected_baseline"]
    actual = {
        "functions": ledger["functions"],
        "ged_perfect": ledger["metrics"]["ged"]["perfect"],
        "type_match_perfect": ledger["metrics"]["type_match"]["perfect"],
        "byte_match_perfect": ledger["metrics"]["byte_match"]["perfect"],
        "union_perfect": ledger["union"]["perfect"],
    }
    _require_equal("baseline headline", actual, expected)
    _require_equal(
        "baseline Glaurung revision",
        ledger["revisions"]["glaurung"],
        manifest["revisions"]["glaurung"],
    )


def render_json(ledger: Mapping[str, Any]) -> str:
    """Render a ledger as canonical, byte-stable JSON."""
    return (
        json.dumps(ledger, sort_keys=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis", type=Path, help="per-function gap-analysis JSON")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--raw-package", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--check-baseline",
        action="store_true",
        help="require the pinned revision and headline counts",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """Run the score-ledger command-line interface."""
    args = _parser().parse_args(argv)
    manifest = load_json(args.manifest)
    if args.raw_package is not None:
        verify_raw_package(args.raw_package, manifest)
    ledger = build_ledger(load_json(args.analysis), manifest)
    if args.check_baseline:
        check_baseline(ledger, manifest)
    output = render_json(ledger)
    if args.output is None:
        print(output, end="")
    else:
        args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
