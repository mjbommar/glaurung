#!/usr/bin/env python3
"""Fail-closed comparison of cold and retained runtime Axeyum profiles."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

COLD_SCHEMA = "glaurung-axeyum-native-profile-v1"
WARM_SCHEMA = "glaurung-axeyum-warm-profile-v8"
DECISIVE_OUTCOMES = {"sat", "unsat"}
COMMON_PHASES = (
    "translation_nanos",
    "word_rewrite_nanos",
    "bit_blast_nanos",
    "cnf_encode_nanos",
    "solve_nanos",
    "model_lift_nanos",
    "replay_nanos",
    "model_extract_nanos",
)
COLD_PHASES = ("arena_create_nanos", "solver_create_nanos", *COMMON_PHASES)
WARM_PHASES = ("session_create_nanos", *COMMON_PHASES, "unattributed_nanos")
HOST_SCHEMA = "glaurung-runtime-profile-host-observation-v1"
BUDGET_SCHEMA = "glaurung-runtime-axeyum-profile-budget-v1"
BUDGET_FIELDS = {
    "minimum_matched_population": int,
    "minimum_process_repetitions": int,
    "maximum_p50_relative_change_ppm": int,
    "maximum_p95_relative_change_ppm": int,
    "maximum_peak_rss_relative_change_ppm": int,
    "maximum_one_minute_load_per_logical_cpu": (int, float),
    "maximum_cpu_pressure_some_avg10": (int, float),
}


def load_measurement_metadata(path: Path, repetitions: int) -> dict[str, Any]:
    """Validate counterbalanced lane observations and summarize host load."""
    observations = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
        if not isinstance(value, dict) or value.get("schema") != HOST_SCHEMA:
            raise ValueError(f"{path}:{line_number}: invalid host observation schema")
        observations.append(value)
    expected_count = repetitions * 4
    if len(observations) != expected_count:
        raise ValueError(
            f"host observation count differs: expected={expected_count}, "
            f"actual={len(observations)}"
        )
    observed_orders = []
    expected_sequence = []
    for iteration in range(1, repetitions + 1):
        order = ["cold", "optimized"] if iteration % 2 else ["optimized", "cold"]
        for lane in order:
            expected_sequence.extend(
                ((iteration, lane, "before"), (iteration, lane, "after"))
            )
        observed_orders.append(order)
    actual_sequence = [
        (value.get("iteration"), value.get("lane"), value.get("stage"))
        for value in observations
    ]
    if actual_sequence != expected_sequence:
        for position, (actual, expected) in enumerate(
            zip(actual_sequence, expected_sequence, strict=True), 1
        ):
            if actual != expected:
                raise ValueError(
                    f"host observation {position} differs: "
                    f"expected={expected!r}, actual={actual!r}"
                )
        raise ValueError("host observation sequence differs")
    loads = []
    pressures = []
    for value in observations:
        load = value.get("load_average")
        if not isinstance(load, dict) or not isinstance(load.get("one"), (int, float)):
            raise ValueError("host observation lacks numeric one-minute load")
        loads.append(float(load["one"]))
        pressure = value.get("cpu_pressure_some")
        if pressure is not None:
            if not isinstance(pressure, dict) or not isinstance(
                pressure.get("avg10"), (int, float)
            ):
                raise ValueError("host observation has invalid CPU pressure")
            pressures.append(float(pressure["avg10"]))
    return {
        "protocol": "alternating-counterbalanced-v1",
        "lane_orders": observed_orders,
        "observations": observations,
        "one_minute_load": {"minimum": min(loads), "maximum": max(loads)},
        "cpu_pressure_some_avg10": (
            {"minimum": min(pressures), "maximum": max(pressures)}
            if pressures
            else None
        ),
    }


def load_budget(path: Path) -> dict[str, Any]:
    """Load a strict, versioned runtime Axeyum performance budget."""
    try:
        budget = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise ValueError(f"{path}: invalid budget JSON: {error}") from error
    if not isinstance(budget, dict) or budget.get("schema") != BUDGET_SCHEMA:
        raise ValueError(f"{path}: invalid performance budget schema")
    expected = {"schema", *BUDGET_FIELDS}
    if set(budget) != expected:
        raise ValueError(
            f"{path}: budget fields differ: "
            f"missing={sorted(expected - set(budget))!r}, "
            f"extra={sorted(set(budget) - expected)!r}"
        )
    for field, field_type in BUDGET_FIELDS.items():
        value = budget[field]
        if isinstance(value, bool) or not isinstance(value, field_type):
            raise ValueError(f"{path}: budget {field} has invalid type")
    if budget["minimum_matched_population"] <= 0:
        raise ValueError(f"{path}: minimum matched population must be positive")
    if budget["minimum_process_repetitions"] <= 0:
        raise ValueError(f"{path}: minimum process repetitions must be positive")
    for field in (
        "maximum_one_minute_load_per_logical_cpu",
        "maximum_cpu_pressure_some_avg10",
    ):
        if budget[field] < 0:
            raise ValueError(f"{path}: {field} must be non-negative")
    return budget


def evaluate_budget(report: dict[str, Any], budget: dict[str, Any]) -> dict[str, Any]:
    """Evaluate every budget constraint without short-circuiting failures."""
    measurement = report.get("measurement")
    if not isinstance(measurement, dict):
        raise ValueError("performance budget requires measurement metadata")
    observations = measurement.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("performance budget requires host observations")
    normalized_loads = []
    for observation in observations:
        logical_cpus = observation.get("logical_cpus")
        load = observation.get("load_average", {}).get("one")
        if (
            isinstance(logical_cpus, bool)
            or not isinstance(logical_cpus, int)
            or logical_cpus <= 0
            or isinstance(load, bool)
            or not isinstance(load, (int, float))
        ):
            raise ValueError("performance budget requires valid CPU-normalized load")
        normalized_loads.append(load / logical_cpus)
    pressure = measurement.get("cpu_pressure_some_avg10")
    if not isinstance(pressure, dict) or not isinstance(
        pressure.get("maximum"), (int, float)
    ):
        raise ValueError("performance budget requires Linux CPU pressure metadata")

    checks = []

    def check(name: str, actual: int | float, limit: int | float, kind: str) -> None:
        passed = actual >= limit if kind == "minimum" else actual <= limit
        checks.append(
            {"name": name, "actual": actual, kind: limit, "passed": passed}
        )

    check(
        "matched_population",
        report["matched_population"],
        budget["minimum_matched_population"],
        "minimum",
    )
    check(
        "process_repetitions",
        report["matched_process_repetitions"],
        budget["minimum_process_repetitions"],
        "minimum",
    )
    for name, comparison_key, budget_key in (
        ("p50_relative_change_ppm", "p50_total", "maximum_p50_relative_change_ppm"),
        ("p95_relative_change_ppm", "p95_total", "maximum_p95_relative_change_ppm"),
        (
            "peak_rss_relative_change_ppm",
            "peak_rss",
            "maximum_peak_rss_relative_change_ppm",
        ),
    ):
        try:
            actual = report["comparison"][comparison_key][
                "optimized_relative_change_ppm"
            ]
        except KeyError as error:
            raise ValueError(f"performance budget requires {comparison_key}") from error
        check(name, actual, budget[budget_key], "maximum")
    check(
        "one_minute_load_per_logical_cpu",
        max(normalized_loads),
        budget["maximum_one_minute_load_per_logical_cpu"],
        "maximum",
    )
    check(
        "cpu_pressure_some_avg10",
        pressure["maximum"],
        budget["maximum_cpu_pressure_some_avg10"],
        "maximum",
    )
    return {
        "schema": "glaurung-runtime-axeyum-profile-budget-result-v1",
        "passed": all(item["passed"] for item in checks),
        "checks": checks,
    }


def _records(paths: list[Path], schemas: set[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            raise ValueError(f"profile input is not a file: {path}")
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number}: record is not an object")
            schema = record.get("schema")
            if schema not in schemas:
                raise ValueError(
                    f"{path}:{line_number}: expected one of {sorted(schemas)!r}, "
                    f"got {schema!r}"
                )
            if record.get("complete") is not True:
                raise ValueError(f"{path}:{line_number}: incomplete Axeyum check")
            if record.get("outcome") not in DECISIVE_OUTCOMES:
                raise ValueError(
                    f"{path}:{line_number}: non-decisive outcome "
                    f"{record.get('outcome')!r}"
                )
            phases = WARM_PHASES if schema == WARM_SCHEMA else COLD_PHASES
            for field in (
                "process_id",
                "query_hash",
                "total_nanos",
                "model_values",
                *phases,
            ):
                if field not in record:
                    raise ValueError(f"{path}:{line_number}: missing {field}")
            if not isinstance(record["query_hash"], str):
                raise ValueError(f"{path}:{line_number}: query_hash is not a string")
            for field in ("process_id", "total_nanos", "model_values", *phases):
                if not isinstance(record[field], int) or record[field] < 0:
                    raise ValueError(
                        f"{path}:{line_number}: {field} is not a non-negative integer"
                    )
            records.append(record)
    if not records:
        raise ValueError(f"no records found for schemas {sorted(schemas)!r}")
    return records


def nearest_rank(values: list[int], percentile: int) -> int:
    """Return an integer percentile using the explicit nearest-rank policy."""
    if not values:
        raise ValueError("cannot calculate a percentile of an empty population")
    if not 1 <= percentile <= 100:
        raise ValueError("percentile must be in [1, 100]")
    ordered = sorted(values)
    return ordered[math.ceil(percentile * len(ordered) / 100) - 1]


def _relative_change_ppm(baseline: int, candidate: int) -> int:
    """Return signed candidate change using integer parts per million."""
    if baseline <= 0:
        raise ValueError("relative-change baseline must be positive")
    return round((candidate - baseline) * 1_000_000 / baseline)


def _identity(record: dict[str, Any]) -> tuple[str, str, bool]:
    return (
        record["query_hash"],
        record["outcome"],
        record["model_values"] > 0,
    )


def _optimized_class(record: dict[str, Any]) -> str:
    if record["schema"] == COLD_SCHEMA:
        return "singleton_cold"
    return "session_created" if record["path_created"] else "session_reused"


def _paired_queries(
    cold: list[dict[str, Any]], optimized: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    query_hashes = sorted({record["query_hash"] for record in cold})
    rows = []
    for query_hash in query_hashes:
        cold_records = [record for record in cold if record["query_hash"] == query_hash]
        optimized_records = [
            record for record in optimized if record["query_hash"] == query_hash
        ]
        classes = {_optimized_class(record) for record in optimized_records}
        if len(classes) != 1:
            raise ValueError(
                f"optimized query {query_hash} changed execution class: {sorted(classes)!r}"
            )
        cold_totals = [record["total_nanos"] for record in cold_records]
        optimized_totals = [record["total_nanos"] for record in optimized_records]
        rows.append(
            {
                "query_hash": query_hash,
                "outcome": cold_records[0]["outcome"],
                "model_producing": cold_records[0]["model_values"] > 0,
                "optimized_class": next(iter(classes)),
                "samples": len(cold_records),
                "cold_p50_total_nanos": nearest_rank(cold_totals, 50),
                "cold_p95_total_nanos": nearest_rank(cold_totals, 95),
                "optimized_p50_total_nanos": nearest_rank(optimized_totals, 50),
                "optimized_p95_total_nanos": nearest_rank(optimized_totals, 95),
            }
        )
    return rows


def _summary(records: list[dict[str, Any]], phases: tuple[str, ...]) -> dict[str, Any]:
    totals = [record["total_nanos"] for record in records]
    return {
        "checks": len(records),
        "processes": len({record["process_id"] for record in records}),
        "p50_total_nanos": nearest_rank(totals, 50),
        "p95_total_nanos": nearest_rank(totals, 95),
        "model_producing_checks": sum(record["model_values"] > 0 for record in records),
        "outcomes": dict(sorted(Counter(record["outcome"] for record in records).items())),
        "phases": {
            phase.removesuffix("_nanos"): {
                "p50_nanos": nearest_rank([record[phase] for record in records], 50),
                "p95_nanos": nearest_rank([record[phase] for record in records], 95),
            }
            for phase in phases
        },
    }


def build_report(
    cold_paths: list[Path],
    warm_paths: list[Path],
    *,
    cold_peak_rss_kib: int | None = None,
    warm_peak_rss_kib: int | None = None,
) -> dict[str, Any]:
    """Validate a matched population and return its deterministic report."""
    cold = _records(cold_paths, {COLD_SCHEMA})
    warm = _records(warm_paths, {COLD_SCHEMA, WARM_SCHEMA})
    cold_population = Counter(_identity(record) for record in cold)
    warm_population = Counter(_identity(record) for record in warm)
    if cold_population != warm_population:
        missing = list((cold_population - warm_population).elements())
        extra = list((warm_population - cold_population).elements())
        raise ValueError(
            "cold/warm Axeyum populations differ: "
            f"missing_from_warm={missing!r}, extra_in_warm={extra!r}"
        )
    cold_processes = {record["process_id"] for record in cold}
    warm_processes = {record["process_id"] for record in warm}
    if len(cold_processes) != len(warm_processes):
        raise ValueError(
            "cold/warm process repetition counts differ: "
            f"cold={len(cold_processes)}, warm={len(warm_processes)}"
        )
    warm_retained = [record for record in warm if record["schema"] == WARM_SCHEMA]
    warm_singletons = [record for record in warm if record["schema"] == COLD_SCHEMA]
    if not warm_retained:
        raise ValueError("optimized corpus contains no retained direct-delta checks")
    if any(record.get("entry_mode") != "direct_delta" for record in warm_retained):
        raise ValueError("warm corpus contains a non-direct-delta check")

    warm_summary = _summary(warm, COMMON_PHASES)
    warm_summary.update(
        {
            "singleton_cold_checks": len(warm_singletons),
            "created_sessions": sum(
                bool(record.get("path_created")) for record in warm_retained
            ),
            "reused_session_checks": sum(
                record.get("path_created") is False for record in warm_retained
            ),
            "peak_arena_terms": max(record.get("arena_terms", 0) for record in warm_retained),
            "peak_aig_nodes": max(record.get("aig_nodes", 0) for record in warm_retained),
            "peak_cnf_variables": max(
                record.get("cnf_variables", 0) for record in warm_retained
            ),
            "peak_cnf_clauses": max(
                record.get("cnf_clauses", 0) for record in warm_retained
            ),
            "peak_stable_identity_nodes": max(
                record.get("stable_identity_nodes", 0) for record in warm_retained
            ),
            "peak_stable_term_entries": max(
                record.get("stable_term_entries", 0) for record in warm_retained
            ),
            "peak_stable_assertion_entries": max(
                record.get("stable_assertion_entries", 0) for record in warm_retained
            ),
            "classes": {
                name: _summary(selected, phases)
                for name, selected, phases in (
                    ("singleton_cold", warm_singletons, COLD_PHASES),
                    (
                        "session_created",
                        [record for record in warm_retained if record["path_created"]],
                        WARM_PHASES,
                    ),
                    (
                        "session_reused",
                        [record for record in warm_retained if not record["path_created"]],
                        WARM_PHASES,
                    ),
                )
                if selected
            },
        }
    )
    report = {
        "schema": "glaurung-runtime-axeyum-profile-report-v1",
        "percentile_policy": "nearest-rank",
        "matched_population": len(cold),
        "matched_process_repetitions": len(cold_processes),
        "paired_queries": _paired_queries(cold, warm),
        "cold": _summary(cold, COLD_PHASES),
        "warm": warm_summary,
    }
    report["comparison"] = {
        percentile: {
            "optimized_minus_cold_nanos": warm_summary[field]
            - report["cold"][field],
            "optimized_relative_change_ppm": _relative_change_ppm(
                report["cold"][field], warm_summary[field]
            ),
        }
        for percentile, field in (
            ("p50_total", "p50_total_nanos"),
            ("p95_total", "p95_total_nanos"),
        )
    }
    if cold_peak_rss_kib is not None or warm_peak_rss_kib is not None:
        if not isinstance(cold_peak_rss_kib, int) or cold_peak_rss_kib <= 0:
            raise ValueError("cold peak RSS must be a positive integer")
        if not isinstance(warm_peak_rss_kib, int) or warm_peak_rss_kib <= 0:
            raise ValueError("warm peak RSS must be a positive integer")
        report["process_peak_rss_kib"] = {
            "cold": cold_peak_rss_kib,
            "warm": warm_peak_rss_kib,
        }
        report["comparison"]["peak_rss"] = {
            "optimized_minus_cold_kib": warm_peak_rss_kib - cold_peak_rss_kib,
            "optimized_relative_change_ppm": _relative_change_ppm(
                cold_peak_rss_kib, warm_peak_rss_kib
            ),
        }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cold", type=Path, action="append", required=True)
    parser.add_argument("--warm", type=Path, action="append", required=True)
    parser.add_argument("--cold-peak-rss-kib", type=int, required=True)
    parser.add_argument("--warm-peak-rss-kib", type=int, required=True)
    parser.add_argument("--glaurung-revision", required=True)
    parser.add_argument("--axeyum-revision", required=True)
    parser.add_argument("--source-state-sha256", required=True)
    parser.add_argument("--measurement-metadata", type=Path, required=True)
    parser.add_argument("--budget", type=Path)
    parser.add_argument("--dirty-worktree", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = build_report(
            args.cold,
            args.warm,
            cold_peak_rss_kib=args.cold_peak_rss_kib,
            warm_peak_rss_kib=args.warm_peak_rss_kib,
        )
        report["measurement"] = load_measurement_metadata(
            args.measurement_metadata, report["matched_process_repetitions"]
        )
    except ValueError as error:
        parser.error(str(error))
    report["implementation"] = {
        "glaurung_revision": args.glaurung_revision,
        "axeyum_revision": args.axeyum_revision,
        "dirty_worktree": args.dirty_worktree,
        "source_state_sha256": args.source_state_sha256,
        "build_profile": "release",
        "solver_authority": "axeyum-native",
    }
    if args.budget is not None:
        try:
            report["budget"] = evaluate_budget(report, load_budget(args.budget))
        except ValueError as error:
            parser.error(str(error))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        args.output.write_text(rendered)
    return 0 if report.get("budget", {}).get("passed", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
