from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "tools" / "axeyum" / "runtime_profile_report.py"
SPEC = importlib.util.spec_from_file_location("runtime_profile_report", REPORT_PATH)
assert SPEC is not None and SPEC.loader is not None
REPORT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REPORT
SPEC.loader.exec_module(REPORT)


def profile_record(*, warm: bool, query: str, outcome: str = "sat") -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": REPORT.WARM_SCHEMA if warm else REPORT.COLD_SCHEMA,
        "complete": True,
        "process_id": 17,
        "query_hash": query,
        "outcome": outcome,
        "model_values": 1 if outcome == "sat" else 0,
        "total_nanos": 100 if warm else 200,
        "arena_terms": 10,
        "aig_nodes": 11,
        "cnf_variables": 12,
        "cnf_clauses": 13,
    }
    phases = REPORT.WARM_PHASES if warm else REPORT.COLD_PHASES
    record.update({phase: 1 for phase in phases})
    if warm:
        record.update(
            {
                "entry_mode": "direct_delta",
                "path_created": True,
                "stable_identity_nodes": 8,
                "stable_term_entries": 7,
                "stable_assertion_entries": 2,
            }
        )
    return record


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def test_report_requires_exact_matched_axeyum_population(tmp_path: Path) -> None:
    cold_path = tmp_path / "cold.jsonl"
    warm_path = tmp_path / "warm.jsonl"
    write_jsonl(cold_path, [profile_record(warm=False, query="sha256:a")])
    write_jsonl(warm_path, [profile_record(warm=True, query="sha256:a")])

    report = REPORT.build_report(
        [cold_path], [warm_path], cold_peak_rss_kib=100, warm_peak_rss_kib=90
    )

    assert report["matched_population"] == 1
    assert report["matched_process_repetitions"] == 1
    assert report["cold"]["p95_total_nanos"] == 200
    assert report["warm"]["p95_total_nanos"] == 100
    assert report["warm"]["peak_cnf_clauses"] == 13
    assert report["warm"]["classes"]["session_created"]["checks"] == 1
    assert report["process_peak_rss_kib"] == {"cold": 100, "warm": 90}
    assert report["comparison"] == {
        "p50_total": {
            "optimized_minus_cold_nanos": -100,
            "optimized_relative_change_ppm": -500_000,
        },
        "p95_total": {
            "optimized_minus_cold_nanos": -100,
            "optimized_relative_change_ppm": -500_000,
        },
        "peak_rss": {
            "optimized_minus_cold_kib": -10,
            "optimized_relative_change_ppm": -100_000,
        },
    }


def test_report_rejects_verdict_or_model_population_drift(tmp_path: Path) -> None:
    cold_path = tmp_path / "cold.jsonl"
    warm_path = tmp_path / "warm.jsonl"
    write_jsonl(cold_path, [profile_record(warm=False, query="sha256:a")])
    write_jsonl(
        warm_path,
        [profile_record(warm=True, query="sha256:a", outcome="unsat")],
    )

    with pytest.raises(ValueError, match="populations differ"):
        REPORT.build_report([cold_path], [warm_path])


def test_report_rejects_incomplete_or_unknown_checks(tmp_path: Path) -> None:
    cold_path = tmp_path / "cold.jsonl"
    warm_path = tmp_path / "warm.jsonl"
    cold = profile_record(warm=False, query="sha256:a")
    cold["complete"] = False
    write_jsonl(cold_path, [cold])
    write_jsonl(warm_path, [profile_record(warm=True, query="sha256:a")])

    with pytest.raises(ValueError, match="incomplete Axeyum check"):
        REPORT.build_report([cold_path], [warm_path])


def test_report_accepts_cold_singletons_in_the_optimized_lane(tmp_path: Path) -> None:
    cold_path = tmp_path / "cold.jsonl"
    optimized_path = tmp_path / "optimized.jsonl"
    cold = [
        profile_record(warm=False, query="sha256:singleton"),
        profile_record(warm=False, query="sha256:shared", outcome="unsat"),
    ]
    optimized_singleton = profile_record(warm=False, query="sha256:singleton")
    optimized_retained = profile_record(
        warm=True, query="sha256:shared", outcome="unsat"
    )
    write_jsonl(cold_path, cold)
    write_jsonl(optimized_path, [optimized_singleton, optimized_retained])

    report = REPORT.build_report([cold_path], [optimized_path])

    assert report["matched_population"] == 2
    assert report["warm"]["singleton_cold_checks"] == 1
    assert report["warm"]["classes"]["singleton_cold"]["checks"] == 1
    assert report["paired_queries"][1]["optimized_class"] == "singleton_cold"


def test_nearest_rank_policy_is_explicit() -> None:
    assert REPORT.nearest_rank(list(range(1, 21)), 50) == 10
    assert REPORT.nearest_rank(list(range(1, 21)), 95) == 19


def test_measurement_metadata_requires_counterbalanced_lane_order(
    tmp_path: Path,
) -> None:
    path = tmp_path / "host.jsonl"
    observations = []
    for iteration, lanes in ((1, ("cold", "optimized")), (2, ("optimized", "cold"))):
        for lane in lanes:
            for stage in ("before", "after"):
                observations.append(
                    {
                        "schema": REPORT.HOST_SCHEMA,
                        "iteration": iteration,
                        "lane": lane,
                        "stage": stage,
                        "load_average": {"one": 2.0, "five": 3.0, "fifteen": 4.0},
                        "cpu_pressure_some": {"avg10": 1.0},
                    }
                )
    write_jsonl(path, observations)

    metadata = REPORT.load_measurement_metadata(path, 2)

    assert metadata["protocol"] == "alternating-counterbalanced-v1"
    assert metadata["lane_orders"] == [
        ["cold", "optimized"],
        ["optimized", "cold"],
    ]
    observations[4]["lane"] = "cold"
    write_jsonl(path, observations)
    with pytest.raises(ValueError, match="host observation 5 differs"):
        REPORT.load_measurement_metadata(path, 2)


def test_performance_budget_fails_closed_on_every_regression(tmp_path: Path) -> None:
    cold_path = tmp_path / "cold.jsonl"
    warm_path = tmp_path / "warm.jsonl"
    write_jsonl(cold_path, [profile_record(warm=False, query="sha256:a")])
    write_jsonl(warm_path, [profile_record(warm=True, query="sha256:a")])
    report = REPORT.build_report(
        [cold_path], [warm_path], cold_peak_rss_kib=100, warm_peak_rss_kib=110
    )
    report["measurement"] = {
        "observations": [
            {
                "logical_cpus": 4,
                "load_average": {"one": 6.0},
            }
        ],
        "cpu_pressure_some_avg10": {"maximum": 3.0},
    }
    budget = {
        "schema": REPORT.BUDGET_SCHEMA,
        "minimum_matched_population": 2,
        "minimum_process_repetitions": 2,
        "maximum_p50_relative_change_ppm": -400_000,
        "maximum_p95_relative_change_ppm": -400_000,
        "maximum_peak_rss_relative_change_ppm": 50_000,
        "maximum_one_minute_load_per_logical_cpu": 1.0,
        "maximum_cpu_pressure_some_avg10": 2.0,
    }

    result = REPORT.evaluate_budget(report, budget)

    assert result["passed"] is False
    assert [check["name"] for check in result["checks"] if not check["passed"]] == [
        "matched_population",
        "process_repetitions",
        "peak_rss_relative_change_ppm",
        "one_minute_load_per_logical_cpu",
        "cpu_pressure_some_avg10",
    ]


def test_performance_budget_schema_rejects_missing_threshold(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    path.write_text(json.dumps({"schema": REPORT.BUDGET_SCHEMA}))

    with pytest.raises(ValueError, match="budget fields differ"):
        REPORT.load_budget(path)
