#!/usr/bin/env python3
"""Focused tests for lineage_gate.py's fail-closed parsing and invariants."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("lineage_gate.py")
SPEC = importlib.util.spec_from_file_location("lineage_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
lineage_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lineage_gate
SPEC.loader.exec_module(lineage_gate)


class LineageGateTests(unittest.TestCase):
    def test_parse_run_reads_exact_footers(self) -> None:
        warm = lineage_gate.DRIVERS["surface"].expected_warm
        warm_text = " ".join(f"{key}={value}" for key, value in warm.items())
        stderr_text = (
            "[shadow-diff] queries=2551 agree=2551 disagree=0 | "
            "SAME-STREAM z3=4409.0ms axeyum=1069.4ms speedup=4.1x\n"
            "[model-choice] both-sat=1 different-model=0 | "
            "z3-unknown=0 axeyum-unknown=0 unknown-split=0\n"
            f"[axeyum-warm] {warm_text}\n"
        )
        time_text = (
            "\tElapsed (wall clock) time (h:mm:ss or m:ss): 1:19.22\n"
            "\tMaximum resident set size (kbytes): 83140\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stderr_path = root / "run.stderr"
            time_path = root / "run.time"
            stderr_path.write_text(stderr_text)
            time_path.write_text(time_text)
            parsed = lineage_gate.parse_run(stderr_path, time_path)
        self.assertEqual(parsed["queries"], 2_551)
        self.assertEqual(parsed["warm"], warm)
        self.assertEqual(parsed["wall_seconds"], 79.22)
        self.assertEqual(parsed["max_rss_kib"], 83_140)

    def test_parse_run_reads_auto_admission_footer(self) -> None:
        warm = lineage_gate.DRIVERS["surface"].expected_auto_warm
        warm_text = " ".join(f"{key}={value}" for key, value in warm.items())
        stderr_text = (
            "[shadow-diff] queries=2551 agree=2551 disagree=0 | "
            "SAME-STREAM z3=4362.3ms axeyum=1154.4ms speedup=3.8x\n"
            "[model-choice] both-sat=1 different-model=0 | "
            "z3-unknown=0 axeyum-unknown=0 unknown-split=0\n"
            f"[axeyum-warm] {warm_text}\n"
            "[axeyum-auto] probes=358 activations=191\n"
        )
        time_text = (
            "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:05.74\n"
            "\tMaximum resident set size (kbytes): 65136\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stderr_path = root / "run.stderr"
            time_path = root / "run.time"
            stderr_path.write_text(stderr_text)
            time_path.write_text(time_text)
            parsed = lineage_gate.parse_run(stderr_path, time_path)
        self.assertEqual(parsed["warm"], warm)
        self.assertEqual(parsed["auto"], {"probes": 358, "activations": 191})

    def test_parse_run_reads_adaptive_pressure_footer(self) -> None:
        warm = lineage_gate.DRIVERS["surface"].expected_adaptive_warm
        warm_text = " ".join(f"{key}={value}" for key, value in warm.items())
        stderr_text = (
            "[shadow-diff] queries=2551 agree=2551 disagree=0 | "
            "SAME-STREAM z3=4437.5ms axeyum=1095.4ms speedup=4.1x\n"
            "[model-choice] both-sat=1 different-model=0 | "
            "z3-unknown=0 axeyum-unknown=0 unknown-split=0\n"
            f"[axeyum-warm] {warm_text}\n"
            "[axeyum-adaptive] pressure-events=87 expansions=0 "
            "initial-live-paths=2 pressure-threshold=128\n"
        )
        time_text = (
            "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:05.80\n"
            "\tMaximum resident set size (kbytes): 81212\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stderr_path = root / "run.stderr"
            time_path = root / "run.time"
            stderr_path.write_text(stderr_text)
            time_path.write_text(time_text)
            parsed = lineage_gate.parse_run(stderr_path, time_path)
        self.assertEqual(parsed["warm"], warm)
        self.assertEqual(
            parsed["adaptive"],
            {
                "pressure-events": 87,
                "expansions": 0,
                "initial-live-paths": 2,
                "pressure-threshold": 128,
            },
        )

    def test_validate_accepts_exact_repetitions(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        runs = []
        for repetition, axeyum_ms in enumerate((1_064.3, 1_071.5, 1_072.4), 1):
            runs.append(
                {
                    "driver": "surface",
                    "repetition": repetition,
                    "queries": spec.expected_queries,
                    "agree": spec.expected_queries,
                    "disagree": 0,
                    "unknown_split": 0,
                    "z3_ms": 4_409.0,
                    "axeyum_ms": axeyum_ms,
                    "warm": dict(spec.expected_warm),
                    "max_rss_kib": 83_140,
                    "wall_seconds": 6.0,
                    "stdout_sha256": "a" * 64,
                }
            )
        summaries = lineage_gate.validate_artifact(
            {"schema": lineage_gate.SCHEMA, "repetitions": 3, "runs": runs}
        )
        self.assertAlmostEqual(summaries["surface"]["axeyum_mean_ms"], 1_069.4)

    def test_validate_rejects_traffic_drift(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        warm = dict(spec.expected_warm)
        warm["added"] += 1
        artifact = {
            "schema": lineage_gate.SCHEMA,
            "repetitions": 1,
            "runs": [
                {
                    "driver": "surface",
                    "repetition": 1,
                    "queries": spec.expected_queries,
                    "agree": spec.expected_queries,
                    "disagree": 0,
                    "unknown_split": 0,
                    "z3_ms": 1.0,
                    "axeyum_ms": 1.0,
                    "warm": warm,
                    "max_rss_kib": 1,
                    "stdout_sha256": "a" * 64,
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "warm traffic drift"):
            lineage_gate.validate_artifact(artifact)

    def test_validate_accepts_exact_auto_partition(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        run = {
            "driver": "surface",
            "repetition": 1,
            "queries": spec.expected_queries,
            "agree": spec.expected_queries,
            "disagree": 0,
            "unknown_split": 0,
            "z3_ms": 4_362.3,
            "axeyum_ms": 1_154.4,
            "warm": dict(spec.expected_auto_warm),
            "auto": dict(spec.expected_auto),
            "max_rss_kib": 65_136,
            "stdout_sha256": "a" * 64,
        }
        summaries = lineage_gate.validate_artifact(
            {
                "schema": lineage_gate.SCHEMA,
                "policy": {"warm_reuse": "auto"},
                "repetitions": 1,
                "runs": [run],
            }
        )
        self.assertEqual(summaries["surface"]["runs"], 1)

    def test_validate_accepts_exact_adaptive_partition(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        run = {
            "driver": "surface",
            "repetition": 1,
            "queries": spec.expected_queries,
            "agree": spec.expected_queries,
            "disagree": 0,
            "unknown_split": 0,
            "z3_ms": 4_437.5,
            "axeyum_ms": 1_095.4,
            "warm": dict(spec.expected_adaptive_warm),
            "adaptive": dict(spec.expected_adaptive),
            "max_rss_kib": 81_212,
            "stdout_sha256": "a" * 64,
        }
        summaries = lineage_gate.validate_artifact(
            {
                "schema": lineage_gate.SCHEMA,
                "policy": {"warm_reuse": "adaptive"},
                "repetitions": 1,
                "runs": [run],
            }
        )
        self.assertEqual(summaries["surface"]["runs"], 1)

    def test_thresholds_distinguish_regression_from_environment_drift(self) -> None:
        comparison = {
            "surface": {
                "axeyum_change": 0.031,
                "ratio_change": 0.01,
                "median_rss_change": 0.051,
                "z3_change": -0.021,
            }
        }
        violations = lineage_gate.threshold_violations(
            comparison,
            max_axeyum=0.03,
            max_ratio=0.03,
            max_rss=0.05,
            max_z3_drift=0.02,
        )
        self.assertEqual(len(violations), 3)
        self.assertTrue(any("axeyum" in violation for violation in violations))
        self.assertTrue(any("median-rss" in violation for violation in violations))
        self.assertTrue(any("z3-drift" in violation for violation in violations))

    def test_cross_policy_identity_allows_only_lineage_to_adaptive(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {"warm_reuse": "lineage", "max_live_paths": 9},
            "repetitions": 3,
            "drivers": {"surface": {"sha256": "a" * 64}},
        }
        candidate = {
            **baseline,
            "policy": {"warm_reuse": "adaptive", "max_live_paths": 9},
        }
        lineage_gate.validate_comparison_identity(
            baseline, candidate, allow_lineage_to_adaptive=True
        )
        candidate["policy"] = {"warm_reuse": "auto", "max_live_paths": 9}
        with self.assertRaisesRegex(ValueError, "lineage.*adaptive"):
            lineage_gate.validate_comparison_identity(
                baseline, candidate, allow_lineage_to_adaptive=True
            )


if __name__ == "__main__":
    unittest.main()
