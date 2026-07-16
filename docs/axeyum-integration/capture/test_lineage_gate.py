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


if __name__ == "__main__":
    unittest.main()
