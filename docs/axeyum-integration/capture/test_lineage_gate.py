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

    def test_parse_run_reads_replay_sat_cache_footer(self) -> None:
        warm = lineage_gate.DRIVERS["surface"].expected_warm
        warm_text = " ".join(f"{key}={value}" for key, value in warm.items())
        cache = {
            "enabled": 1,
            "max-entries": 64,
            "max-model-values": 4096,
            "max-model-bits": 262144,
            "hits": 121,
            "misses": 2430,
            "insertions": 1500,
            "evictions": 0,
            "replay-failures": 0,
            "declined-unsat": 930,
            "declined-unknown": 0,
            "declined-oversized-models": 0,
            "declined-non-scalar-models": 0,
            "entries": 0,
            "model-values": 0,
            "model-bits": 0,
        }
        cache_text = " ".join(f"{key}={value}" for key, value in cache.items())
        stderr_text = (
            "[shadow-diff] queries=2551 agree=2551 disagree=0 | "
            "SAME-STREAM z3=4409.0ms axeyum=1069.4ms speedup=4.1x\n"
            "[model-choice] both-sat=1 different-model=0 | "
            "z3-unknown=0 axeyum-unknown=0 unknown-split=0\n"
            f"[axeyum-warm] {warm_text}\n"
            f"[axeyum-sat-cache] {cache_text}\n"
        )
        time_text = (
            "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:05.74\n"
            "\tMaximum resident set size (kbytes): 83140\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stderr_path = root / "run.stderr"
            time_path = root / "run.time"
            stderr_path.write_text(stderr_text)
            time_path.write_text(time_text)
            parsed = lineage_gate.parse_run(stderr_path, time_path)
        self.assertEqual(parsed["sat_cache"], cache)

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

    def test_parse_run_reads_serial_owner_footer(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        warm_text = " ".join(
            f"{key}={value}"
            for key, value in spec.expected_adaptive_serial_warm.items()
        )
        serial_text = " ".join(
            f"{key}={value}" for key, value in spec.expected_adaptive_serial.items()
        )
        stderr_text = (
            "[shadow-diff] queries=2551 agree=2551 disagree=0 | "
            "SAME-STREAM z3=4491.4ms axeyum=369.6ms speedup=12.2x\n"
            "[model-choice] both-sat=1 different-model=0 | "
            "z3-unknown=0 axeyum-unknown=0 unknown-split=0\n"
            f"[axeyum-warm] {warm_text}\n"
            f"[axeyum-serial-owner] {serial_text}\n"
        )
        time_text = (
            "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:04.88\n"
            "\tMaximum resident set size (kbytes): 74288\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stderr_path = root / "run.stderr"
            time_path = root / "run.time"
            stderr_path.write_text(stderr_text)
            time_path.write_text(time_text)
            parsed = lineage_gate.parse_run(stderr_path, time_path)
        self.assertEqual(parsed["warm"], spec.expected_adaptive_serial_warm)
        self.assertEqual(parsed["serial"], spec.expected_adaptive_serial)

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

    def test_validate_replay_sat_cache_partitions_warm_checks(self) -> None:
        cache = {
            "enabled": 1,
            "max-entries": lineage_gate.DEFAULT_REPLAY_SAT_CACHE_ENTRIES,
            "max-model-values": (lineage_gate.DEFAULT_REPLAY_SAT_CACHE_MODEL_VALUES),
            "max-model-bits": lineage_gate.DEFAULT_REPLAY_SAT_CACHE_MODEL_BITS,
            "hits": 3,
            "misses": 7,
            "insertions": 4,
            "evictions": 0,
            "replay-failures": 0,
            "declined-unsat": 3,
            "declined-unknown": 0,
            "declined-oversized-models": 0,
            "declined-non-scalar-models": 0,
            "entries": 0,
            "model-values": 0,
            "model-bits": 0,
        }
        lineage_gate.validate_replay_sat_cache(
            cache, enabled=True, warm_checks=10, context="test"
        )
        cache["replay-failures"] = 1
        with self.assertRaisesRegex(ValueError, "replay failure"):
            lineage_gate.validate_replay_sat_cache(
                cache, enabled=True, warm_checks=10, context="test"
            )

    def test_validate_disabled_replay_sat_cache_requires_zero_traffic(self) -> None:
        cache = {
            "enabled": 0,
            "max-entries": 0,
            "max-model-values": 0,
            "max-model-bits": 0,
            "hits": 0,
            "misses": 0,
            "insertions": 0,
            "evictions": 0,
            "replay-failures": 0,
            "declined-unsat": 0,
            "declined-unknown": 0,
            "declined-oversized-models": 0,
            "declined-non-scalar-models": 0,
            "entries": 0,
            "model-values": 0,
            "model-bits": 0,
        }
        lineage_gate.validate_replay_sat_cache(
            cache, enabled=False, warm_checks=10, context="test"
        )
        cache["misses"] = 1
        with self.assertRaisesRegex(ValueError, "nonzero traffic"):
            lineage_gate.validate_replay_sat_cache(
                cache, enabled=False, warm_checks=10, context="test"
            )

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

    def test_validate_accepts_exact_adaptive_owner_transfer_partition(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        run = {
            "driver": "surface",
            "repetition": 1,
            "queries": spec.expected_queries,
            "agree": spec.expected_queries,
            "disagree": 0,
            "unknown_split": 0,
            "z3_ms": 4_366.1,
            "axeyum_ms": 446.0,
            "warm": dict(spec.expected_adaptive_transfer_warm),
            "adaptive": dict(spec.expected_adaptive_transfer),
            "max_rss_kib": 77_580,
            "stdout_sha256": "a" * 64,
        }
        summaries = lineage_gate.validate_artifact(
            {
                "schema": lineage_gate.SCHEMA,
                "policy": {
                    "warm_reuse": "adaptive",
                    "warm_owner_transfer": "on",
                },
                "repetitions": 1,
                "runs": [run],
            }
        )
        self.assertEqual(summaries["surface"]["runs"], 1)

    def test_validate_accepts_exact_adaptive_serial_partition(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        run = {
            "driver": "surface",
            "repetition": 1,
            "queries": spec.expected_queries,
            "agree": spec.expected_queries,
            "disagree": 0,
            "unknown_split": 0,
            "z3_ms": 4_491.4,
            "axeyum_ms": 369.6,
            "warm": dict(spec.expected_adaptive_serial_warm),
            "serial": dict(spec.expected_adaptive_serial),
            "max_rss_kib": 74_288,
            "stdout_sha256": "a" * 64,
        }
        summaries = lineage_gate.validate_artifact(
            {
                "schema": lineage_gate.SCHEMA,
                "policy": {
                    "warm_reuse": "adaptive",
                    "warm_owner_transfer": "on",
                    "serial_sibling_reuse": "on",
                },
                "repetitions": 1,
                "runs": [run],
            }
        )
        self.assertEqual(summaries["surface"]["runs"], 1)

    def test_validate_accepts_exact_direct_delta_partition(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        run = {
            "driver": "surface",
            "repetition": 1,
            "queries": spec.expected_queries,
            "agree": spec.expected_queries,
            "disagree": 0,
            "unknown_split": 0,
            "z3_ms": 4_410.2,
            "axeyum_ms": 399.8,
            "warm": dict(spec.expected_direct_delta_warm),
            "adaptive": dict(spec.expected_adaptive_transfer),
            "max_rss_kib": 79_464,
            "stdout_sha256": "a" * 64,
        }
        summaries = lineage_gate.validate_artifact(
            {
                "schema": lineage_gate.SCHEMA,
                "policy": {
                    "warm_reuse": "adaptive",
                    "warm_owner_transfer": "on",
                    "serial_sibling_reuse": "off",
                    "direct_delta": "on",
                },
                "repetitions": 1,
                "runs": [run],
            }
        )
        self.assertEqual(summaries["surface"]["runs"], 1)

    def test_validate_accepts_source_identity_direct_serial_partition(self) -> None:
        spec = lineage_gate.DRIVERS["surface"]
        run = {
            "driver": "surface",
            "repetition": 1,
            "queries": spec.expected_queries,
            "agree": spec.expected_queries,
            "disagree": 0,
            "unknown_split": 0,
            "z3_ms": 4_470.4,
            "axeyum_ms": 314.4,
            "warm": dict(spec.expected_direct_serial_warm),
            "serial": dict(spec.expected_adaptive_serial),
            "max_rss_kib": 73_900,
            "stdout_sha256": "a" * 64,
        }
        summaries = lineage_gate.validate_artifact(
            {
                "schema": lineage_gate.SCHEMA,
                "policy": {
                    "warm_reuse": "adaptive",
                    "warm_owner_transfer": "on",
                    "serial_sibling_reuse": "on",
                    "direct_delta": "on",
                    "direct_sibling_identity": "source-prefix-v1",
                },
                "repetitions": 1,
                "runs": [run],
            }
        )
        self.assertEqual(summaries["surface"]["runs"], 1)

    def test_validate_rejects_direct_serial_without_source_identity(self) -> None:
        artifact = {
            "schema": lineage_gate.SCHEMA,
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
                "serial_sibling_reuse": "on",
                "direct_delta": "on",
            },
            "repetitions": 1,
            "runs": [{}],
        }
        with self.assertRaisesRegex(ValueError, "source-prefix-v1"):
            lineage_gate.validate_artifact(artifact)

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

    def test_cross_policy_identity_allows_only_named_cache_enablement(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {"warm_reuse": "lineage", "replay_sat_cache": "off"},
            "repetitions": 3,
            "drivers": {"surface": {"sha256": "a" * 64}},
        }
        candidate = {
            **baseline,
            "policy": {"warm_reuse": "lineage", "replay_sat_cache": "on"},
        }
        lineage_gate.validate_comparison_identity(
            baseline,
            candidate,
            allow_lineage_to_adaptive=False,
            allow_replay_sat_cache_enablement=True,
        )
        candidate["policy"] = {
            "warm_reuse": "adaptive",
            "replay_sat_cache": "on",
        }
        with self.assertRaisesRegex(ValueError, "outside named policy"):
            lineage_gate.validate_comparison_identity(
                baseline,
                candidate,
                allow_lineage_to_adaptive=False,
                allow_replay_sat_cache_enablement=True,
            )

    def test_cross_policy_identity_allows_only_named_owner_transfer(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "off",
            },
            "repetitions": 3,
            "drivers": {
                "surface": {
                    "path": "/main/surface.sys",
                    "sha256": "a" * 64,
                    "bytes": 17,
                    "solve_budget": 100,
                }
            },
        }
        candidate = {
            **baseline,
            "drivers": {
                "surface": {
                    **baseline["drivers"]["surface"],
                    "path": "/clean-worktree/surface.sys",
                }
            },
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
            },
        }
        lineage_gate.validate_comparison_identity(
            baseline,
            candidate,
            allow_lineage_to_adaptive=False,
            allow_warm_owner_transfer_enablement=True,
        )
        candidate["policy"] = {
            "warm_reuse": "lineage",
            "warm_owner_transfer": "on",
        }
        with self.assertRaisesRegex(ValueError, "outside named policy"):
            lineage_gate.validate_comparison_identity(
                baseline,
                candidate,
                allow_lineage_to_adaptive=False,
                allow_warm_owner_transfer_enablement=True,
            )

    def test_cross_policy_identity_allows_only_named_serial_reuse(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
                "serial_sibling_reuse": "off",
            },
            "repetitions": 3,
            "drivers": {"surface": {"sha256": "a" * 64}},
        }
        candidate = {
            **baseline,
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
                "serial_sibling_reuse": "on",
            },
        }
        lineage_gate.validate_comparison_identity(
            baseline,
            candidate,
            allow_lineage_to_adaptive=False,
            allow_serial_sibling_reuse_enablement=True,
        )
        candidate["policy"] = {
            "warm_reuse": "lineage",
            "warm_owner_transfer": "on",
            "serial_sibling_reuse": "on",
        }
        with self.assertRaisesRegex(ValueError, "outside named policy"):
            lineage_gate.validate_comparison_identity(
                baseline,
                candidate,
                allow_lineage_to_adaptive=False,
                allow_serial_sibling_reuse_enablement=True,
            )

    def test_cross_policy_identity_allows_only_named_direct_delta(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
                "serial_sibling_reuse": "off",
            },
            "repetitions": 3,
            "drivers": {"surface": {"sha256": "a" * 64}},
        }
        candidate = {
            **baseline,
            "policy": {
                **baseline["policy"],
                "direct_delta": "on",
            },
        }
        lineage_gate.validate_comparison_identity(
            baseline,
            candidate,
            allow_lineage_to_adaptive=False,
            allow_direct_delta_enablement=True,
        )
        candidate["policy"] = {
            **candidate["policy"],
            "serial_sibling_reuse": "on",
        }
        with self.assertRaisesRegex(ValueError, "outside named policy"):
            lineage_gate.validate_comparison_identity(
                baseline,
                candidate,
                allow_lineage_to_adaptive=False,
                allow_direct_delta_enablement=True,
            )

    def test_cross_policy_identity_allows_serial_snapshot_to_direct(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
                "serial_sibling_reuse": "on",
                "direct_delta": "off",
            },
            "repetitions": 3,
            "drivers": {"surface": {"sha256": "a" * 64}},
        }
        candidate = {
            **baseline,
            "policy": {
                **baseline["policy"],
                "serial_sibling_reuse": "off",
                "direct_delta": "on",
            },
        }
        lineage_gate.validate_comparison_identity(
            baseline,
            candidate,
            allow_lineage_to_adaptive=False,
            allow_serial_snapshot_to_direct_delta=True,
        )
        candidate["policy"] = {
            **candidate["policy"],
            "warm_owner_transfer": "off",
        }
        with self.assertRaisesRegex(ValueError, "outside production direct"):
            lineage_gate.validate_comparison_identity(
                baseline,
                candidate,
                allow_lineage_to_adaptive=False,
                allow_serial_snapshot_to_direct_delta=True,
            )

    def test_cross_policy_identity_allows_direct_source_siblings(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
                "serial_sibling_reuse": "off",
                "direct_delta": "on",
                "direct_sibling_identity": "off",
            },
            "repetitions": 3,
            "drivers": {"surface": {"sha256": "a" * 64}},
        }
        candidate = {
            **baseline,
            "policy": {
                **baseline["policy"],
                "serial_sibling_reuse": "on",
                "direct_sibling_identity": "source-prefix-v1",
            },
        }
        lineage_gate.validate_comparison_identity(
            baseline,
            candidate,
            allow_lineage_to_adaptive=False,
            allow_direct_source_sibling_enablement=True,
        )

    def test_cross_policy_identity_allows_serial_snapshot_to_source_direct(self) -> None:
        baseline = {
            "system": {"machine": "x86_64"},
            "policy": {
                "warm_reuse": "adaptive",
                "warm_owner_transfer": "on",
                "serial_sibling_reuse": "on",
                "direct_delta": "off",
                "direct_sibling_identity": "off",
            },
            "repetitions": 3,
            "drivers": {"surface": {"sha256": "a" * 64}},
        }
        candidate = {
            **baseline,
            "policy": {
                **baseline["policy"],
                "direct_delta": "on",
                "direct_sibling_identity": "source-prefix-v1",
            },
        }
        lineage_gate.validate_comparison_identity(
            baseline,
            candidate,
            allow_lineage_to_adaptive=False,
            allow_serial_snapshot_to_source_direct=True,
        )


if __name__ == "__main__":
    unittest.main()
