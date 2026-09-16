from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "tools" / "runtime_sample_harness.py"
SPEC = importlib.util.spec_from_file_location("runtime_sample_harness", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def test_runtime_corpus_has_balanced_real_sources() -> None:
    samples = HARNESS.load_samples()
    assert len(samples) == 60
    assert {sample.category for sample in samples} == {
        "normal",
        "crash",
        "memory_corruption",
        "dangerous",
    }
    for category in {sample.category for sample in samples}:
        assert sum(sample.category == category for sample in samples) == 15
    assert len({sample.source.read_bytes() for sample in samples}) == 60


def test_runtime_manifest_has_paired_outcome_oracles() -> None:
    for sample in HARNESS.load_samples():
        assert sample.good == "good"
        assert sample.bad == "bad"
        assert sample.expected_good == "exit:0"
        assert sample.expected_bad.startswith(("exit:", "signal:"))
        if sample.category == "crash":
            assert sample.expected_bad.startswith("signal:")


def test_environment_inventory_never_persists_plaintext_values() -> None:
    inventory = HARNESS.environment_inventory(b"TOKEN=secret-value\0EMPTY=\0")
    assert [entry["name"] for entry in inventory] == ["EMPTY", "TOKEN"]
    assert "secret-value" not in repr(inventory)
    assert inventory[1]["value_size"] == len("secret-value")


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_build_and_run_real_control_and_crash(tmp_path: Path) -> None:
    samples = {sample.id: sample for sample in HARNESS.load_samples()}
    normal = samples["normal_open_file"]
    crash = samples["crash_null_write"]
    normal_binary = HARNESS.compile_sample(normal, "gcc", "O2", "pie", tmp_path)
    crash_binary = HARNESS.compile_sample(crash, "gcc", "O2", "pie", tmp_path)
    good = HARNESS.run_one(normal_binary, normal, "good", 5.0)
    bad = HARNESS.run_one(crash_binary, crash, "bad", 5.0)
    assert HARNESS.observed_outcome(good) == normal.expected_good
    assert HARNESS.observed_outcome(bad) == crash.expected_bad


@pytest.mark.skipif(not Path("/proc/self/maps").exists(), reason="requires Linux procfs")
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_live_capture_records_real_proc_metadata(tmp_path: Path) -> None:
    sample = next(
        sample for sample in HARNESS.load_samples() if sample.id == "normal_heap_lifecycle"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = HARNESS.capture_live(binary, sample, "bad", tmp_path, 5.0)
    assert (capture / "manifest.json").is_file()
    assert (capture / "maps").read_text()
    assert (capture / "status").read_text()


@pytest.mark.skipif(not Path("/proc/self/maps").exists(), reason="requires Linux procfs")
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_entry_capture_can_stop_a_crashing_scenario(tmp_path: Path) -> None:
    sample = next(
        sample for sample in HARNESS.load_samples() if sample.id == "crash_null_write"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O2", "pie", tmp_path)
    capture = HARNESS.capture_live(binary, sample, "bad", tmp_path, 5.0, "entry")
    assert (capture / "manifest.json").is_file()
    assert "crash_null_write" in (capture / "cmdline").read_text()
