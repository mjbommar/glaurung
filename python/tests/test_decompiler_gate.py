"""The decompiler gate exposes honest, non-overlapping evidence profiles."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
GATE = ROOT / "scripts" / "decompiler-gate.sh"
BUILD_GUARD = ROOT / "tools" / "build_guard.py"
METRIC_CHECKOUT_ENV = "DECBENCH" + "_DIR"


def gate_plan(
    profile: str,
    option: str = "--print-plan",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Print one profile without executing its expensive commands."""
    return subprocess.run(
        [str(GATE), profile, option],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, **(env or {})},
    )


@pytest.mark.parametrize("profile", ["fast", "default", "release"])
def test_each_gate_profile_prints_its_evidence_denominator(profile: str):
    result = gate_plan(profile)
    assert result.returncode == 0, result.stderr
    assert f"PROFILE: {profile}" in result.stdout
    assert "RUNS:" in result.stdout
    assert "DOES NOT RUN:" in result.stdout


def test_fast_is_the_core_inner_loop_only():
    plan = gate_plan("fast").stdout
    assert "uv run python tools/build_guard.py" in plan
    assert "cargo test --features python-ext" in plan
    assert 'pytest python/tests/ -m "core and not decbench"' in plan
    assert "ruff check" in plan
    assert "ty check" in plan
    assert "DecBench/Joern metrics" in plan
    assert "decbench-local-gate.sh" not in plan


def test_default_reuses_the_local_fixture_gate_without_decbench():
    plan = gate_plan("default").stdout
    assert "scripts/decbench-local-gate.sh --no-decbench" in plan
    assert "DecBench/Joern metrics" in plan


def test_release_is_the_only_profile_that_requests_decbench():
    default = gate_plan("default").stdout
    release = gate_plan("release").stdout
    assert "scripts/decbench-local-gate.sh --decbench" not in default
    assert "scripts/decbench-local-gate.sh --decbench" in release
    assert "DOES NOT RUN: nothing in the declared release matrix" in release


def test_unknown_profile_fails_closed():
    result = gate_plan("typo")
    assert result.returncode == 2
    assert "unknown profile" in result.stderr


def test_release_preflight_calls_a_missing_metric_lane_not_evidence(tmp_path: Path):
    missing = tmp_path / "missing-decbench-checkout"
    result = gate_plan(
        "release",
        "--preflight",
        {METRIC_CHECKOUT_ENV: str(missing)},
    )
    assert result.returncode == 3
    assert "NOT EVIDENCE" in result.stderr
    assert str(missing) in result.stderr


def test_build_guard_reports_the_native_binary_fingerprint():
    result = subprocess.run(
        [sys.executable, str(BUILD_GUARD)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    fingerprint = next(
        line.removeprefix("native SHA-256:  ")
        for line in result.stdout.splitlines()
        if line.startswith("native SHA-256:  ")
    )
    assert len(fingerprint) == 64
    assert set(fingerprint) <= set("0123456789abcdef")
