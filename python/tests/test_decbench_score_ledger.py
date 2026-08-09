"""Regression tests for the pinned 250-function DecBench score ledger."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "decbench_score_ledger.py"
MANIFEST = ROOT / "tests" / "decbench_scoreboard" / "manifest.json"
BASELINE = ROOT / "tests" / "decbench_scoreboard" / "glaurung-c1cfdc97.json"
BASELINE_LEDGER = ROOT / "tests" / "decbench_scoreboard" / "baseline-ledger.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("decbench_score_ledger", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ledger_module():
    return _load_tool()


def test_pinned_baseline_reproduces_the_fresh_submission_run(ledger_module):
    manifest = ledger_module.load_json(MANIFEST)
    report = ledger_module.load_json(BASELINE)

    ledger = ledger_module.build_ledger(report, manifest)
    ledger_module.check_baseline(ledger, manifest)

    assert ledger["functions"] == 250
    assert ledger["metrics"]["ged"] == {
        "coverage": 239,
        "missing": 11,
        "perfect": 59,
        "perfect_rate": pytest.approx(59 / 239),
        "mean": pytest.approx(32.45606694560669),
        "median": 10.0,
        "zeros": 59,
    }
    assert ledger["metrics"]["type_match"]["coverage"] == 235
    assert ledger["metrics"]["type_match"]["perfect"] == 13
    assert ledger["metrics"]["byte_match"]["coverage"] == 250
    assert ledger["metrics"]["byte_match"]["perfect"] == 7
    assert ledger["union"] == {
        "coverage": 250,
        "perfect": 67,
        "perfect_rate": pytest.approx(67 / 250),
    }


def test_ledger_reports_arch_optimization_size_and_head_to_head(ledger_module):
    ledger = ledger_module.build_ledger(
        ledger_module.load_json(BASELINE), ledger_module.load_json(MANIFEST)
    )

    assert ledger["dimensions"]["arch"]["elf-arm-32"]["functions"] == 84
    assert ledger["dimensions"]["arch"]["elf-x86-64-64"]["functions"] == 158
    assert ledger["dimensions"]["opt"]["O2-noinline"]["metrics"]["ged"][
        "mean"
    ] == pytest.approx(52.40625)
    assert ledger["dimensions"]["cfg_size"]["250+"]["union"]["perfect"] == 0
    assert ledger["head_to_head"]["ghidra"]["type_match"]["other_mean"] == (
        pytest.approx(0.23070193899548536)
    )


def test_manifest_materializes_overlapping_canary_sets(ledger_module):
    manifest = ledger_module.load_json(MANIFEST)
    report = ledger_module.load_json(BASELINE)
    ledger = ledger_module.build_ledger(report, manifest)

    assert ledger_module.derive_canaries(report["rows"]) == manifest["canaries"]
    assert len(manifest["canaries"]["worst_ged"]) == 40
    assert len(manifest["canaries"]["worst_type_match"]) == 40
    assert len(manifest["canaries"]["worst_byte_match"]) == 40
    assert len(manifest["canaries"]["current_perfect"]) == 67
    assert [item["key"] for item in ledger["canaries"]["worst_ged"]] == manifest[
        "canaries"
    ]["worst_ged"]
    assert any("yyparse" in key for key in manifest["canaries"]["worst_ged"])
    assert any(
        "console_getc" in key for key in manifest["canaries"]["worst_type_match"]
    )
    assert any(
        "statdb_write" in key for key in manifest["canaries"]["worst_byte_match"]
    )


def test_missing_or_extra_function_fails_loudly(ledger_module):
    manifest = ledger_module.load_json(MANIFEST)
    report = ledger_module.load_json(BASELINE)
    report["rows"] = report["rows"][:-1]

    with pytest.raises(ledger_module.LedgerError, match="function key mismatch"):
        ledger_module.build_ledger(report, manifest)


def test_stale_revision_or_metric_schema_fails_loudly(ledger_module):
    manifest = ledger_module.load_json(MANIFEST)
    report = ledger_module.load_json(BASELINE)
    report["provenance"]["decbench"] = "stale"

    with pytest.raises(ledger_module.LedgerError, match="provenance decbench mismatch"):
        ledger_module.build_ledger(report, manifest)

    report = ledger_module.load_json(BASELINE)
    report["metric_schema"]["byte_match"]["revision"] = "main-before-pr61"
    with pytest.raises(ledger_module.LedgerError, match="metric schema mismatch"):
        ledger_module.build_ledger(report, manifest)


def test_a_new_glaurung_revision_is_the_allowed_independent_variable(ledger_module):
    manifest = ledger_module.load_json(MANIFEST)
    report = ledger_module.load_json(BASELINE)
    report["provenance"]["glaurung"] = "future-revision"

    ledger = ledger_module.build_ledger(report, manifest)

    assert ledger["revisions"]["glaurung"] == "future-revision"
    with pytest.raises(ledger_module.LedgerError, match="baseline Glaurung revision"):
        ledger_module.check_baseline(ledger, manifest)


def test_raw_package_checksum_is_verified(ledger_module, tmp_path: Path):
    manifest = ledger_module.load_json(MANIFEST)
    package = tmp_path / "results.zip"
    package.write_bytes(b"real DecBench package bytes")
    manifest["raw_package"]["sha256"] = hashlib.sha256(package.read_bytes()).hexdigest()

    ledger_module.verify_raw_package(package, manifest)
    package.write_bytes(b"changed")
    with pytest.raises(ledger_module.LedgerError, match="checksum mismatch"):
        ledger_module.verify_raw_package(package, manifest)


def test_rendered_json_is_byte_deterministic(ledger_module):
    manifest = ledger_module.load_json(MANIFEST)
    report = ledger_module.load_json(BASELINE)

    first = ledger_module.render_json(ledger_module.build_ledger(report, manifest))
    second = ledger_module.render_json(ledger_module.build_ledger(report, manifest))

    assert first == second
    assert first == BASELINE_LEDGER.read_text(encoding="utf-8")
    assert first.endswith("\n")
    assert json.loads(first)["metric_schema"]["byte_match"]["revision"].startswith(
        "decbench-pr61@"
    )


def test_input_row_order_does_not_change_the_ledger(ledger_module):
    manifest = ledger_module.load_json(MANIFEST)
    report = ledger_module.load_json(BASELINE)
    expected = ledger_module.render_json(ledger_module.build_ledger(report, manifest))
    report["rows"].reverse()

    actual = ledger_module.render_json(ledger_module.build_ledger(report, manifest))

    assert actual == expected
