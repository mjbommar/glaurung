from __future__ import annotations

import hashlib
import json
from pathlib import Path

from glaurung.llm.agents.windows_corpus_curator import (
    WindowsCorpusCuratorConfig,
    run_windows_corpus_curator,
)


CORPUS_ROOT = Path("samples/binaries/platforms/windows/vendor/realworld")
COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)


def test_windows_corpus_curator_records_provenance_and_dashboard_coverage() -> None:
    result = run_windows_corpus_curator(
        WindowsCorpusCuratorConfig(
            corpus_root=str(CORPUS_ROOT),
            comparison_path=str(COMPARISON),
            max_selected=12,
        )
    )

    assert result.claim_level == "corpus_curation_not_analysis"
    assert result.fixture_count == 30
    assert result.fast_baseline_count == 10
    assert result.stress_count == 20
    assert result.missing_dashboard_entries == []
    assert result.missing_local_files == []
    assert result.manifest_drift == []
    assert result.manifest_drift_count == 0
    assert result.drift_guard_passed is True
    assert {"exe", "dll", "sys"} <= set(result.binary_kind_counts)
    assert result.manifest_path.endswith("MANIFEST.json")
    assert result.manifest_written is False
    assert result.manifest_fixture_count == 30
    assert len(result.selected_fixtures) == 12
    assert all(len(record.sha256) == 64 for record in result.all_fixtures)
    assert all(record.architecture == "x64-pe" for record in result.all_fixtures)
    assert any(record.source_path for record in result.all_fixtures)
    assert any(record.file_description for record in result.all_fixtures)
    assert any(
        "vendor_tiny_stub_precision" in record.stress_purpose
        for record in result.all_fixtures
    )
    assert any(
        "callback_table_data_ref_recall" in record.stress_purpose
        for record in result.all_fixtures
    )
    assert any(
        "windows_ghidra_parity.py" in command
        for command in result.dashboard_refresh_commands
    )
    assert result.evidence_bundle.claim_level == "triage_evidence_bundle_not_finding"


def test_windows_corpus_curator_selects_diverse_fixture_subset() -> None:
    result = run_windows_corpus_curator(
        WindowsCorpusCuratorConfig(
            corpus_root=str(CORPUS_ROOT),
            comparison_path=str(COMPARISON),
            max_selected=8,
        )
    )

    suites = {record.suite for record in result.selected_fixtures}
    kinds = {record.binary_kind for record in result.selected_fixtures}
    purposes = {record.stress_purpose[0] for record in result.selected_fixtures}

    assert "fast_baseline" in suites
    assert "stress" in suites
    assert len(kinds) >= 2
    assert len(purposes) >= 4
    assert (
        "run dashboard refresh after fixture changes"
        in result.evidence_bundle.next_actions
    )


def test_windows_corpus_curator_can_write_enriched_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "MANIFEST.json"
    result = run_windows_corpus_curator(
        WindowsCorpusCuratorConfig(
            corpus_root=str(CORPUS_ROOT.resolve()),
            comparison_path=str(COMPARISON),
            manifest_path=str(manifest_path),
            write_manifest=True,
            max_selected=4,
        )
    )

    assert result.manifest_written is True
    assert result.manifest_path == str(manifest_path)
    assert result.manifest_fixture_count == 30
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 2
    assert manifest["curation"]["tool"] == "windows_corpus_curator"
    assert manifest["curation"]["fast_baseline_count"] == 10
    assert manifest["curation"]["stress_count"] == 20
    assert len(manifest["fixtures"]) == 30
    first = manifest["fixtures"][0]
    assert {
        "file",
        "path",
        "suite",
        "binary_kind",
        "architecture",
        "sha256",
        "stress_purpose",
        "ghidra_internal_functions",
        "glaurung_functions",
    } <= set(first)


def test_windows_corpus_curator_reports_and_fails_manifest_drift(
    tmp_path: Path,
) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    binary = corpus_root / "app.exe"
    payload = b"MZdrift-fixture"
    binary.write_bytes(payload)
    comparison = tmp_path / "comparison.json"
    comparison.write_text(
        json.dumps(
            [
                {
                    "file": "app.exe",
                    "source_label": "tmp",
                    "glaurung": {"functions": 3},
                    "ghidra": {"metrics": {"internal_functions": 4}},
                    "address_gap": {"missing_entries": 1, "extra_entries": 2},
                }
            ]
        ),
        encoding="utf-8",
    )
    manifest = corpus_root / "MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "fixtures": [
                    {
                        "file": "app.exe",
                        "path": "stale/app.exe",
                        "suite": "fast_baseline",
                        "binary_kind": "exe",
                        "architecture": "x64-pe",
                        "size_bytes": 1,
                        "sha256": "stale",
                        "pdb_status": "unknown",
                        "stress_purpose": ["stale"],
                        "ghidra_internal_functions": 0,
                        "glaurung_functions": 0,
                        "missing_entries": 0,
                        "extra_entries": 0,
                    },
                    {"file": "ghost.dll"},
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_windows_corpus_curator(
        WindowsCorpusCuratorConfig(
            corpus_root=str(corpus_root),
            comparison_path=str(comparison),
            fail_on_drift=False,
        )
    )

    assert result.fixture_count == 1
    assert result.drift_guard_passed is False
    assert result.manifest_drift_count >= 2
    reasons = {item.reason for item in result.manifest_drift}
    assert "stale_manifest_field" in reasons
    assert "stale_manifest_entry" in reasons
    sha_drift = [
        item
        for item in result.manifest_drift
        if item.file == "app.exe" and item.field == "sha256"
    ]
    assert sha_drift[0].current == hashlib.sha256(payload).hexdigest()
    assert sha_drift[0].recorded == "stale"

    try:
        run_windows_corpus_curator(
            WindowsCorpusCuratorConfig(
                corpus_root=str(corpus_root),
                comparison_path=str(comparison),
                fail_on_drift=True,
            )
        )
    except ValueError as exc:
        assert "corpus drift guard failed" in str(exc)
    else:
        raise AssertionError("expected corpus drift guard failure")


def test_windows_corpus_curator_accepts_intentional_manifest_drift(
    tmp_path: Path,
) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    binary = corpus_root / "app.exe"
    payload = b"MZaccepted-drift-fixture"
    binary.write_bytes(payload)
    comparison = tmp_path / "comparison.json"
    comparison.write_text(
        json.dumps(
            [
                {
                    "file": "app.exe",
                    "source_label": "tmp",
                    "glaurung": {"functions": 3},
                    "ghidra": {"metrics": {"internal_functions": 4}},
                    "address_gap": {"missing_entries": 0, "extra_entries": 0},
                }
            ]
        ),
        encoding="utf-8",
    )
    manifest = corpus_root / "MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "fixtures": [
                    {
                        "file": "app.exe",
                        "path": str(binary),
                        "suite": "stress",
                        "binary_kind": "exe",
                        "architecture": "x64-pe",
                        "size_bytes": len(payload),
                        "sha256": "stale",
                        "pdb_status": "unknown",
                        "stress_purpose": ["general_windows_pe_coverage"],
                        "ghidra_internal_functions": 4,
                        "glaurung_functions": 3,
                        "missing_entries": 0,
                        "extra_entries": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    current_sha = hashlib.sha256(payload).hexdigest()
    accepted = tmp_path / "accepted-drift.json"
    accepted.write_text(
        json.dumps(
            {
                "accepted_drift": [
                    {
                        "file": "app.exe",
                        "field": "sha256",
                        "drift_reason": "stale_manifest_field",
                        "current": current_sha,
                        "recorded": "stale",
                        "reason": "Fixture byte replacement is intentional for review.",
                        "expires_utc_date": "2026-06-30",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    review_notes = tmp_path / "corpus-review.md"

    result = run_windows_corpus_curator(
        WindowsCorpusCuratorConfig(
            corpus_root=str(corpus_root),
            comparison_path=str(comparison),
            accepted_drift_path=str(accepted),
            review_notes_path=str(review_notes),
            fail_on_drift=True,
        )
    )

    assert result.manifest_drift_count == 1
    assert result.accepted_drift_count == 1
    assert result.unaccepted_manifest_drift_count == 0
    assert result.drift_guard_passed is True
    assert result.accepted_drift[0].acceptance.acceptance_reason.startswith(
        "Fixture byte replacement"
    )
    assert "windows_corpus_curator:accepted_drift_policy" in result.tool_sequence
    assert "windows_corpus_curator:write_review_notes" in result.tool_sequence
    assert result.review_notes_path == str(review_notes)
    assert review_notes.exists()
    assert "Fixture byte replacement is intentional" in result.review_notes_markdown
    assert review_notes.read_text(encoding="utf-8") == result.review_notes_markdown
    assert (
        result.evidence_bundle.subject.attributes["unaccepted_manifest_drift_count"]
        == 0
    )
