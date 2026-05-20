from __future__ import annotations

from pathlib import Path

from glaurung.llm.agents.windows_rule_authoring import (
    WindowsRuleAuthoringConfig,
    load_windows_rule_replay_fixtures,
    run_windows_rule_authoring,
)


COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)
CHECKED_IN_REPLAY_FIXTURES = Path(
    "python/tests/fixtures/windows/functionization_rule_fixtures.yaml"
)


def test_windows_rule_authoring_proposes_test_first_tiny_stub_rule() -> None:
    result = run_windows_rule_authoring(
        WindowsRuleAuthoringConfig(
            comparison_path=str(COMPARISON),
            max_boundary_rows=12,
            max_work_items=6,
            min_precision_extra=50,
        )
    )

    assert result.claim_level == "rule_authoring_plan_not_code_change"
    assert result.work_items
    tiny = next(
        item
        for item in result.work_items
        if item.rule_id == "win-pe-tiny-stub-provenance-gate"
    )
    assert tiny.kind == "tiny_stub_precision_gate"
    assert tiny.seed_class == "tiny_stub"
    assert any(
        "npu" in file.lower() or "xrt" in file.lower() for file in tiny.source_files
    )
    assert {test.kind for test in tiny.proposed_tests} >= {"positive", "negative"}
    assert tiny.proposed_tests[0].kind == "negative"
    assert "do not blindly suppress all tiny helpers" in tiny.non_goals
    assert any(metric.seed_class == "tiny_stub" for metric in tiny.metrics)
    assert any(
        fixture.rule_id == "win-pe-tiny-stub-provenance-gate"
        for fixture in result.replay_fixtures
    )
    assert result.materialized_fixture_count == len(result.replay_fixtures)
    assert result.materialized_case_count == sum(
        len(fixture.cases) for fixture in result.replay_fixtures
    )
    assert result.checked_in_fixture_path == str(CHECKED_IN_REPLAY_FIXTURES)
    assert result.checked_in_fixture_count >= 4
    assert result.checked_in_case_count >= 8
    assert result.checked_in_fixture_drift == []
    assert "windows_function_boundary_diff:precision" in result.tool_sequence
    assert result.evidence_bundle.claim_level == "triage_evidence_bundle_not_finding"


def test_windows_rule_authoring_proposes_seed_class_metrics() -> None:
    result = run_windows_rule_authoring(
        WindowsRuleAuthoringConfig(
            comparison_path=str(COMPARISON),
            max_boundary_rows=16,
            max_work_items=8,
        )
    )

    metric_keys = {
        (metric.seed_class, metric.metric) for metric in result.seed_class_metrics
    }
    assert ("tiny_stub", "extra_entries_on_precision_stress_files") in metric_keys
    assert any(metric.target for metric in result.seed_class_metrics)
    assert any(
        item.kind in {"import_thunk_recall_guard", "body_split_recall_guard"}
        for item in result.work_items
    )
    assert all(item.implementation_scope for item in result.work_items)
    assert "functionization_rule_replay_fixtures" in (
        result.evidence_bundle.coverage.fact_coverage
    )
    assert "test-first implementation plan" in result.notes[0]


def test_windows_rule_authoring_materializes_replay_yaml(tmp_path: Path) -> None:
    output = tmp_path / "functionization_rule_fixtures.yaml"
    result = run_windows_rule_authoring(
        WindowsRuleAuthoringConfig(
            comparison_path=str(COMPARISON),
            max_boundary_rows=16,
            max_work_items=8,
            materialize_fixtures=True,
            fixture_output_path=str(output),
        )
    )

    assert result.fixtures_written is True
    assert result.materialized_fixture_path == str(output)
    assert output.exists()

    loaded = load_windows_rule_replay_fixtures(output)
    rule_ids = {fixture.rule_id for fixture in loaded}
    assert "win-pe-tiny-stub-provenance-gate" in rule_ids
    assert "win-pe-data-ref-padding-boundary-gate" in rule_ids
    assert result.materialized_fixture_count == len(loaded)
    assert result.materialized_case_count == sum(
        len(fixture.cases) for fixture in loaded
    )
    tiny = next(
        fixture
        for fixture in loaded
        if fixture.rule_id == "win-pe-tiny-stub-provenance-gate"
    )
    assert {case.kind for case in tiny.cases} >= {
        "positive",
        "negative",
        "metric_guard",
    }
    assert any(case.expected_state == "candidate_or_label" for case in tiny.cases)


def test_checked_in_windows_rule_authoring_replay_fixture_loads() -> None:
    fixtures = load_windows_rule_replay_fixtures(CHECKED_IN_REPLAY_FIXTURES)

    rule_ids = {fixture.rule_id for fixture in fixtures}
    assert {
        "win-pe-tiny-stub-provenance-gate",
        "win-pe-data-ref-padding-boundary-gate",
        "win-pe-import-thunk-shape-catalog",
        "win-pe-internal-start-body-split-candidates",
        "win-pe-tail-jump-thunk-boundary-gate",
    } <= rule_ids
    assert all(fixture.cases for fixture in fixtures)
    assert any(
        case.expected_state == "label_or_rejected_start"
        for fixture in fixtures
        for case in fixture.cases
    )


def test_windows_rule_authoring_reports_checked_in_fixture_drift(
    tmp_path: Path,
) -> None:
    stale = tmp_path / "stale.yaml"
    stale.write_text(
        """
- rule_id: stale-rule
  kind: tiny_stub_precision_gate
  seed_class: tiny_stub
  source_files: []
  implementation_scope: []
  non_goals: []
  cases:
  - id: stale_case
    kind: negative
    fixture: stale
    expected_state: strict_function
    expected: stale
    rationale: stale
""",
        encoding="utf-8",
    )

    result = run_windows_rule_authoring(
        WindowsRuleAuthoringConfig(
            comparison_path=str(COMPARISON),
            max_boundary_rows=16,
            max_work_items=8,
            checked_in_fixture_path=str(stale),
        )
    )

    assert result.checked_in_fixture_drift
    assert any(
        "stale checked-in fixture" in item for item in result.checked_in_fixture_drift
    )
    assert result.evidence_bundle.blockers == result.checked_in_fixture_drift
