from __future__ import annotations

from pathlib import Path

from glaurung.llm.agents.windows_functionization_review import (
    WindowsFunctionizationReviewConfig,
    run_windows_functionization_review,
)
from glaurung.llm.tools.windows_analyst_notebook import WindowsNotebookDecision


COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)
DIAGNOSTICS = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
)


def test_windows_functionization_review_replays_top_human_issue_classes() -> None:
    result = run_windows_functionization_review(
        WindowsFunctionizationReviewConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_boundary_rows=8,
            max_worklist_rows=8,
        )
    )

    assert result.file_count_total == 30
    assert result.total_missing_entries == 1041
    assert result.total_extra_entries == 3116
    assert (
        result.top_boundary_gaps[0].file == "windows-update-amd-xilinx-xrt_coreutil.dll"
    )
    assert "precision_priority" in result.issue_classes
    assert "tiny_function_recall_gap" in result.issue_classes
    assert "data_ref_padding_reject" in result.issue_classes
    assert "body_split_review" in result.issue_classes
    assert "import_thunk_review" in result.issue_classes
    assert result.tool_sequence[:3] == [
        "windows_function_boundary_diff",
        "windows_candidate_start_worklist",
        "windows_function_body_split_candidates",
    ]
    assert (
        result.evidence_bundle.claim_level == "functionization_review_not_vulnerability"
    )
    assert result.evidence_bundle.coverage.ghidra_missing_entries == 1041
    assert result.evidence_bundle.coverage.ghidra_extra_entries == 3116
    assert result.evidence_bundle.tool_sequence[:3] == result.tool_sequence[:3]
    assert any(
        item.next_tool == "windows_function_start_explain"
        for item in result.review_worklist
    )


def test_windows_functionization_review_keeps_claim_level_bounded() -> None:
    result = run_windows_functionization_review(
        WindowsFunctionizationReviewConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_boundary_rows=3,
            max_worklist_rows=3,
        )
    )

    assert result.claim_level == "functionization_review_not_vulnerability"
    assert all("not vulnerability" in note.lower() for note in result.notes[:1])


def test_windows_functionization_review_attaches_notebook_suppressions() -> None:
    result = run_windows_functionization_review(
        WindowsFunctionizationReviewConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_boundary_rows=3,
            max_worklist_rows=5,
            notebook_decisions=[
                WindowsNotebookDecision(
                    kind="suppression",
                    va=0x1400041A6,
                    state="suppressed_false_start",
                    reason="padding-run data-ref false start",
                    provenance=["analyst:notebook"],
                )
            ],
        )
    )

    assert result.notebook_attachments
    attachment = result.notebook_attachments[0]
    assert attachment.va == 0x1400041A6
    assert attachment.blocks_promotion is True
    assert "candidate_start_worklist" in attachment.matched_surface
    assert "notebook_promotion_blocker" in result.issue_classes
    assert result.blockers
    assert "analyst_notebook_decisions" in result.evidence_bundle.coverage.fact_coverage
    assert result.evidence_bundle.blockers == result.blockers
    assert any(
        ref.source == "windows_analyst_notebook"
        and "notebook_blocks_promotion" in ref.reason_codes
        for ref in result.evidence_bundle.evidence_refs
    )
