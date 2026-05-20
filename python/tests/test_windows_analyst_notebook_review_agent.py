from __future__ import annotations

from pathlib import Path

from glaurung.llm.agents.windows_analyst_notebook_review import (
    WindowsAnalystNotebookReviewConfig,
    run_windows_analyst_notebook_review,
)
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_analyst_notebook import WindowsNotebookDecision


def _project(tmp_path: Path) -> Path:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ" + b"\0" * 512)
    project = tmp_path / "target.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    kb.close()
    return project


def test_windows_analyst_notebook_review_imports_and_verifies_roundtrip(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)

    result = run_windows_analyst_notebook_review(
        WindowsAnalystNotebookReviewConfig(
            project_path=str(project),
            decisions=[
                WindowsNotebookDecision(
                    kind="function_name",
                    va=0x140001000,
                    name="ReviewedFunction",
                ),
                WindowsNotebookDecision(
                    kind="comment",
                    va=0x140001010,
                    comment="source reaches copy sink",
                ),
                WindowsNotebookDecision(
                    kind="data_label",
                    va=0x140020000,
                    name="g_Callbacks",
                    c_type="void *[]",
                ),
                WindowsNotebookDecision(
                    kind="demotion",
                    va=0x140001020,
                    state="suppressed_false_start",
                    reason="SIMD continuation false start",
                    confidence=0.9,
                ),
            ],
            max_transcript_entries=8,
        )
    )

    assert result.claim_level == "analyst_notebook_not_finding"
    assert result.import_result is not None
    assert result.import_result.applied_count == 4
    assert result.verified_count == 4
    assert result.missing_count == 0
    assert result.unsupported_count == 0
    assert result.blockers == []
    assert any("ReviewedFunction" in line for line in result.compact_transcript)
    assert any("suppressed_false_start" in line for line in result.compact_transcript)
    assert result.export_result.ida_script is not None
    assert "ReviewedFunction" in result.export_result.ida_script
    assert result.evidence_bundle.claim_level == "triage_evidence_bundle_not_finding"
    assert result.evidence_bundle.subject.attributes["verified_count"] == 4


def test_windows_analyst_notebook_review_reports_unsupported_decisions(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)

    result = run_windows_analyst_notebook_review(
        WindowsAnalystNotebookReviewConfig(
            project_path=str(project),
            decisions=[
                WindowsNotebookDecision(
                    kind="function_name",
                    va=0x140001000,
                )
            ],
        )
    )

    assert result.verified_count == 0
    assert result.unsupported_count >= 1
    assert result.blockers
    assert any("unsupported" in blocker for blocker in result.blockers)
