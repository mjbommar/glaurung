"""Deterministic Windows analyst-notebook workflow."""

from __future__ import annotations

from typing import Literal

import glaurung as g
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.adapters import import_triage
from ..tools.windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from ..tools.windows_analyst_notebook import (
    WindowsAnalystNotebookResult,
    WindowsAnalystNotebookTool,
    WindowsNotebookDecision,
)


NotebookReviewMode = Literal["export", "import_and_verify"]
NotebookVerificationStatus = Literal["verified", "missing", "unsupported"]


class WindowsNotebookVerification(BaseModel):
    kind: str
    va: int
    va_hex: str
    status: NotebookVerificationStatus
    expected: str
    detail: str


class WindowsAnalystNotebookReviewConfig(BaseModel):
    project_path: str
    notebook_path: str | None = None
    decisions: list[WindowsNotebookDecision] = Field(default_factory=list)
    mode: NotebookReviewMode = "import_and_verify"
    include_scripts: bool = True
    max_transcript_entries: int = Field(32, ge=1, le=256)


class WindowsAnalystNotebookReviewResult(BaseModel):
    claim_level: str = "analyst_notebook_not_finding"
    mode: NotebookReviewMode
    import_result: WindowsAnalystNotebookResult | None = None
    export_result: WindowsAnalystNotebookResult
    verifications: list[WindowsNotebookVerification]
    verified_count: int
    missing_count: int
    unsupported_count: int
    compact_transcript: list[str]
    tool_sequence: list[str]
    blockers: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


def run_windows_analyst_notebook_review(
    config: WindowsAnalystNotebookReviewConfig,
) -> WindowsAnalystNotebookReviewResult:
    ctx = _ctx()
    notebook_tool = WindowsAnalystNotebookTool()
    import_result = None
    tool_sequence: list[str] = []
    if config.mode == "import_and_verify":
        import_result = notebook_tool.run(
            ctx,
            ctx.kb,
            notebook_tool.input_model(
                mode="import",
                project_path=config.project_path,
                notebook_path=config.notebook_path,
                decisions=config.decisions,
                include_scripts=config.include_scripts,
                add_to_kb=False,
            ),
        )
        tool_sequence.append("windows_analyst_notebook:import")

    export_result = notebook_tool.run(
        ctx,
        ctx.kb,
        notebook_tool.input_model(
            mode="export",
            project_path=config.project_path,
            include_scripts=config.include_scripts,
            add_to_kb=False,
        ),
    )
    tool_sequence.append("windows_analyst_notebook:export")
    verifications = _verify_decisions(config.decisions, export_result)
    blockers = _blockers(import_result, verifications)
    transcript = _compact_transcript(export_result, config.max_transcript_entries)
    notes = [
        "Analyst notebook review persists annotations; it does not change scanner policy.",
        "Demotions and suppressions remain visible as comments/bookmarks.",
    ]
    return WindowsAnalystNotebookReviewResult(
        mode=config.mode,
        import_result=import_result,
        export_result=export_result,
        verifications=verifications,
        verified_count=sum(1 for item in verifications if item.status == "verified"),
        missing_count=sum(1 for item in verifications if item.status == "missing"),
        unsupported_count=sum(
            1 for item in verifications if item.status == "unsupported"
        )
        + (import_result.unsupported_count if import_result is not None else 0),
        compact_transcript=transcript,
        tool_sequence=tool_sequence,
        blockers=blockers,
        evidence_bundle=_evidence_bundle(
            config=config,
            export_result=export_result,
            verifications=verifications,
            transcript=transcript,
            tool_sequence=tool_sequence,
            blockers=blockers,
            notes=notes,
        ),
        notes=notes,
    )


def _verify_decisions(
    decisions: list[WindowsNotebookDecision],
    export_result: WindowsAnalystNotebookResult,
) -> list[WindowsNotebookVerification]:
    if not decisions:
        return []
    exported = export_result.notebook.decisions
    return [_verify_one(decision, exported) for decision in decisions]


def _verify_one(
    decision: WindowsNotebookDecision,
    exported: list[WindowsNotebookDecision],
) -> WindowsNotebookVerification:
    expected = _expected_value(decision)
    va_hex = decision.va_hex or f"0x{decision.va:x}"
    if not expected:
        return WindowsNotebookVerification(
            kind=decision.kind,
            va=decision.va,
            va_hex=va_hex,
            status="unsupported",
            expected="",
            detail="decision lacks a verifiable name, comment, label, or state",
        )
    for candidate in exported:
        if candidate.va != decision.va:
            continue
        if _decision_matches(decision, candidate):
            return WindowsNotebookVerification(
                kind=decision.kind,
                va=decision.va,
                va_hex=va_hex,
                status="verified",
                expected=expected,
                detail="decision survived import/export round trip",
            )
    return WindowsNotebookVerification(
        kind=decision.kind,
        va=decision.va,
        va_hex=va_hex,
        status="missing",
        expected=expected,
        detail="decision was not present in exported notebook",
    )


def _decision_matches(
    expected: WindowsNotebookDecision,
    actual: WindowsNotebookDecision,
) -> bool:
    if expected.kind == "function_name":
        return actual.kind == "function_name" and actual.name == expected.name
    if expected.kind == "comment":
        return actual.kind == "comment" and actual.comment == expected.comment
    if expected.kind == "data_label":
        return actual.kind == "data_label" and actual.name == expected.name
    if expected.kind in {
        "function_start_decision",
        "demotion",
        "suppression",
    }:
        return actual.kind in {"function_start_decision", "comment"} and (
            actual.state == expected.state
            or bool(
                actual.comment and expected.state and expected.state in actual.comment
            )
            or bool(
                actual.reason and expected.state and expected.state in actual.reason
            )
        )
    return False


def _expected_value(decision: WindowsNotebookDecision) -> str:
    if decision.name:
        return decision.name
    if decision.comment:
        return decision.comment
    if decision.state:
        return decision.state
    return ""


def _blockers(
    import_result: WindowsAnalystNotebookResult | None,
    verifications: list[WindowsNotebookVerification],
) -> list[str]:
    blockers: list[str] = []
    if import_result is not None and import_result.unsupported_count:
        blockers.append(
            f"unsupported notebook decisions: {import_result.unsupported_count}"
        )
    for verification in verifications:
        if verification.status != "verified":
            blockers.append(
                f"{verification.status} {verification.kind} at {verification.va_hex}: "
                f"{verification.expected or verification.detail}"
            )
    return _dedupe(blockers)


def _compact_transcript(
    export_result: WindowsAnalystNotebookResult,
    max_entries: int,
) -> list[str]:
    transcript = list(export_result.notebook.transcript[:max_entries])
    if len(export_result.notebook.transcript) > max_entries:
        transcript.append(
            f"truncated {len(export_result.notebook.transcript) - max_entries} notebook entries"
        )
    return transcript


def _evidence_bundle(
    *,
    config: WindowsAnalystNotebookReviewConfig,
    export_result: WindowsAnalystNotebookResult,
    verifications: list[WindowsNotebookVerification],
    transcript: list[str],
    tool_sequence: list[str],
    blockers: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "project_path": config.project_path,
                "decision_count": len(export_result.notebook.decisions),
                "verified_count": sum(
                    1 for item in verifications if item.status == "verified"
                ),
                "transcript_count": len(transcript),
            },
        ),
        source_tools=["windows_analyst_notebook"],
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="project_fact",
                source="windows_analyst_notebook_review",
                summary=f"{item.status} {item.kind} at {item.va_hex}: {item.expected}",
                address=item.va,
                reason_codes=[item.status, item.kind],
                provenance=[config.project_path],
            )
            for item in verifications[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=["function_names", "comments", "data_labels", "bookmarks"],
            missing_facts=[
                f"{item.kind}:{item.va_hex}"
                for item in verifications
                if item.status == "missing"
            ],
            stale_or_blocking_facts=blockers,
        ),
        reason_codes=[item.status for item in verifications],
        blockers=blockers,
        next_actions=["review notebook transcript", "export IDA/Ghidra scripts"],
        notes=notes,
    )


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(
        file_path="<windows-analyst-notebook-review>", artifact=artifact
    )
    import_triage(ctx.kb, artifact, "<windows-analyst-notebook-review>")
    return ctx


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
