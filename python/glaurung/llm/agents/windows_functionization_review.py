"""Deterministic Windows functionization review workflow.

This module is the replayable core for a higher-level pydantic-ai agent:
it composes low-level Windows functionization tools into a bounded review
packet without asking an LLM to parse bytes or infer undocumented state.
"""

from __future__ import annotations

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
from ..tools.windows_analyst_notebook import WindowsNotebookDecision
from ..tools.windows_candidate_start_worklist import (
    CandidateStartWorkItem,
    WindowsCandidateStartWorklistArgs,
    WindowsCandidateStartWorklistTool,
)
from ..tools.windows_function_body_split_candidates import (
    FunctionBodySplitCandidate,
    WindowsFunctionBodySplitCandidatesArgs,
    WindowsFunctionBodySplitCandidatesTool,
)
from ..tools.windows_function_boundary_diff import (
    WindowsFunctionBoundaryDiffArgs,
    WindowsFunctionBoundaryDiffRow,
    WindowsFunctionBoundaryDiffTool,
)
from ..tools.windows_import_thunk_catalog import (
    ImportThunkCatalogRow,
    WindowsImportThunkCatalogArgs,
    WindowsImportThunkCatalogTool,
)


class WindowsFunctionizationReviewConfig(BaseModel):
    comparison_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    )
    diagnostics_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
    )
    max_boundary_rows: int = Field(10, ge=1, le=64)
    max_worklist_rows: int = Field(10, ge=1, le=64)
    notebook_decisions: list[WindowsNotebookDecision] = Field(
        default_factory=list,
        description=(
            "Optional notebook decisions to attach to matching functionization "
            "review addresses."
        ),
    )


class WindowsFunctionizationNotebookAttachment(BaseModel):
    va: int
    address: str
    decision_kind: str
    state: str | None = None
    matched_surface: str
    summary: str
    blocks_promotion: bool
    reason_codes: list[str] = Field(default_factory=list)


class WindowsFunctionizationReviewResult(BaseModel):
    claim_level: str
    file_count_total: int
    total_missing_entries: int
    total_extra_entries: int
    issue_classes: list[str] = Field(default_factory=list)
    top_boundary_gaps: list[WindowsFunctionBoundaryDiffRow] = Field(
        default_factory=list
    )
    review_worklist: list[CandidateStartWorkItem] = Field(default_factory=list)
    body_split_candidates: list[FunctionBodySplitCandidate] = Field(
        default_factory=list
    )
    import_thunk_rows: list[ImportThunkCatalogRow] = Field(default_factory=list)
    notebook_attachments: list[WindowsFunctionizationNotebookAttachment] = Field(
        default_factory=list
    )
    blockers: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    tool_sequence: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def run_windows_functionization_review(
    config: WindowsFunctionizationReviewConfig,
) -> WindowsFunctionizationReviewResult:
    ctx = _ctx()
    boundary_tool = WindowsFunctionBoundaryDiffTool()
    worklist_tool = WindowsCandidateStartWorklistTool()
    split_tool = WindowsFunctionBodySplitCandidatesTool()
    thunk_tool = WindowsImportThunkCatalogTool()

    boundary = boundary_tool.run(
        ctx,
        ctx.kb,
        WindowsFunctionBoundaryDiffArgs(
            comparison_path=config.comparison_path,
            sort_by="total_gap",
            max_rows=config.max_boundary_rows,
        ),
    )
    worklist = worklist_tool.run(
        ctx,
        ctx.kb,
        WindowsCandidateStartWorklistArgs(
            comparison_path=config.comparison_path,
            diagnostics_path=config.diagnostics_path,
            diagnostic_kind="all",
            max_rows=config.max_worklist_rows,
        ),
    )
    split = split_tool.run(
        ctx,
        ctx.kb,
        WindowsFunctionBodySplitCandidatesArgs(
            comparison_path=config.comparison_path,
            diagnostics_path=config.diagnostics_path,
            max_rows=config.max_worklist_rows,
        ),
    )
    thunk = thunk_tool.run(
        ctx,
        ctx.kb,
        WindowsImportThunkCatalogArgs(
            comparison_path=config.comparison_path,
            diagnostics_path=config.diagnostics_path,
            file="win11-webservices.dll",
            shape="jmp_rel32",
            max_rows=min(config.max_worklist_rows, 8),
        ),
    )

    issue_classes = _issue_classes(
        boundary.rows,
        worklist.rows,
        split.rows,
        thunk.rows,
    )
    notebook_attachments = _notebook_attachments(
        decisions=config.notebook_decisions,
        worklist=worklist.rows,
        split=split.rows,
        thunk=thunk.rows,
    )
    if notebook_attachments:
        issue_classes = _dedupe(
            [
                *issue_classes,
                *[
                    "notebook_promotion_blocker"
                    for item in notebook_attachments
                    if item.blocks_promotion
                ],
                "notebook_decision_context",
            ]
        )
    tool_sequence = [
        "windows_function_boundary_diff",
        "windows_candidate_start_worklist",
        "windows_function_body_split_candidates",
        "windows_import_thunk_catalog",
    ]
    if notebook_attachments:
        tool_sequence.append("windows_analyst_notebook:attached_decisions")
    blockers = [
        "attached notebook decision blocks functionization promotion: " + item.summary
        for item in notebook_attachments
        if item.blocks_promotion
    ]
    notes = [
        "Functionization review is not vulnerability evidence.",
        "Use address-level tools before changing scanner rules or promoting findings.",
    ]
    return WindowsFunctionizationReviewResult(
        claim_level="functionization_review_not_vulnerability",
        file_count_total=boundary.file_count_total,
        total_missing_entries=boundary.total_missing_entries,
        total_extra_entries=boundary.total_extra_entries,
        issue_classes=issue_classes,
        top_boundary_gaps=boundary.rows,
        review_worklist=worklist.rows,
        body_split_candidates=split.rows,
        import_thunk_rows=thunk.rows,
        notebook_attachments=notebook_attachments,
        blockers=blockers,
        evidence_bundle=_evidence_bundle(
            config=config,
            issue_classes=issue_classes,
            boundary=boundary.rows,
            worklist=worklist.rows,
            split=split.rows,
            thunk=thunk.rows,
            notebook_attachments=notebook_attachments,
            total_missing=boundary.total_missing_entries,
            total_extra=boundary.total_extra_entries,
            tool_sequence=tool_sequence,
            blockers=blockers,
            notes=notes,
        ),
        tool_sequence=tool_sequence,
        notes=notes,
    )


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-functionization-review>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-functionization-review>")
    return ctx


def _evidence_bundle(
    *,
    config: WindowsFunctionizationReviewConfig,
    issue_classes: list[str],
    boundary: list[WindowsFunctionBoundaryDiffRow],
    worklist: list[CandidateStartWorkItem],
    split: list[FunctionBodySplitCandidate],
    thunk: list[ImportThunkCatalogRow],
    notebook_attachments: list[WindowsFunctionizationNotebookAttachment],
    total_missing: int,
    total_extra: int,
    tool_sequence: list[str],
    blockers: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    refs = [
        evidence_ref(
            kind="functionization",
            source="windows_function_boundary_diff",
            summary=(
                f"{row.file}: missing={row.missing_entries} extra={row.extra_entries}"
            ),
            reason_codes=row.cause_buckets,
            provenance=[config.comparison_path],
        )
        for row in boundary[:5]
    ]
    refs.extend(
        evidence_ref(
            kind="diagnostic",
            source="windows_candidate_start_worklist",
            summary=f"{item.file}:{item.address} {item.recommended_action}",
            address=item.va,
            confidence=min(1.0, item.score / 100.0),
            reason_codes=item.reason_codes,
            provenance=[config.diagnostics_path],
        )
        for item in worklist[:5]
    )
    refs.extend(
        evidence_ref(
            kind="functionization",
            source="windows_function_body_split_candidates",
            summary=f"{item.file}:{item.address} inside {item.owner_entry}",
            address=item.va,
            confidence=min(1.0, item.score / 100.0),
            reason_codes=item.reason_codes,
            provenance=[config.diagnostics_path],
        )
        for item in split[:3]
    )
    refs.extend(
        evidence_ref(
            kind="functionization",
            source="windows_import_thunk_catalog",
            summary=f"{item.file}:{item.address} {item.shape} {item.current_state}",
            address=item.va,
            reason_codes=[item.shape, item.current_state],
            provenance=[config.diagnostics_path],
        )
        for item in thunk[:3]
    )
    refs.extend(
        evidence_ref(
            kind="project_fact",
            source="windows_analyst_notebook",
            summary=item.summary,
            address=item.va,
            reason_codes=item.reason_codes,
            provenance=[item.matched_surface],
        )
        for item in notebook_attachments[:8]
    )
    fact_coverage = []
    if notebook_attachments:
        fact_coverage.append("analyst_notebook_decisions")
    return make_windows_evidence_bundle(
        claim_level="functionization_review_not_vulnerability",
        subject=WindowsEvidenceSubject(
            kind="functionization",
            attributes={
                "comparison_path": config.comparison_path,
                "diagnostics_path": config.diagnostics_path,
                "boundary_rows": len(boundary),
                "worklist_rows": len(worklist),
                "notebook_attachment_count": len(notebook_attachments),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=refs,
        coverage=WindowsEvidenceCoverage(
            fact_coverage=fact_coverage,
            ghidra_missing_entries=total_missing,
            ghidra_extra_entries=total_extra,
            stale_or_blocking_facts=blockers,
        ),
        reason_codes=issue_classes,
        blockers=blockers,
        next_actions=[
            "windows_function_start_explain",
            "windows_data_ref_confidence",
            "scanner rule work item",
        ],
        notes=notes,
    )


def _issue_classes(
    boundary_rows: list[WindowsFunctionBoundaryDiffRow],
    worklist_rows: list[CandidateStartWorkItem],
    split_rows: list[FunctionBodySplitCandidate],
    thunk_rows: list[ImportThunkCatalogRow],
) -> list[str]:
    classes: list[str] = []
    for row in boundary_rows:
        classes.extend(row.cause_buckets)
    if any("padding_run" in row.reason_codes for row in worklist_rows):
        classes.append("data_ref_padding_reject")
    if split_rows:
        classes.append("body_split_review")
    if thunk_rows:
        classes.append("import_thunk_review")
    return _dedupe(classes)


def _notebook_attachments(
    *,
    decisions: list[WindowsNotebookDecision],
    worklist: list[CandidateStartWorkItem],
    split: list[FunctionBodySplitCandidate],
    thunk: list[ImportThunkCatalogRow],
) -> list[WindowsFunctionizationNotebookAttachment]:
    if not decisions:
        return []
    surfaces = _review_surfaces(worklist, split, thunk)
    out: list[WindowsFunctionizationNotebookAttachment] = []
    seen: set[tuple[int, str, str]] = set()
    for decision in decisions:
        for surface in surfaces.get(decision.va, []):
            key = (decision.va, decision.kind, surface)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                WindowsFunctionizationNotebookAttachment(
                    va=decision.va,
                    address=f"0x{decision.va:x}",
                    decision_kind=decision.kind,
                    state=decision.state,
                    matched_surface=surface,
                    summary=_notebook_summary(decision, surface),
                    blocks_promotion=_notebook_blocks_promotion(decision),
                    reason_codes=_notebook_reason_codes(decision),
                )
            )
    return out


def _review_surfaces(
    worklist: list[CandidateStartWorkItem],
    split: list[FunctionBodySplitCandidate],
    thunk: list[ImportThunkCatalogRow],
) -> dict[int, list[str]]:
    surfaces: dict[int, list[str]] = {}
    for item in worklist:
        surfaces.setdefault(item.va, []).append(
            f"candidate_start_worklist:{item.file}:{item.address}"
        )
    for item in split:
        surfaces.setdefault(item.va, []).append(
            f"body_split_candidate:{item.file}:{item.address}"
        )
    for item in thunk:
        surfaces.setdefault(item.va, []).append(
            f"import_thunk_catalog:{item.file}:{item.address}"
        )
    return surfaces


def _notebook_blocks_promotion(decision: WindowsNotebookDecision) -> bool:
    return decision.kind in {"demotion", "suppression"} or decision.state in {
        "rejected_start",
        "suppressed_false_start",
    }


def _notebook_summary(decision: WindowsNotebookDecision, surface: str) -> str:
    value = decision.name or decision.state or decision.comment or decision.reason or "-"
    return f"{decision.kind}@0x{decision.va:x}:{value} matched {surface}"


def _notebook_reason_codes(decision: WindowsNotebookDecision) -> list[str]:
    codes: list[str] = [f"notebook:{decision.kind}"]
    if decision.state:
        codes.append(f"notebook_state:{decision.state}")
    if _notebook_blocks_promotion(decision):
        codes.append("notebook_blocks_promotion")
    return codes


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
