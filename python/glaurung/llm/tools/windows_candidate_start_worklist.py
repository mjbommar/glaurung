from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_function_start_explain import (
    DEFAULT_COMPARISON,
    DEFAULT_DIAGNOSTICS,
    FunctionStartState,
    _StartContext,
    _load_json_list,
    _resolve_path,
)


CandidateDiagnosticKind = Literal["missing", "extra", "all"]


class WindowsCandidateStartWorklistArgs(BaseModel):
    comparison_path: str | None = Field(
        None,
        description=(
            "Path to a Glaurung/Ghidra comparison JSON. Defaults to the "
            "30-file post-tiny-stub-gate dashboard in docs/windows-port."
        ),
    )
    diagnostics_path: str | None = Field(
        None,
        description=(
            "Path to per-address diagnostics JSON. Defaults to the 30-file "
            "diagnostics artifact in docs/windows-port."
        ),
    )
    file: str | None = Field(
        None,
        description="Optional binary filename or unique path substring filter.",
    )
    diagnostic_kind: CandidateDiagnosticKind = Field(
        "all",
        description="Return missing starts, extra starts, or both.",
    )
    min_score: int = Field(
        0,
        ge=0,
        description="Only return rows with at least this review score.",
    )
    max_rows: int = Field(
        32,
        ge=0,
        le=512,
        description="Maximum ranked worklist rows to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact candidate-start worklist evidence node.",
    )


class CandidateStartWorkItem(BaseModel):
    file: str
    path: str
    va: int
    address: str
    diagnostic_kind: Literal["missing", "extra"]
    final_state: FunctionStartState
    score: int
    reason_codes: list[str] = Field(default_factory=list)
    seed_kinds: list[str] = Field(default_factory=list)
    scan_rejection_reasons: list[str] = Field(default_factory=list)
    recommended_action: str
    next_tool: str
    bytes_hex: str | None = None
    ghidra_body_size: int | None = None


class WindowsCandidateStartWorklistResult(BaseModel):
    comparison_path: str
    diagnostics_path: str
    total_candidates: int
    returned_candidates: int
    rows: list[CandidateStartWorkItem]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsCandidateStartWorklistTool(
    MemoryTool[
        WindowsCandidateStartWorklistArgs,
        WindowsCandidateStartWorklistResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_candidate_start_worklist",
                description=(
                    "Rank uncertain Windows function-start diagnostics into "
                    "a bounded worklist for agents. Each row carries final "
                    "state, reason codes, and the next address-level tool."
                ),
                tags=("windows", "pe", "ghidra", "function-start", "worklist"),
            ),
            WindowsCandidateStartWorklistArgs,
            WindowsCandidateStartWorklistResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsCandidateStartWorklistArgs,
    ) -> WindowsCandidateStartWorklistResult:
        comparison_path = _resolve_path(args.comparison_path, DEFAULT_COMPARISON)
        diagnostics_path = _resolve_path(args.diagnostics_path, DEFAULT_DIAGNOSTICS)
        comparison_rows = _load_json_list(comparison_path)
        diagnostics_rows = _load_json_list(diagnostics_path)
        comparisons_by_file = {
            str(row.get("file") or Path(str(row.get("path") or "")).name): row
            for row in comparison_rows
        }
        work_items = _collect_work_items(
            comparison_rows=comparison_rows,
            diagnostics_rows=diagnostics_rows,
            comparisons_by_file=comparisons_by_file,
            args=args,
        )
        total_candidates = len(work_items)
        rows = [
            item
            for item in sorted(
                work_items, key=lambda row: (-row.score, row.file, row.va)
            )
            if item.score >= args.min_score
        ][: args.max_rows]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_candidate_start_worklist",
                    props={
                        "file": args.file,
                        "diagnostic_kind": args.diagnostic_kind,
                        "returned_candidates": len(rows),
                        "total_candidates": total_candidates,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsCandidateStartWorklistResult(
            comparison_path=str(comparison_path),
            diagnostics_path=str(diagnostics_path),
            total_candidates=total_candidates,
            returned_candidates=len(rows),
            rows=rows,
            evidence_node_id=evidence_node_id,
            notes=[
                "Worklist rows prioritize functionization review, not vulnerability claims.",
                "Use windows_function_start_explain on a row before changing scanner rules.",
            ],
        )


def _collect_work_items(
    *,
    comparison_rows: list[dict],
    diagnostics_rows: list[dict],
    comparisons_by_file: dict[str, dict],
    args: WindowsCandidateStartWorklistArgs,
) -> list[CandidateStartWorkItem]:
    out: list[CandidateStartWorkItem] = []
    for diagnostics in diagnostics_rows:
        file_name = str(
            diagnostics.get("file") or Path(str(diagnostics.get("path") or "")).name
        )
        if args.file and not _file_matches(diagnostics, args.file):
            continue
        comparison = comparisons_by_file.get(file_name)
        if comparison is None:
            comparison = _matching_comparison(comparison_rows, diagnostics)
        if comparison is None:
            continue
        for kind in _diagnostic_kinds(args.diagnostic_kind):
            for entry in diagnostics.get(kind) or []:
                va = int(entry.get("va") or 0)
                if va <= 0:
                    continue
                explained = _StartContext.from_rows(
                    comparison,
                    diagnostics,
                    va,
                    max_refs=4,
                ).to_result()
                out.append(
                    CandidateStartWorkItem(
                        file=explained.file,
                        path=explained.path,
                        va=explained.va,
                        address=explained.address,
                        diagnostic_kind=kind,
                        final_state=explained.final_state,
                        score=_score(kind, explained),
                        reason_codes=explained.reason_codes,
                        seed_kinds=explained.seed_kinds,
                        scan_rejection_reasons=[
                            item.reason for item in explained.scan_rejections
                        ],
                        recommended_action=explained.recommended_action,
                        next_tool="windows_function_start_explain",
                        bytes_hex=None
                        if explained.bytes is None
                        else explained.bytes.hex,
                        ghidra_body_size=(
                            None
                            if explained.ghidra is None
                            else explained.ghidra.body_size
                        ),
                    )
                )
    return out


def _diagnostic_kinds(
    kind: CandidateDiagnosticKind,
) -> tuple[Literal["missing", "extra"], ...]:
    if kind == "all":
        return ("missing", "extra")
    if kind == "missing":
        return ("missing",)
    return ("extra",)


def _file_matches(row: dict, file_filter: str) -> bool:
    needle = file_filter.lower()
    file_name = str(row.get("file") or "").lower()
    path = str(row.get("path") or "").lower()
    return needle == file_name or path.endswith("/" + needle) or needle in path


def _matching_comparison(
    comparison_rows: list[dict],
    diagnostics: dict,
) -> dict | None:
    file_name = str(
        diagnostics.get("file") or Path(str(diagnostics.get("path") or "")).name
    ).lower()
    for row in comparison_rows:
        if str(row.get("file") or "").lower() == file_name:
            return row
    return None


def _score(kind: Literal["missing", "extra"], item: object) -> int:
    reason_codes = list(getattr(item, "reason_codes", []) or [])
    score = 100 if kind == "missing" else 80
    if "padding_run" in reason_codes:
        score += 100
    if "simd_head" in reason_codes:
        score += 35
    if "pdata_body_overlap" in reason_codes:
        score += 20
    if "ghidra_thunk" in reason_codes or "rex_import_jump_thunk" in reason_codes:
        score += 20
    if "code_pointer_ref" in reason_codes:
        score += 15
    ghidra = getattr(item, "ghidra", None)
    if ghidra is not None and getattr(ghidra, "body_size", 0) > 32:
        score += 10
    if getattr(item, "final_state", None) == "strict_function":
        score -= 40
    return max(score, 0)


def build_tool() -> WindowsCandidateStartWorklistTool:
    return WindowsCandidateStartWorklistTool()
