from __future__ import annotations

from pathlib import Path

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


class WindowsFunctionBodySplitCandidatesArgs(BaseModel):
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
    min_score: int = Field(
        0,
        ge=0,
        description="Only return rows with at least this split score.",
    )
    max_rows: int = Field(
        32,
        ge=0,
        le=512,
        description="Maximum split candidates to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact body-split worklist evidence node.",
    )


class FunctionBodySplitCandidate(BaseModel):
    file: str
    path: str
    va: int
    address: str
    current_state: FunctionStartState
    score: int
    owner_entry_va: int
    owner_entry: str
    owner_seed_kind: str | None = None
    owner_total_size: int
    owner_basic_block_count: int
    ghidra_body_size: int | None = None
    pdata_body_overlap_starts: int = 0
    bytes_hex: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    recommended_action: str


class WindowsFunctionBodySplitCandidatesResult(BaseModel):
    comparison_path: str
    diagnostics_path: str
    total_candidates: int
    returned_candidates: int
    rows: list[FunctionBodySplitCandidate]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsFunctionBodySplitCandidatesTool(
    MemoryTool[
        WindowsFunctionBodySplitCandidatesArgs,
        WindowsFunctionBodySplitCandidatesResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_function_body_split_candidates",
                description=(
                    "Rank Ghidra-only starts that sit inside existing "
                    "Glaurung function bodies, highlighting over-merged "
                    "Windows function regions for review agents."
                ),
                tags=("windows", "pe", "ghidra", "function-boundaries", "body-split"),
            ),
            WindowsFunctionBodySplitCandidatesArgs,
            WindowsFunctionBodySplitCandidatesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFunctionBodySplitCandidatesArgs,
    ) -> WindowsFunctionBodySplitCandidatesResult:
        comparison_path = _resolve_path(args.comparison_path, DEFAULT_COMPARISON)
        diagnostics_path = _resolve_path(args.diagnostics_path, DEFAULT_DIAGNOSTICS)
        comparison_rows = _load_json_list(comparison_path)
        diagnostics_rows = _load_json_list(diagnostics_path)
        comparisons_by_file = {
            str(row.get("file") or Path(str(row.get("path") or "")).name): row
            for row in comparison_rows
        }
        candidates = _collect_candidates(
            comparison_rows=comparison_rows,
            diagnostics_rows=diagnostics_rows,
            comparisons_by_file=comparisons_by_file,
            file_filter=args.file,
        )
        total_candidates = len(candidates)
        rows = [
            row
            for row in sorted(
                candidates, key=lambda item: (-item.score, item.file, item.va)
            )
            if row.score >= args.min_score
        ][: args.max_rows]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_function_body_split_candidates",
                    props={
                        "file": args.file,
                        "returned_candidates": len(rows),
                        "total_candidates": total_candidates,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsFunctionBodySplitCandidatesResult(
            comparison_path=str(comparison_path),
            diagnostics_path=str(diagnostics_path),
            total_candidates=total_candidates,
            returned_candidates=len(rows),
            rows=rows,
            evidence_node_id=evidence_node_id,
            notes=[
                "Body-split candidates are review work items, not automatic function edits."
            ],
        )


def _collect_candidates(
    *,
    comparison_rows: list[dict],
    diagnostics_rows: list[dict],
    comparisons_by_file: dict[str, dict],
    file_filter: str | None,
) -> list[FunctionBodySplitCandidate]:
    out: list[FunctionBodySplitCandidate] = []
    for diagnostics in diagnostics_rows:
        file_name = str(
            diagnostics.get("file") or Path(str(diagnostics.get("path") or "")).name
        )
        if file_filter and not _file_matches(diagnostics, file_filter):
            continue
        comparison = comparisons_by_file.get(file_name)
        if comparison is None:
            comparison = _matching_comparison(comparison_rows, diagnostics)
        if comparison is None:
            continue
        for entry in diagnostics.get("missing") or []:
            if not entry.get("containing_function"):
                continue
            va = int(entry.get("va") or 0)
            if va <= 0:
                continue
            explained = _StartContext.from_rows(
                comparison,
                diagnostics,
                va,
                max_refs=4,
            ).to_result()
            owner = explained.containing_function
            if owner is None:
                continue
            pdata_overlap = (
                0
                if explained.pdata is None
                else explained.pdata.pdata_body_overlap_starts
            )
            ghidra_body = (
                None if explained.ghidra is None else explained.ghidra.body_size
            )
            reason_codes = _reason_codes(owner.total_size, pdata_overlap, ghidra_body)
            out.append(
                FunctionBodySplitCandidate(
                    file=explained.file,
                    path=explained.path,
                    va=explained.va,
                    address=explained.address,
                    current_state=explained.final_state,
                    score=_score(owner.total_size, pdata_overlap, ghidra_body),
                    owner_entry_va=owner.entry_va,
                    owner_entry=owner.entry,
                    owner_seed_kind=owner.seed_kind,
                    owner_total_size=int(owner.total_size or 0),
                    owner_basic_block_count=owner.basic_block_count,
                    ghidra_body_size=ghidra_body,
                    pdata_body_overlap_starts=pdata_overlap,
                    bytes_hex=None if explained.bytes is None else explained.bytes.hex,
                    reason_codes=reason_codes,
                    recommended_action="split_existing_function_body",
                )
            )
    return out


def _file_matches(row: dict, file_filter: str) -> bool:
    needle = file_filter.lower()
    file_name = str(row.get("file") or "").lower()
    path = str(row.get("path") or "").lower()
    return needle == file_name or path.endswith("/" + needle) or needle in path


def _matching_comparison(comparison_rows: list[dict], diagnostics: dict) -> dict | None:
    file_name = str(
        diagnostics.get("file") or Path(str(diagnostics.get("path") or "")).name
    ).lower()
    for row in comparison_rows:
        if str(row.get("file") or "").lower() == file_name:
            return row
    return None


def _score(
    owner_total_size: int | None,
    pdata_overlap: int,
    ghidra_body_size: int | None,
) -> int:
    score = 40
    score += min(80, int((owner_total_size or 0) / 4096))
    score += min(60, int((ghidra_body_size or 0) / 8))
    if pdata_overlap:
        score += 25
    return score


def _reason_codes(
    owner_total_size: int | None,
    pdata_overlap: int,
    ghidra_body_size: int | None,
) -> list[str]:
    codes = ["inside_existing_function", "ghidra_only_start"]
    if (owner_total_size or 0) >= 16_384:
        codes.append("large_owner_function")
    if pdata_overlap:
        codes.append("pdata_overlap")
    if (ghidra_body_size or 0) <= 32:
        codes.append("tiny_ghidra_body")
    else:
        codes.append("non_tiny_ghidra_body")
    return codes


def build_tool() -> WindowsFunctionBodySplitCandidatesTool:
    return WindowsFunctionBodySplitCandidatesTool()
