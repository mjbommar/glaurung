from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from .windows_function_start_explain import (
    DEFAULT_COMPARISON,
    GhidraFunctionFact,
    _load_json_list,
    _parse_hex_or_int,
    _resolve_path,
)


BoundarySortKey = Literal["missing", "extra", "total_gap", "recall", "file"]


class WindowsFunctionBoundaryDiffArgs(BaseModel):
    comparison_path: str | None = Field(
        None,
        description=(
            "Path to a Glaurung/Ghidra comparison JSON. Defaults to the "
            "30-file post-tiny-stub-gate dashboard in docs/windows-port."
        ),
    )
    file: str | None = Field(
        None,
        description="Optional binary filename or unique path substring filter.",
    )
    sort_by: BoundarySortKey = Field(
        "total_gap",
        description="How to rank returned rows.",
    )
    min_missing: int = Field(
        0,
        ge=0,
        description="Only include rows with at least this many Ghidra-only starts.",
    )
    min_extra: int = Field(
        0,
        ge=0,
        description="Only include rows with at least this many Glaurung-only starts.",
    )
    max_rows: int = Field(
        30,
        ge=0,
        le=512,
        description="Maximum rows to return after filtering and sorting.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact boundary-diff evidence node to the KB.",
    )


class WindowsFunctionBoundaryDiffRow(BaseModel):
    file: str
    path: str
    source_label: str | None = None
    glaurung_functions: int
    ghidra_internal_functions: int
    missing_entries: int
    extra_entries: int
    missing_thunks: int
    missing_le32: int
    recall: float
    suspected_reason: str
    cause_buckets: list[str] = Field(default_factory=list)
    next_tools: list[str] = Field(default_factory=list)
    seed_kind_counts: dict[str, int] = Field(default_factory=dict)
    code_label_count: int = 0
    sample_missing: list[GhidraFunctionFact] = Field(default_factory=list)
    sample_extra: list[str] = Field(default_factory=list)
    trend_missing_delta: int | None = None
    trend_extra_delta: int | None = None


class WindowsFunctionBoundaryDiffResult(BaseModel):
    comparison_path: str
    file_count_total: int
    filtered_file_count: int
    returned_file_count: int
    total_missing_entries: int
    total_extra_entries: int
    rows: list[WindowsFunctionBoundaryDiffRow]
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsFunctionBoundaryDiffTool(
    MemoryTool[WindowsFunctionBoundaryDiffArgs, WindowsFunctionBoundaryDiffResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_function_boundary_diff",
                description=(
                    "Summarize Glaurung-vs-Ghidra Windows functionization "
                    "differences by binary with cause buckets and next-tool "
                    "recommendations for functionization review agents."
                ),
                tags=("windows", "pe", "ghidra", "function-boundaries", "agentic"),
            ),
            WindowsFunctionBoundaryDiffArgs,
            WindowsFunctionBoundaryDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFunctionBoundaryDiffArgs,
    ) -> WindowsFunctionBoundaryDiffResult:
        comparison_path = _resolve_path(args.comparison_path, DEFAULT_COMPARISON)
        raw_rows = _load_json_list(comparison_path)
        all_rows = [_row_from_comparison(row) for row in raw_rows]
        total_missing = sum(row.missing_entries for row in all_rows)
        total_extra = sum(row.extra_entries for row in all_rows)

        rows = _filter_rows(all_rows, args)
        filtered_file_count = len(rows)
        rows = _sort_rows(rows, args.sort_by)[: args.max_rows]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_function_boundary_diff",
                    props={
                        "comparison_path": str(comparison_path),
                        "file": args.file,
                        "sort_by": args.sort_by,
                        "returned_file_count": len(rows),
                        "total_missing_entries": total_missing,
                        "total_extra_entries": total_extra,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        notes = [
            "Rows summarize functionization quality, not vulnerability findings.",
            "Use windows_function_start_explain for address-level evidence.",
        ]
        return WindowsFunctionBoundaryDiffResult(
            comparison_path=str(comparison_path),
            file_count_total=len(all_rows),
            filtered_file_count=filtered_file_count,
            returned_file_count=len(rows),
            total_missing_entries=total_missing,
            total_extra_entries=total_extra,
            rows=rows,
            evidence_bundle=_evidence_bundle(
                comparison_path=str(comparison_path),
                rows=rows,
                total_missing=total_missing,
                total_extra=total_extra,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _row_from_comparison(row: dict[str, Any]) -> WindowsFunctionBoundaryDiffRow:
    gap = row.get("address_gap") or {}
    glaurung = row.get("glaurung") or {}
    stats = glaurung.get("stats") or {}
    ghidra = row.get("ghidra") or {}
    metrics = ghidra.get("metrics") or {}
    ghidra_functions = int(metrics.get("internal_functions") or 0)
    missing = int(gap.get("missing_entries") or 0)
    extra = int(gap.get("extra_entries") or 0)
    seed_counts = {
        str(k): int(v)
        for k, v in (stats.get("seed_kind_counts") or {}).items()
        if isinstance(v, int)
    }
    cause_buckets = _cause_buckets(
        file_name=str(row.get("file") or ""),
        missing=missing,
        extra=extra,
        missing_thunks=int(gap.get("missing_thunks") or 0),
        missing_le32=int(gap.get("missing_le32") or 0),
        suspected_reason=str(row.get("suspected_reason") or ""),
        seed_counts=seed_counts,
        code_label_count=int(stats.get("code_label_count") or 0),
    )
    trend = row.get("trend") or {}
    return WindowsFunctionBoundaryDiffRow(
        file=str(row.get("file") or ""),
        path=str(row.get("path") or ""),
        source_label=row.get("source_label"),
        glaurung_functions=int(glaurung.get("functions") or 0),
        ghidra_internal_functions=ghidra_functions,
        missing_entries=missing,
        extra_entries=extra,
        missing_thunks=int(gap.get("missing_thunks") or 0),
        missing_le32=int(gap.get("missing_le32") or 0),
        recall=_recall(ghidra_functions, missing),
        suspected_reason=str(row.get("suspected_reason") or ""),
        cause_buckets=cause_buckets,
        next_tools=_next_tools(cause_buckets),
        seed_kind_counts=seed_counts,
        code_label_count=int(stats.get("code_label_count") or 0),
        sample_missing=[
            _ghidra_sample(sample) for sample in gap.get("sample_missing") or []
        ],
        sample_extra=[str(value) for value in gap.get("sample_extra") or []],
        trend_missing_delta=trend.get("missing_delta"),
        trend_extra_delta=trend.get("extra_delta"),
    )


def _filter_rows(
    rows: list[WindowsFunctionBoundaryDiffRow],
    args: WindowsFunctionBoundaryDiffArgs,
) -> list[WindowsFunctionBoundaryDiffRow]:
    out = rows
    if args.file:
        needle = args.file.lower()
        exact = [
            row
            for row in out
            if row.file.lower() == needle or row.path.lower().endswith("/" + needle)
        ]
        if exact:
            out = exact
        else:
            out = [
                row
                for row in out
                if needle in row.file.lower() or needle in row.path.lower()
            ]
    out = [row for row in out if row.missing_entries >= args.min_missing]
    out = [row for row in out if row.extra_entries >= args.min_extra]
    return out


def _sort_rows(
    rows: list[WindowsFunctionBoundaryDiffRow],
    sort_by: BoundarySortKey,
) -> list[WindowsFunctionBoundaryDiffRow]:
    if sort_by == "missing":
        return sorted(rows, key=lambda row: (-row.missing_entries, row.file))
    if sort_by == "extra":
        return sorted(rows, key=lambda row: (-row.extra_entries, row.file))
    if sort_by == "recall":
        return sorted(rows, key=lambda row: (row.recall, row.file))
    if sort_by == "file":
        return sorted(rows, key=lambda row: row.file)
    return sorted(
        rows,
        key=lambda row: (-(row.missing_entries + row.extra_entries), row.file),
    )


def _cause_buckets(
    *,
    file_name: str,
    missing: int,
    extra: int,
    missing_thunks: int,
    missing_le32: int,
    suspected_reason: str,
    seed_counts: dict[str, int],
    code_label_count: int,
) -> list[str]:
    buckets: list[str] = []
    if missing == 0 and extra == 0:
        buckets.append("parity")
    if missing > 0:
        buckets.append("recall_gap")
    if extra > 0:
        buckets.append("precision_gap")
    if missing_le32 and missing_le32 >= max(1, missing // 2):
        buckets.append("tiny_function_recall_gap")
    if missing_thunks:
        buckets.append("import_thunk_gap")
    if extra > missing and extra >= 25:
        buckets.append("precision_priority")
    if missing > extra and missing >= 25:
        buckets.append("recall_priority")
    if seed_counts.get("tiny_stub", 0) >= 500:
        buckets.append("tiny_stub_pressure")
    if seed_counts.get("data_ref", 0) >= 100:
        buckets.append("data_ref_boundary_review")
    if code_label_count >= 20_000:
        buckets.append("large_label_surface")
    lowered = file_name.lower()
    if "webservices" in lowered or "rtkauduservice" in lowered:
        buckets.append("body_split_review")
    if "npu" in lowered or "xrt" in lowered:
        buckets.append("vendor_runtime_stress")
    if suspected_reason and suspected_reason not in {"parity_or_over", ""}:
        buckets.append(suspected_reason)
    return _dedupe(buckets)


def _next_tools(cause_buckets: list[str]) -> list[str]:
    tools = ["windows_function_start_explain"]
    if any(
        bucket in cause_buckets for bucket in {"precision_gap", "precision_priority"}
    ):
        tools.append("windows_candidate_start_worklist")
    if any(
        bucket in cause_buckets
        for bucket in {"body_split_review", "tiny_function_recall_gap"}
    ):
        tools.append("windows_function_body_split_candidates")
    if "import_thunk_gap" in cause_buckets:
        tools.append("windows_import_thunk_catalog")
    if "data_ref_boundary_review" in cause_buckets:
        tools.append("windows_data_ref_confidence")
    return _dedupe(tools)


def _recall(ghidra_functions: int, missing: int) -> float:
    if ghidra_functions <= 0:
        return 1.0
    return round(max(0.0, 1.0 - (missing / ghidra_functions)), 6)


def _evidence_bundle(
    *,
    comparison_path: str,
    rows: list[WindowsFunctionBoundaryDiffRow],
    total_missing: int,
    total_extra: int,
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="functionization_review_not_vulnerability",
        subject=WindowsEvidenceSubject(
            kind="boundary_diff",
            attributes={
                "comparison_path": comparison_path,
                "returned_file_count": len(rows),
            },
        ),
        source_tools=["windows_function_boundary_diff"],
        evidence_refs=[
            evidence_ref(
                kind="functionization",
                source="windows_function_boundary_diff",
                summary=(
                    f"{row.file}: missing={row.missing_entries} "
                    f"extra={row.extra_entries} "
                    f"buckets={','.join(row.cause_buckets[:4])}"
                ),
                reason_codes=row.cause_buckets,
                provenance=[comparison_path],
            )
            for row in rows[:8]
        ],
        coverage=WindowsEvidenceCoverage(
            ghidra_missing_entries=total_missing,
            ghidra_extra_entries=total_extra,
        ),
        reason_codes=_dedupe([bucket for row in rows for bucket in row.cause_buckets]),
        next_actions=_dedupe([tool for row in rows for tool in row.next_tools]),
        notes=notes,
    )


def _ghidra_sample(raw: Any) -> GhidraFunctionFact:
    entry = _parse_hex_or_int(raw.get("entry"))
    return GhidraFunctionFact(
        entry_va=entry,
        entry=f"0x{entry:x}",
        body_size=int(raw.get("body") or 0),
        thunk=bool(raw.get("thunk")),
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsFunctionBoundaryDiffTool:
    return WindowsFunctionBoundaryDiffTool()
