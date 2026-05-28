from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.binary_diff import BinaryDiff, diff_binaries
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


FunctionDiffStatus = Literal["same", "changed", "added", "removed"]


class WindowsBinaryDiffSummaryArgs(BaseModel):
    binary_a: str = Field(..., description="Pre-change binary path.")
    binary_b: str = Field(..., description="Post-change binary path.")
    status: FunctionDiffStatus | None = Field(
        None,
        description="Optional status filter: same, changed, added, or removed.",
    )
    function: str | None = Field(None, description="Optional exact function name filter.")
    name_contains: str | None = Field(
        None,
        description="Optional case-sensitive function-name substring filter.",
    )
    max_rows: int = Field(
        64,
        ge=0,
        description="Maximum diff rows to return after filtering. Use 0 for summary only.",
    )
    skip_anonymous: bool = Field(
        True,
        description="Drop sub_<hex> placeholder names that often shift between builds.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact binary-diff evidence node to the KB.",
    )


class BinaryFunctionFingerprint(BaseModel):
    name: str
    entry_va: int
    size: int
    body_hash: str


class BinaryDiffRow(BaseModel):
    name: str
    status: FunctionDiffStatus
    a: BinaryFunctionFingerprint | None = None
    b: BinaryFunctionFingerprint | None = None


class WindowsBinaryDiffSummaryResult(BaseModel):
    binary_a: str
    binary_b: str
    functions_a: int
    functions_b: int
    same: int
    changed: int
    added: int
    removed: int
    filtered_row_count: int
    rows: list[BinaryDiffRow]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsBinaryDiffSummaryTool(
    MemoryTool[WindowsBinaryDiffSummaryArgs, WindowsBinaryDiffSummaryResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_binary_diff_summary",
                description=(
                    "Run Glaurung function-level binary diff and return structured "
                    "changed/added/removed function evidence for patch triage."
                ),
                tags=("windows", "pe", "diff", "patch", "metadata"),
            ),
            WindowsBinaryDiffSummaryArgs,
            WindowsBinaryDiffSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsBinaryDiffSummaryArgs,
    ) -> WindowsBinaryDiffSummaryResult:
        diff = diff_binaries(
            args.binary_a,
            args.binary_b,
            skip_anonymous=args.skip_anonymous,
        )
        rows = _filter_rows(diff, args)
        filtered_row_count = len(rows)
        rows = rows[: args.max_rows] if args.max_rows else []

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_binary_diff_summary",
                    props={
                        "binary_a": args.binary_a,
                        "binary_b": args.binary_b,
                        "status": args.status,
                        "function": args.function,
                        "name_contains": args.name_contains,
                        "filtered_row_count": filtered_row_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsBinaryDiffSummaryResult(
            binary_a=diff.binary_a,
            binary_b=diff.binary_b,
            functions_a=diff.functions_a,
            functions_b=diff.functions_b,
            same=diff.same,
            changed=diff.changed,
            added=diff.added,
            removed=diff.removed,
            filtered_row_count=filtered_row_count,
            rows=rows,
            evidence_node_id=evidence_node_id,
            notes=[
                "function-level binary diff is a patch-triage seed, not a vulnerability verdict"
            ],
        )


def _filter_rows(
    diff: BinaryDiff,
    args: WindowsBinaryDiffSummaryArgs,
) -> list[BinaryDiffRow]:
    rows = [_row_record(row) for row in diff.rows]
    if args.status:
        rows = [row for row in rows if row.status == args.status]
    if args.function:
        rows = [row for row in rows if row.name == args.function]
    if args.name_contains:
        rows = [row for row in rows if args.name_contains in row.name]
    return rows


def _row_record(row) -> BinaryDiffRow:
    return BinaryDiffRow(
        name=row.name,
        status=row.status,
        a=_fingerprint(row.a),
        b=_fingerprint(row.b),
    )


def _fingerprint(fingerprint) -> BinaryFunctionFingerprint | None:
    if fingerprint is None:
        return None
    return BinaryFunctionFingerprint(
        name=fingerprint.name,
        entry_va=fingerprint.entry_va,
        size=fingerprint.size,
        body_hash=fingerprint.body_hash,
    )


def build_tool() -> WindowsBinaryDiffSummaryTool:
    return WindowsBinaryDiffSummaryTool()
