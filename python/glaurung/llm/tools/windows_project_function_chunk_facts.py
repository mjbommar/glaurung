from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb import windows_function_chunks
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class ProjectFunctionChunkFact(BaseModel):
    owner_entry_va: int | None = None
    chunk_start_va: int
    chunk_end_va: int | None = None
    chunk_size: int | None = None
    chunk_kind: str
    relation_kind: str
    target_va: int | None = None
    target_name: str | None = None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    name: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class WindowsProjectFunctionChunkFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    owner_entry_va: int | None = Field(
        None,
        description="Optional owner function VA filter.",
    )
    chunk_kind: str | None = Field(
        None,
        description=(
            "Optional chunk kind filter, for example import_thunk, jump_thunk, "
            "shared_tail_candidate, split_body_candidate, or pdata_body."
        ),
    )
    relation_kind: str | None = Field(
        None,
        description="Optional relation filter, for example owns or thunk_to.",
    )
    target_va: int | None = Field(None, description="Optional target VA filter.")
    min_confidence: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="Minimum confidence for returned facts.",
    )
    max_rows: int = Field(64, ge=0, description="Maximum facts to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact function-chunk evidence node to the KB.",
    )


class WindowsProjectFunctionChunkFactsResult(BaseModel):
    project_path: str
    chunk_count: int
    chunks: list[ProjectFunctionChunkFact]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectFunctionChunkFactsTool(
    MemoryTool[
        WindowsProjectFunctionChunkFactsArgs,
        WindowsProjectFunctionChunkFactsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_function_chunk_facts",
                description=(
                    "Query first-class Windows function chunk, thunk, tailcall, "
                    "shared-tail, and funclet facts from a .glaurung project."
                ),
                tags=("windows", "pe", "project", "functions", "chunks", "thunks"),
            ),
            WindowsProjectFunctionChunkFactsArgs,
            WindowsProjectFunctionChunkFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectFunctionChunkFactsArgs,
    ) -> WindowsProjectFunctionChunkFactsResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        project = PersistentKnowledgeBase.open(project_path)
        try:
            rows = windows_function_chunks.list_function_chunks(
                project,
                owner_entry_va=args.owner_entry_va,
                chunk_kind=args.chunk_kind,
                relation_kind=args.relation_kind,
                target_va=args.target_va,
                min_confidence=args.min_confidence,
                limit=args.max_rows,
            )
        finally:
            project.close()

        chunks = [
            ProjectFunctionChunkFact(
                owner_entry_va=row.owner_entry_va,
                chunk_start_va=row.chunk_start_va,
                chunk_end_va=row.chunk_end_va,
                chunk_size=row.chunk_size,
                chunk_kind=row.chunk_kind,
                relation_kind=row.relation_kind,
                target_va=row.target_va,
                target_name=row.target_name,
                source=row.source,
                confidence=row.confidence,
                name=row.name,
                detail=dict(row.detail or {}),
            )
            for row in rows
        ]
        coverage = _coverage(chunks)
        missing = [] if chunks else ["function_chunk_facts"]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_function_chunk_facts",
                    props={
                        "project_path": str(project_path),
                        "owner_entry_va": args.owner_entry_va,
                        "chunk_kind": args.chunk_kind,
                        "relation_kind": args.relation_kind,
                        "target_va": args.target_va,
                        "chunk_count": len(chunks),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectFunctionChunkFactsResult(
            project_path=str(project_path),
            chunk_count=len(chunks),
            chunks=chunks,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "function chunk facts explain boundaries, thunks, and tail targets; "
                "they do not by themselves prove source reachability or vulnerability"
            ],
        )


def _coverage(chunks: list[ProjectFunctionChunkFact]) -> list[str]:
    coverage = ["function_chunk_facts"] if chunks else []
    kinds = {chunk.chunk_kind for chunk in chunks}
    if kinds & {"jump_thunk", "adjustor_thunk", "import_thunk"}:
        coverage.append("thunk_facts")
    if kinds & {"tail_jump_target", "shared_tail_candidate"}:
        coverage.append("tailcall_chunk_facts")
    if kinds & {"split_body_candidate", "exception_funclet_candidate"}:
        coverage.append("split_body_or_funclet_facts")
    if kinds & {"pdata_body", "public_symbol_range"}:
        coverage.append("range_backed_chunk_facts")
    return coverage


def build_tool() -> WindowsProjectFunctionChunkFactsTool:
    return WindowsProjectFunctionChunkFactsTool()
