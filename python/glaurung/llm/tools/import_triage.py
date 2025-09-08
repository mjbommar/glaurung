from __future__ import annotations

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class TriageImportArgs(BaseModel):
    path: str | None = Field(None, description="Optional override of file path")
    max_read_bytes: int | None = None
    max_file_size: int | None = None
    max_depth: int = 1


class TriageImportResult(BaseModel):
    file_node_id: str
    size_bytes: int
    format: str | None = None
    arch: str | None = None


class TriageImportTool(MemoryTool[TriageImportArgs, TriageImportResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="import_triage",
                description="Run triage on a path and import summary into KB.",
                tags=("triage", "kb"),
            ),
            TriageImportArgs,
            TriageImportResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: TriageImportArgs
    ) -> TriageImportResult:
        path = args.path or ctx.file_path
        art = g.triage.analyze_path(
            path,
            args.max_read_bytes or ctx.budgets.max_read_bytes,
            args.max_file_size or ctx.budgets.max_file_size,
            args.max_depth,
        )
        # file node
        file_node = kb.add_node(
            Node(kind=NodeKind.file, label=path, props={"size": art.size_bytes})
        )
        # artifact node
        art_node = kb.add_node(
            Node(kind=NodeKind.artifact, label="triage", props={"path": path})
        )
        kb.add_edge(Edge(src=file_node.id, dst=art_node.id, kind="has_artifact"))
        fmt = arch = None
        if art.verdicts:
            try:
                v = art.verdicts[0]
                fmt = str(v.format)
                arch = str(v.arch)
            except Exception:
                pass
        return TriageImportResult(
            file_node_id=file_node.id,
            size_bytes=art.size_bytes,
            format=fmt,
            arch=arch,
        )


def build_tool() -> MemoryTool[TriageImportArgs, TriageImportResult]:
    return TriageImportTool()
