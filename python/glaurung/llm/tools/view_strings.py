from __future__ import annotations

from pydantic import BaseModel

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class StringsImportArgs(BaseModel):
    add_to_kb: bool = True
    max_samples: int = 200


class StringsImportResult(BaseModel):
    count: int
    evidence_node_id: str | None = None


class StringsImportTool(MemoryTool[StringsImportArgs, StringsImportResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="view_strings",
                description="Import string samples from triage artifact into KB.",
                tags=("strings", "kb"),
            ),
            StringsImportArgs,
            StringsImportResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: StringsImportArgs
    ) -> StringsImportResult:
        art = ctx.artifact
        count = 0
        ev_id = None
        if not art or not getattr(art, "strings", None):
            return StringsImportResult(count=0, evidence_node_id=None)
        if args.add_to_kb:
            ev = kb.add_node(Node(kind=NodeKind.evidence, label="strings"))
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
        # Collect from available sample buckets
        s = art.strings
        samples_added = 0
        # Prefer unified strings list if present
        if hasattr(s, "strings") and getattr(s, "strings"):
            for ds in getattr(s, "strings")[: args.max_samples]:
                text = getattr(ds, "text", None)
                if not text:
                    continue
                n = kb.add_node(
                    Node(kind=NodeKind.string, label=str(text)[:80], text=str(text))
                )
                if ev_id:
                    kb.add_edge(Edge(src=ev_id, dst=n.id, kind="has_string"))
                count += 1
                samples_added += 1
        # Fallback to legacy per-encoding sample arrays if available
        if samples_added < args.max_samples:
            buckets = []
            for attr in ("ascii_samples", "utf8_samples", "utf16le_samples"):
                if hasattr(s, attr) and getattr(s, attr):
                    buckets.extend(getattr(s, attr))
            remaining = args.max_samples - samples_added
            for sample in buckets[:remaining]:
                n = kb.add_node(
                    Node(
                        kind=NodeKind.string,
                        label=str(sample.text)[:80],
                        text=str(sample.text),
                    )
                )
                if ev_id:
                    kb.add_edge(Edge(src=ev_id, dst=n.id, kind="has_string"))
                count += 1
        return StringsImportResult(count=count, evidence_node_id=ev_id)


def build_tool() -> MemoryTool[StringsImportArgs, StringsImportResult]:
    return StringsImportTool()
