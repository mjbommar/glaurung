from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class KBSearchArgs(BaseModel):
    query: str
    k: int = Field(10, ge=1, le=200)


class KBSearchHit(BaseModel):
    node_id: str
    label: str
    score: int
    kind: str


class KBSearchResult(BaseModel):
    hits: List[KBSearchHit]


class KBSearchTool(MemoryTool[KBSearchArgs, KBSearchResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="search_kb",
                description="Text search across all KB nodes (label/text)",
                tags=("search",),
            ),
            KBSearchArgs,
            KBSearchResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: KBSearchArgs
    ) -> KBSearchResult:
        ranked = kb.search_text(args.query, limit=args.k)
        return KBSearchResult(
            hits=[
                KBSearchHit(node_id=n.id, label=n.label, score=score, kind=n.kind.value)
                for n, score in ranked
            ]
        )


def build_tool() -> MemoryTool[KBSearchArgs, KBSearchResult]:
    return KBSearchTool()
