from __future__ import annotations

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class AddNoteArgs(BaseModel):
    text: str = Field(..., description="Analyst/LLM note text")
    tags: list[str] = Field(default_factory=list)


class AddNoteResult(BaseModel):
    node_id: str


class AddNoteTool(MemoryTool[AddNoteArgs, AddNoteResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="kb_add_note",
                description="Add a freeform note into the knowledge base",
                tags=("kb", "note"),
            ),
            AddNoteArgs,
            AddNoteResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: AddNoteArgs
    ) -> AddNoteResult:
        n = kb.add_node(
            Node(
                kind=NodeKind.note, label=args.text[:64], text=args.text, tags=args.tags
            )
        )
        return AddNoteResult(node_id=n.id)


def build_tool() -> MemoryTool[AddNoteArgs, AddNoteResult]:
    return AddNoteTool()
