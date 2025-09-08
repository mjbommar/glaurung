from __future__ import annotations

from pydantic import BaseModel

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class ElfGotMapArgs(BaseModel):
    add_to_kb: bool = True


class GotEntry(BaseModel):
    va: int
    name: str


class ElfGotMapResult(BaseModel):
    entries: list[GotEntry]
    evidence_node_id: str | None = None


class ElfGotMapTool(MemoryTool[ElfGotMapArgs, ElfGotMapResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="map_elf_got",
                description="Extract ELF GOT map and optionally import into KB.",
                tags=("symbols", "elf", "kb"),
            ),
            ElfGotMapArgs,
            ElfGotMapResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: ElfGotMapArgs
    ) -> ElfGotMapResult:
        entries: list[GotEntry] = []
        ev_id = None
        try:
            pairs = g.analysis.elf_got_map_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            )
            for va, name in pairs:
                entries.append(GotEntry(va=int(va), name=str(name)))
        except Exception:
            entries = []
        if args.add_to_kb and entries:
            ev = kb.add_node(Node(kind=NodeKind.evidence, label="map_elf_got"))
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
            for e in entries:
                n = kb.add_node(
                    Node(kind=NodeKind.import_sym, label=e.name, props={"va": e.va})
                )
                kb.add_edge(Edge(src=ev.id, dst=n.id, kind="got_entry"))
        return ElfGotMapResult(entries=entries, evidence_node_id=ev_id)


def build_tool() -> MemoryTool[ElfGotMapArgs, ElfGotMapResult]:
    return ElfGotMapTool()
