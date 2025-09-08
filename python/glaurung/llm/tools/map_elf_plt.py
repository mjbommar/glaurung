from __future__ import annotations

from pydantic import BaseModel

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class ElfPltMapArgs(BaseModel):
    add_to_kb: bool = True


class PltEntry(BaseModel):
    va: int
    name: str


class ElfPltMapResult(BaseModel):
    entries: list[PltEntry]
    evidence_node_id: str | None = None


class ElfPltMapTool(MemoryTool[ElfPltMapArgs, ElfPltMapResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="map_elf_plt",
                description="Extract ELF PLT map and optionally import into KB.",
                tags=("symbols", "elf", "kb"),
            ),
            ElfPltMapArgs,
            ElfPltMapResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: ElfPltMapArgs
    ) -> ElfPltMapResult:
        entries: list[PltEntry] = []
        ev_id = None
        try:
            pairs = g.analysis.elf_plt_map_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            )
            for va, name in pairs:
                entries.append(PltEntry(va=int(va), name=str(name)))
        except Exception:
            entries = []
        if args.add_to_kb and entries:
            ev = kb.add_node(Node(kind=NodeKind.evidence, label="map_elf_plt"))
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
            for e in entries:
                n = kb.add_node(
                    Node(kind=NodeKind.import_sym, label=e.name, props={"va": e.va})
                )
                kb.add_edge(Edge(src=ev.id, dst=n.id, kind="plt_entry"))
        return ElfPltMapResult(entries=entries, evidence_node_id=ev_id)


def build_tool() -> MemoryTool[ElfPltMapArgs, ElfPltMapResult]:
    return ElfPltMapTool()
