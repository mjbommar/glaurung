from __future__ import annotations

from pydantic import BaseModel

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class PeIatMapArgs(BaseModel):
    add_to_kb: bool = True


class IatEntry(BaseModel):
    va: int
    name: str


class PeIatMapResult(BaseModel):
    entries: list[IatEntry]
    evidence_node_id: str | None = None


class PeIatMapTool(MemoryTool[PeIatMapArgs, PeIatMapResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="map_pe_iat",
                description="Extract PE IAT map and optionally import into KB.",
                tags=("symbols", "pe", "kb"),
            ),
            PeIatMapArgs,
            PeIatMapResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: PeIatMapArgs
    ) -> PeIatMapResult:
        entries: list[IatEntry] = []
        ev_id = None
        try:
            pairs = g.analysis.pe_iat_map_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            )
            for va, name in pairs:
                entries.append(IatEntry(va=int(va), name=str(name)))
        except Exception:
            entries = []
        if args.add_to_kb and entries:
            ev = kb.add_node(Node(kind=NodeKind.evidence, label="map_pe_iat"))
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
            for e in entries:
                n = kb.add_node(
                    Node(kind=NodeKind.import_sym, label=e.name, props={"va": e.va})
                )
                kb.add_edge(Edge(src=ev.id, dst=n.id, kind="iat_entry"))
        return PeIatMapResult(entries=entries, evidence_node_id=ev_id)


def build_tool() -> MemoryTool[PeIatMapArgs, PeIatMapResult]:
    return PeIatMapTool()
