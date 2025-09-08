from __future__ import annotations

from pydantic import BaseModel

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class SymbolAddress(BaseModel):
    va: int
    name: str


class MapSymbolAddressesArgs(BaseModel):
    add_to_kb: bool = True


class MapSymbolAddressesResult(BaseModel):
    symbols: list[SymbolAddress]
    evidence_node_id: str | None = None


class MapSymbolAddressesTool(
    MemoryTool[MapSymbolAddressesArgs, MapSymbolAddressesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="map_symbol_addresses",
                description="Build an address→symbol map for defined symbols.",
                tags=("symbols", "kb"),
            ),
            MapSymbolAddressesArgs,
            MapSymbolAddressesResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: MapSymbolAddressesArgs
    ) -> MapSymbolAddressesResult:
        pairs: list[tuple[int, str]] = []
        try:
            pairs = g.symbols.symbol_address_map(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            )
        except Exception:
            pairs = []
        entries = [SymbolAddress(va=int(a), name=str(n)) for (a, n) in pairs]
        ev_id = None
        if args.add_to_kb and entries:
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="symbol_addresses",
                    props={"count": len(entries)},
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
        return MapSymbolAddressesResult(symbols=entries, evidence_node_id=ev_id)


def build_tool() -> MemoryTool[MapSymbolAddressesArgs, MapSymbolAddressesResult]:
    return MapSymbolAddressesTool()
