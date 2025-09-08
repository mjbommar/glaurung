from __future__ import annotations

from pydantic import BaseModel

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class SymbolsListArgs(BaseModel):
    add_to_kb: bool = True


class SymbolsListResult(BaseModel):
    imports: list[str]
    exports: list[str]
    libs: list[str]
    evidence_node_id: str | None = None


class SymbolsListTool(MemoryTool[SymbolsListArgs, SymbolsListResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="view_symbols",
                description="List imports/exports/libs and optionally import into KB.",
                tags=("symbols", "kb"),
            ),
            SymbolsListArgs,
            SymbolsListResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: SymbolsListArgs
    ) -> SymbolsListResult:
        imports: list[str] = []
        exports: list[str] = []
        libs: list[str] = []
        try:
            _all, _dyn, imps, exps, libnames = g.triage.list_symbols(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            )
            imports = [str(s) for s in imps]
            exports = [str(s) for s in exps]
            libs = [str(s) for s in libnames]
        except Exception:
            pass
        ev_id = None
        if args.add_to_kb and (imports or exports or libs):
            ev = kb.add_node(Node(kind=NodeKind.evidence, label="view_symbols"))
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
            for name in imports[:200]:
                n = kb.add_node(
                    Node(kind=NodeKind.import_sym, label=str(name), tags=["import"])
                )
                kb.add_edge(Edge(src=ev.id, dst=n.id, kind="imports"))
            for name in exports[:200]:
                n = kb.add_node(Node(kind=NodeKind.note, label=f"export:{name}"))
                kb.add_edge(Edge(src=ev.id, dst=n.id, kind="exports"))
            for name in libs[:100]:
                n = kb.add_node(Node(kind=NodeKind.note, label=f"lib:{name}"))
                kb.add_edge(Edge(src=ev.id, dst=n.id, kind="lib"))
        return SymbolsListResult(
            imports=imports, exports=exports, libs=libs, evidence_node_id=ev_id
        )


def build_tool() -> MemoryTool[SymbolsListArgs, SymbolsListResult]:
    return SymbolsListTool()
