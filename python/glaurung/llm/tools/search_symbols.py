from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


WhereKind = Literal["all", "dynamic", "imports", "exports", "libs"]


class SymbolsSearchArgs(BaseModel):
    query: str = Field(..., description="Substring or regex to search for")
    where: list[WhereKind] = Field(
        default_factory=lambda: ["all", "imports", "exports"],
        description="Symbol categories to search",
    )
    case_sensitive: bool = False
    regex: bool = False
    demangle: bool = True
    max_results: int | None = None
    add_to_kb: bool = True


class SymbolMatch(BaseModel):
    name: str
    category: WhereKind


class SymbolsSearchResult(BaseModel):
    matches: list[SymbolMatch]
    total_scanned: int
    evidence_node_id: str | None = None


class SymbolsSearchTool(MemoryTool[SymbolsSearchArgs, SymbolsSearchResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="search_symbols",
                description="Search symbols by substring or regex across categories.",
                tags=("symbols", "kb"),
            ),
            SymbolsSearchArgs,
            SymbolsSearchResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: SymbolsSearchArgs
    ) -> SymbolsSearchResult:
        # Load symbols (demangled if requested)
        try:
            if args.demangle:
                all_syms, dyn_syms, imports, exports, libs = (
                    g.symbols.list_symbols_demangled(
                        ctx.file_path,
                        ctx.budgets.max_read_bytes,
                        ctx.budgets.max_file_size,
                    )
                )
            else:
                all_syms, dyn_syms, imports, exports, libs = g.symbols.list_symbols(
                    ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
                )
        except Exception:
            all_syms, dyn_syms, imports, exports, libs = [], [], [], [], []

        cat_map: dict[WhereKind, list[str]] = {
            "all": all_syms,
            "dynamic": dyn_syms,
            "imports": imports,
            "exports": exports,
            "libs": libs,
        }
        targets: list[tuple[str, WhereKind]] = []
        for c in args.where:
            if c in cat_map:
                targets.extend((s, c) for s in cat_map[c])
        # dedupe targets by (name, category) to avoid duplicates from overlaps
        seen: set[tuple[str, WhereKind]] = set()
        filtered: list[SymbolMatch] = []
        total = 0

        # Build matcher
        if args.regex:
            flags = 0 if args.case_sensitive else re.IGNORECASE
            try:
                pattern = re.compile(args.query, flags)
            except re.error:
                pattern = None
        else:
            pattern = None
            q = args.query if args.case_sensitive else args.query.lower()

        max_results = args.max_results or ctx.budgets.max_results
        for name, cat in targets:
            total += 1
            k = (name, cat)
            if k in seen:
                continue
            seen.add(k)
            if pattern is not None:
                if not pattern.search(name):
                    continue
            else:
                hay = name if args.case_sensitive else name.lower()
                if q not in hay:
                    continue
            filtered.append(SymbolMatch(name=name, category=cat))
            if len(filtered) >= max_results:
                break

        ev_id = None
        if args.add_to_kb and filtered:
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="search_symbols",
                    props={"query": args.query, "count": len(filtered)},
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return SymbolsSearchResult(
            matches=filtered, total_scanned=total, evidence_node_id=ev_id
        )


def build_tool() -> MemoryTool[SymbolsSearchArgs, SymbolsSearchResult]:
    return SymbolsSearchTool()
