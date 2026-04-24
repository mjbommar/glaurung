"""Tools: xrefs-to / xrefs-from a given VA.

IDA's "X" key, as an agent-callable tool pair. Built on top of
``g.analysis.analyze_functions_path`` which returns a bounded call-graph.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Dict, List, Tuple

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class XrefArgs(BaseModel):
    va: int = Field(..., description="Target virtual address")
    max_results: int = Field(32, description="Cap on returned refs (default 32)")


class XrefEntry(BaseModel):
    va: int
    name: str | None = None
    kind: str = Field(
        "call",
        description="Reference kind: 'call' (direct control-flow) or 'data' "
                    "(load/store reference).",
    )


class XrefResult(BaseModel):
    target_va: int
    refs: List[XrefEntry]


@lru_cache(maxsize=4)
def _analyse(path: str):
    """Memoised per-path analyser (expensive to recompute)."""
    funcs, cg = g.analysis.analyze_functions_path(path)
    # Build name → entry-VA and entry-VA → name indexes.
    va_by_name: Dict[str, int] = {}
    name_by_va: Dict[int, str] = {}
    for f in funcs:
        ev = int(f.entry_point.value)
        va_by_name[f.name] = ev
        name_by_va[ev] = f.name
    # Callgraph edges → (caller_va, callee_va, caller_name, callee_name).
    edges: List[Tuple[int, int, str, str]] = []
    for e in cg.edges:
        c = va_by_name.get(e.caller)
        t = va_by_name.get(e.callee)
        if c is not None and t is not None:
            edges.append((c, t, e.caller, e.callee))
    return funcs, edges, name_by_va


def _containing_function(funcs, va: int) -> Tuple[int, str] | None:
    for f in funcs:
        start = int(f.entry_point.value)
        for bb in f.basic_blocks:
            if int(bb.start_address.value) <= va < int(bb.end_address.value):
                return start, f.name
        if start == va:
            return start, f.name
    return None


class ListXrefsToTool(MemoryTool[XrefArgs, XrefResult]):
    """Return every function that calls into the given VA (or a block inside it)."""

    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="list_xrefs_to",
                description="Return control-flow references that land at or "
                            "inside the function starting at this VA "
                            "(IDA's 'X' key, incoming direction).",
                tags=("analysis", "xrefs"),
            ),
            XrefArgs,
            XrefResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: XrefArgs,
    ) -> XrefResult:
        funcs, edges, name_by_va = _analyse(str(ctx.file_path))
        target = int(args.va)
        refs: List[XrefEntry] = []
        for caller_va, callee_va, caller_name, _ in edges:
            if callee_va == target:
                refs.append(
                    XrefEntry(va=caller_va, name=caller_name, kind="call")
                )
                if len(refs) >= args.max_results:
                    break
        return XrefResult(target_va=target, refs=refs)


class ListXrefsFromTool(MemoryTool[XrefArgs, XrefResult]):
    """Return every function that `va` (or its containing function) calls."""

    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="list_xrefs_from",
                description="Return the direct-call targets reachable from "
                            "the function containing this VA (outgoing "
                            "direction).",
                tags=("analysis", "xrefs"),
            ),
            XrefArgs,
            XrefResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: XrefArgs,
    ) -> XrefResult:
        funcs, edges, name_by_va = _analyse(str(ctx.file_path))
        target = int(args.va)
        # Find the containing function's entry VA.
        cf = _containing_function(funcs, target)
        if cf is None:
            return XrefResult(target_va=target, refs=[])
        fn_va, _ = cf
        refs: List[XrefEntry] = []
        seen: set[int] = set()
        for caller_va, callee_va, _caller_name, callee_name in edges:
            if caller_va == fn_va and callee_va not in seen:
                seen.add(callee_va)
                refs.append(
                    XrefEntry(va=callee_va, name=callee_name, kind="call")
                )
                if len(refs) >= args.max_results:
                    break
        return XrefResult(target_va=target, refs=refs)


def build_xrefs_to() -> MemoryTool[XrefArgs, XrefResult]:
    return ListXrefsToTool()


def build_xrefs_from() -> MemoryTool[XrefArgs, XrefResult]:
    return ListXrefsFromTool()
