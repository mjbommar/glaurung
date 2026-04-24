"""Tool: list the direct-call targets of a single function.

Complements list_xrefs_from with a name-resolved, deduplicated output
keyed explicitly on one function's entry VA. Handy when the agent has
already identified the function of interest and just wants its callee
set without the surrounding callgraph query.
"""

from __future__ import annotations

from typing import List, Set

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .xrefs import _analyse  # noqa: F401 — re-use the memoised analyser


class ListCallsArgs(BaseModel):
    func_va: int = Field(..., description="Entry VA of the caller function")
    max_results: int = Field(64, description="Cap on returned callees")


class Callee(BaseModel):
    va: int
    name: str | None = None
    # 'internal' when the callee is another function discovered in this binary
    # and 'external' when the call target is a PLT/IAT import resolved by
    # the name-resolution pass. Unknown callees fall into 'external' too.
    kind: str = "internal"


class ListCallsResult(BaseModel):
    caller_va: int
    callees: List[Callee]


class ListCallsFromFunctionTool(
    MemoryTool[ListCallsArgs, ListCallsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="list_calls_from_function",
                description="Return the deduplicated set of direct-call "
                            "targets reachable from the function whose "
                            "entry is `func_va`. Cheaper than "
                            "list_xrefs_from when the caller's VA is known.",
                tags=("analysis", "xrefs"),
            ),
            ListCallsArgs,
            ListCallsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ListCallsArgs,
    ) -> ListCallsResult:
        funcs, edges, name_by_va = _analyse(str(ctx.file_path))
        caller_va = int(args.func_va)
        callees: List[Callee] = []
        seen: Set[int] = set()
        internal_vas = {int(f.entry_point.value) for f in funcs}
        for c_va, t_va, _cn, t_name in edges:
            if c_va != caller_va:
                continue
            if t_va in seen:
                continue
            seen.add(t_va)
            kind = "internal" if t_va in internal_vas else "external"
            callees.append(Callee(va=t_va, name=t_name, kind=kind))
            if len(callees) >= args.max_results:
                break
        return ListCallsResult(caller_va=caller_va, callees=callees)


def build_tool() -> MemoryTool[ListCallsArgs, ListCallsResult]:
    return ListCallsFromFunctionTool()
