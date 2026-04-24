from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class FunctionItem(BaseModel):
    name: str
    entry_va: int
    end_va: int | None = Field(
        None,
        description="Max end-address across basic blocks — useful for lining up "
                    "a function's extent against external data references.",
    )
    size: int | None = None
    blocks: int | None = None
    edges: int | None = Field(
        None, description="Intra-function CFG edges (successor count sum)."
    )
    total_instr_count: int | None = Field(
        None, description="Total instructions across all basic blocks."
    )
    calls_made: int | None = Field(
        None,
        description="Number of distinct direct-call targets from this function "
                    "(callgraph out-degree).",
    )
    callers_count: int | None = Field(
        None,
        description="Number of distinct functions that directly call this one "
                    "(callgraph in-degree).",
    )


class ListFunctionsArgs(BaseModel):
    max_functions: int | None = Field(None, description="Limit number of functions")
    add_to_kb: bool = True


class ListFunctionsResult(BaseModel):
    functions: list[FunctionItem]
    evidence_node_id: str | None = None


class ListFunctionsTool(MemoryTool[ListFunctionsArgs, ListFunctionsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="list_functions",
                description="Enumerate discovered functions with entry/end VA, "
                            "size, block and instruction counts, and callgraph "
                            "fan-in/out. Useful for prioritising which "
                            "functions an agent should analyse first.",
                tags=("analysis", "kb"),
            ),
            ListFunctionsArgs,
            ListFunctionsResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: ListFunctionsArgs
    ) -> ListFunctionsResult:
        try:
            funcs, cg = g.analysis.analyze_functions_path(
                ctx.file_path,
                ctx.budgets.max_read_bytes,
                ctx.budgets.max_file_size,
                max_functions=args.max_functions or ctx.budgets.max_functions,
                max_blocks=ctx.budgets.max_blocks,
                max_instructions=ctx.budgets.max_instructions,
                timeout_ms=ctx.budgets.timeout_ms,
            )
        except Exception:
            funcs, cg = [], None

        # Callgraph fan-in / fan-out keyed by entry-VA.
        # The callgraph emits synthesized names like ``sub_10c0`` even when the
        # function list already carries resolved names such as ``main`` — so we
        # normalise both sides to a VA before counting.
        va_by_cg_name: dict[str, int] = {}
        for f in funcs:
            ev = int(
                getattr(
                    getattr(f, "entry_point", 0), "value", getattr(f, "entry_point", 0)
                )
                or 0
            )
            va_by_cg_name[f"sub_{ev:x}"] = ev
            va_by_cg_name[str(getattr(f, "name", ""))] = ev

        calls_made_by_va: Counter[int] = Counter()
        callers_by_va: Counter[int] = Counter()
        if cg is not None:
            seen: set[tuple[int, str]] = set()
            for e in cg.edges:
                cva = va_by_cg_name.get(e.caller)
                if cva is None:
                    continue
                # Count every distinct (caller_va, callee_name) pair toward
                # the caller's fan-out — external/PLT targets are still a call.
                out_key = (cva, e.callee)
                if out_key not in seen:
                    seen.add(out_key)
                    calls_made_by_va[cva] += 1
                # Fan-in only counts resolved internal callees.
                tva = va_by_cg_name.get(e.callee)
                if tva is not None:
                    in_key = (cva, str(tva))
                    if in_key not in seen:
                        seen.add(in_key)
                        callers_by_va[tva] += 1

        out: list[FunctionItem] = []
        for f in funcs:
            name = str(getattr(f, "name", "func"))
            try:
                size = (
                    int(getattr(f, "size", 0) or 0)
                    if getattr(f, "size", None) is not None
                    else None
                )
            except Exception:
                size = None
            blocks: int | None
            edges: int | None
            end_va: int | None
            total_instr: int | None
            try:
                bbs = list(f.basic_blocks)
                blocks = len(bbs)
                edges = sum(len(bb.successor_ids) for bb in bbs)
                end_va = (
                    max(int(bb.end_address.value) for bb in bbs) if bbs else None
                )
                total_instr = sum(
                    int(getattr(bb, "instruction_count", 0) or 0) for bb in bbs
                )
            except Exception:
                blocks = None
                edges = None
                end_va = None
                total_instr = None
            entry_va = int(
                getattr(
                    getattr(f, "entry_point", 0),
                    "value",
                    getattr(f, "entry_point", 0),
                )
                or 0
            )
            out.append(
                FunctionItem(
                    name=name,
                    entry_va=entry_va,
                    end_va=end_va,
                    size=size,
                    blocks=blocks,
                    edges=edges,
                    total_instr_count=total_instr,
                    calls_made=(
                        int(calls_made_by_va.get(entry_va, 0))
                        if cg is not None
                        else None
                    ),
                    callers_count=(
                        int(callers_by_va.get(entry_va, 0))
                        if cg is not None
                        else None
                    ),
                )
            )

        ev_id = None
        if args.add_to_kb and out:
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence, label="functions", props={"count": len(out)}
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
            for fi in out:
                fn = kb.add_node(
                    Node(
                        kind=NodeKind.function,
                        label=fi.name,
                        props={"entry_va": fi.entry_va, "size": fi.size},
                    )
                )
                kb.add_edge(Edge(src=ev.id, dst=fn.id, kind="has_function"))

        return ListFunctionsResult(functions=out, evidence_node_id=ev_id)


def build_tool() -> MemoryTool[ListFunctionsArgs, ListFunctionsResult]:
    return ListFunctionsTool()
