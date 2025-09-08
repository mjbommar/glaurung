from __future__ import annotations

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class FunctionItem(BaseModel):
    name: str
    entry_va: int
    size: int | None = None
    blocks: int | None = None
    edges: int | None = None


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
                description="Enumerate discovered functions with entry VA, size, and block counts.",
                tags=("analysis", "kb"),
            ),
            ListFunctionsArgs,
            ListFunctionsResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: ListFunctionsArgs
    ) -> ListFunctionsResult:
        try:
            funcs, _cg = g.analysis.analyze_functions_path(
                ctx.file_path,
                ctx.budgets.max_read_bytes,
                ctx.budgets.max_file_size,
                max_functions=args.max_functions or ctx.budgets.max_functions,
                max_blocks=ctx.budgets.max_blocks,
                max_instructions=ctx.budgets.max_instructions,
                timeout_ms=ctx.budgets.timeout_ms,
            )
        except Exception:
            funcs = []

        out: list[FunctionItem] = []
        for f in funcs:
            try:
                size = (
                    int(getattr(f, "size", 0) or 0)
                    if getattr(f, "size", None) is not None
                    else None
                )
            except Exception:
                size = None
            try:
                blocks = len(f.basic_blocks)
                edges = sum(len(bb.successor_ids) for bb in f.basic_blocks)
            except Exception:
                blocks = None
                edges = None
            out.append(
                FunctionItem(
                    name=str(getattr(f, "name", "func")),
                    entry_va=int(
                        getattr(
                            getattr(f, "entry_point", 0),
                            "value",
                            getattr(f, "entry_point", 0),
                        )
                        or 0
                    ),
                    size=size,
                    blocks=blocks,
                    edges=edges,
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
