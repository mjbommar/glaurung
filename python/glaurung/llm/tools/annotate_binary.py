from __future__ import annotations

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from ..tools.base import MemoryTool, ToolMeta


class AnnotateArgs(BaseModel):
    max_functions: int = Field(5, ge=1, le=100)
    snippet_max_instructions: int = 120
    full_function_instr_threshold: int = 200


class AnnotateResult(BaseModel):
    evidence_node_id: str
    function_count: int
    notes: list[str] = Field(default_factory=list)


class AnnotateBinaryTool(MemoryTool[AnnotateArgs, AnnotateResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="annotate_binary",
                description="Disassemble and annotate functions; import results into KB.",
                tags=("evidence", "analysis"),
            ),
            AnnotateArgs,
            AnnotateResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: AnnotateArgs
    ) -> AnnotateResult:
        # Basic function discovery (fast) and store summary in KB
        try:
            funcs, _cg = g.analysis.analyze_functions_path(
                ctx.file_path,
                ctx.budgets.max_read_bytes,
                ctx.budgets.max_file_size,
                max_functions=args.max_functions,
                max_blocks=ctx.budgets.max_blocks,
                max_instructions=ctx.budgets.max_instructions,
                timeout_ms=ctx.budgets.timeout_ms,
            )
        except Exception as e:
            raise e

        ev_node = kb.add_node(
            Node(kind=NodeKind.evidence, label="functions", props={"count": len(funcs)})
        )
        file_node = None
        for n in kb.nodes():
            if n.kind == NodeKind.file:
                file_node = n
                break
        if file_node:
            kb.add_edge(Edge(src=file_node.id, dst=ev_node.id, kind="has_evidence"))

        for f in funcs:
            fn = kb.add_node(
                Node(
                    kind=NodeKind.function,
                    label=str(getattr(f, "name", "func")),
                    props={
                        "entry_va": int(
                            getattr(
                                getattr(f, "entry_point", 0),
                                "value",
                                getattr(f, "entry_point", 0),
                            )
                            or 0
                        ),
                        "size": int(getattr(f, "size", 0) or 0),
                    },
                )
            )
            kb.add_edge(Edge(src=ev_node.id, dst=fn.id, kind="has_function"))

        return AnnotateResult(
            evidence_node_id=ev_node.id, function_count=len(funcs), notes=[]
        )


def build_tool() -> MemoryTool[AnnotateArgs, AnnotateResult]:
    return AnnotateBinaryTool()
