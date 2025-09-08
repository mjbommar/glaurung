from __future__ import annotations

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class DisasmWindowArgs(BaseModel):
    va: int = Field(..., description="Virtual address to start disassembly")
    window_bytes: int | None = None
    max_instructions: int | None = None
    add_to_kb: bool = True


class DisassembledInst(BaseModel):
    va: int
    bytes_hex: str
    text: str


class DisasmWindowResult(BaseModel):
    instructions: list[DisassembledInst]
    evidence_node_id: str | None = None


class DisasmWindowTool(MemoryTool[DisasmWindowArgs, DisasmWindowResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="view_disassembly",
                description="Disassemble a window at VA using native disassembler.",
                tags=("disasm", "kb"),
            ),
            DisasmWindowArgs,
            DisasmWindowResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: DisasmWindowArgs
    ) -> DisasmWindowResult:
        instrs: list[g.Instruction] = []
        try:
            instrs = g.disasm.disassemble_window_at(
                ctx.file_path,
                int(args.va),
                window_bytes=args.window_bytes or ctx.budgets.max_disasm_window,
                max_instructions=args.max_instructions or ctx.budgets.max_instructions,
                max_time_ms=ctx.budgets.timeout_ms,
            )
        except Exception:
            instrs = []
        out: list[DisassembledInst] = []
        for ins in instrs:
            text = f"{ins.mnemonic} " + ", ".join(
                str(o) for o in getattr(ins, "operands", [])
            )
            out.append(
                DisassembledInst(
                    va=int(ins.address.value),
                    bytes_hex=(ins.bytes or b"").hex(),
                    text=text,
                )
            )
        ev_id = None
        if args.add_to_kb and out:
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label=f"disasm@0x{args.va:x}",
                    props={"count": len(out)},
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
        return DisasmWindowResult(instructions=out, evidence_node_id=ev_id)


def build_tool() -> MemoryTool[DisasmWindowArgs, DisasmWindowResult]:
    return DisasmWindowTool()
