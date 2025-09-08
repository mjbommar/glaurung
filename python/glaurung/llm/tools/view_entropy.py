from __future__ import annotations

from math import log2
from typing import Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
import glaurung as g


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    # 256-bin histogram
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    n = len(data)
    h = 0.0
    for c in hist:
        if c:
            p = c / n
            h -= p * log2(p)
    return float(h)


class EntropyCalcArgs(BaseModel):
    va: Optional[int] = Field(
        None,
        description="Virtual address to start window; if None, compute over file prefix",
    )
    file_offset: Optional[int] = Field(
        None, description="File offset to start window; exclusive with 'va'"
    )
    length: int = Field(
        4096, description="Number of bytes to analyze (bounded by budgets)"
    )
    add_to_kb: bool = True


class EntropyCalcResult(BaseModel):
    entropy: float
    start_va: int | None = None
    start_offset: int | None = None
    length: int
    evidence_node_id: str | None = None


class EntropyCalcTool(MemoryTool[EntropyCalcArgs, EntropyCalcResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="view_entropy",
                description=(
                    "Compute Shannon entropy over file or a specific VA/offset window."
                ),
                tags=("entropy", "kb"),
            ),
            EntropyCalcArgs,
            EntropyCalcResult,
        )

    def _read_window(
        self, ctx: MemoryContext, args: EntropyCalcArgs
    ) -> tuple[bytes, int | None, int | None]:
        # Determine start offset in file
        start_off: int | None = None
        start_va: int | None = None
        if args.file_offset is not None and args.va is not None:
            raise ValueError("Specify either 'va' or 'file_offset', not both")
        if args.file_offset is not None:
            start_off = max(0, int(args.file_offset))
        elif args.va is not None:
            start_va = int(args.va)
            try:
                off = g.analysis.va_to_file_offset_path(
                    ctx.file_path,
                    start_va,
                    ctx.budgets.max_read_bytes,
                    ctx.budgets.max_file_size,
                )
            except Exception:
                off = None
            if off is None:
                # If mapping fails, treat as empty
                return b"", start_va, None
            start_off = int(off)
        else:
            # Whole-file mode: start at 0
            start_off = 0

        # Bound length by budgets and file size
        length = min(int(args.length), max(0, ctx.budgets.max_read_bytes))
        if length <= 0:
            return b"", start_va, start_off
        try:
            with open(ctx.file_path, "rb") as f:
                f.seek(start_off)
                data = f.read(length)
        except FileNotFoundError:
            data = b""
        return data, start_va, start_off

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: EntropyCalcArgs
    ) -> EntropyCalcResult:
        data, s_va, s_off = self._read_window(ctx, args)
        h = _shannon_entropy(data)
        ev_id = None
        if args.add_to_kb:
            label = (
                f"entropy@0x{s_va:x}"
                if s_va is not None
                else f"entropy@off:{s_off}"
                if s_off is not None
                else "entropy@file"
            )
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label=label,
                    props={
                        "entropy": h,
                        "start_va": s_va,
                        "start_offset": s_off,
                        "length": len(data),
                    },
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return EntropyCalcResult(
            entropy=h,
            start_va=s_va,
            start_offset=s_off,
            length=len(data),
            evidence_node_id=ev_id,
        )


def build_tool() -> MemoryTool[EntropyCalcArgs, EntropyCalcResult]:
    return EntropyCalcTool()
