from __future__ import annotations

from pydantic import BaseModel

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class DetectEntryArgs(BaseModel):
    add_to_kb: bool = True


class DetectEntryResult(BaseModel):
    format: str | None
    arch: str | None
    endianness: str | None
    entry_va: int | None
    file_offset: int | None
    evidence_node_id: str | None = None


class DetectEntryTool(MemoryTool[DetectEntryArgs, DetectEntryResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="view_entry",
                description="Detect binary format, arch, endianness, and entry point.",
                tags=("triage", "kb"),
            ),
            DetectEntryArgs,
            DetectEntryResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: DetectEntryArgs
    ) -> DetectEntryResult:
        fmt = arch = end = entry = off = None
        try:
            det = g.analysis.detect_entry_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            )
            if det:
                fmt, arch, end, entry, off = det
        except Exception:
            pass
        ev_id = None
        if args.add_to_kb and any([fmt, arch, end, entry]):
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="entry",
                    props={
                        "format": str(fmt) if fmt is not None else None,
                        "arch": str(arch) if arch is not None else None,
                        "endianness": str(end) if end is not None else None,
                        "entry_va": int(entry) if entry is not None else None,
                        "file_offset": int(off) if off is not None else None,
                    },
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))
        return DetectEntryResult(
            format=str(fmt) if fmt is not None else None,
            arch=str(arch) if arch is not None else None,
            endianness=str(end) if end is not None else None,
            entry_va=int(entry) if entry is not None else None,
            file_offset=int(off) if off is not None else None,
            evidence_node_id=ev_id,
        )


def build_tool() -> MemoryTool[DetectEntryArgs, DetectEntryResult]:
    return DetectEntryTool()
