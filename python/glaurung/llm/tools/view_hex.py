from __future__ import annotations

import string
from typing import Optional

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


def _to_ascii_preview(data: bytes, width: int = 16) -> list[str]:
    lines: list[str] = []
    printable = set(bytes(string.printable, "ascii"))
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(
            chr(b) if b in printable and 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"{hexpart:<{width * 3}}  {asciipart}")
    return lines


class BytesViewArgs(BaseModel):
    va: Optional[int] = Field(
        None, description="Virtual address to read from (exclusive with file_offset)"
    )
    file_offset: Optional[int] = Field(
        None, description="File offset to read from (exclusive with va)"
    )
    length: int = Field(64, description="Bytes to read (bounded by budgets)")
    add_to_kb: bool = True


class BytesViewResult(BaseModel):
    start_va: int | None = None
    start_offset: int | None = None
    length: int
    bytes_hex: str
    ascii_preview: list[str]
    evidence_node_id: str | None = None


class BytesViewTool(MemoryTool[BytesViewArgs, BytesViewResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="view_hex",
                description="Read raw bytes from a VA or file offset with hex+ASCII preview.",
                tags=("bytes", "kb"),
            ),
            BytesViewArgs,
            BytesViewResult,
        )

    def _resolve_offset(
        self, ctx: MemoryContext, args: BytesViewArgs
    ) -> tuple[int | None, int | None]:
        if args.file_offset is not None and args.va is not None:
            raise ValueError("Specify either 'va' or 'file_offset', not both")
        if args.file_offset is not None:
            return None, max(0, int(args.file_offset))
        if args.va is not None:
            va = int(args.va)
            try:
                off = g.analysis.va_to_file_offset_path(
                    ctx.file_path,
                    va,
                    ctx.budgets.max_read_bytes,
                    ctx.budgets.max_file_size,
                )
            except Exception:
                off = None
            if off is None:
                return va, None
            return va, int(off)
        # default: start of file
        return None, 0

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: BytesViewArgs
    ) -> BytesViewResult:
        s_va, s_off = self._resolve_offset(ctx, args)
        nbytes = min(int(args.length), max(0, ctx.budgets.max_read_bytes))
        buf = b""
        if s_off is not None and nbytes > 0:
            try:
                with open(ctx.file_path, "rb") as f:
                    f.seek(s_off)
                    buf = f.read(nbytes)
            except FileNotFoundError:
                buf = b""
        hexstr = buf.hex()
        preview = _to_ascii_preview(buf)
        ev_id = None
        if args.add_to_kb:
            label = (
                f"bytes@0x{s_va:x}"
                if s_va is not None
                else f"bytes@off:{s_off}"
                if s_off is not None
                else "bytes@file"
            )
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label=label,
                    props={"start_va": s_va, "start_offset": s_off, "length": len(buf)},
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return BytesViewResult(
            start_va=s_va,
            start_offset=s_off,
            length=len(buf),
            bytes_hex=hexstr,
            ascii_preview=preview,
            evidence_node_id=ev_id,
        )


def build_tool() -> MemoryTool[BytesViewArgs, BytesViewResult]:
    return BytesViewTool()
