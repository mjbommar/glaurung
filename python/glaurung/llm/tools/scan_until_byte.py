"""Tool: walk forward from a VA / file offset until a sentinel byte hits.

Fills the gap between :mod:`view_hex` (xxd-style fixed-length read) and
:mod:`search_byte_pattern` (IDA-style pattern search). The classic use
case is "find the end of this C string" — start at a VA, scan until the
next ``0x00``, and report the offset of the terminator and the bytes
consumed. Works just as well for finding the next ``0xCC`` in a code
cave, the next ``0x0A`` in a log buffer, or any other sentinel.

Deterministic, no LLM, bounded by ``ctx.budgets.max_read_bytes`` and an
explicit per-call ``max_scan_bytes`` so a runaway scan can't burn the
whole budget on a single tool invocation.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class ScanUntilByteArgs(BaseModel):
    va: Optional[int] = Field(
        None, description="Virtual address to start scanning from (exclusive with file_offset)"
    )
    file_offset: Optional[int] = Field(
        None, description="File offset to start scanning from (exclusive with va)"
    )
    sentinels: List[int] = Field(
        default_factory=lambda: [0x00],
        description="Byte values that terminate the scan. Scan stops at the "
        "FIRST occurrence of any value in this list. Default: [0x00] (C-string null terminator).",
    )
    max_scan_bytes: int = Field(
        4096,
        description="Hard cap on bytes scanned before giving up. Bounded by "
        "ctx.budgets.max_read_bytes regardless of this value.",
    )
    include_sentinel: bool = Field(
        False,
        description="If True, the sentinel byte is included in `bytes_consumed`. "
        "If False (default), bytes_consumed contains only the bytes BEFORE the sentinel.",
    )
    add_to_kb: bool = True

    @field_validator("sentinels")
    @classmethod
    def _validate_sentinels(cls, v: List[int]) -> List[int]:
        if not v:
            raise ValueError("sentinels must contain at least one byte value")
        for b in v:
            if not 0 <= int(b) <= 0xFF:
                raise ValueError(f"sentinel byte {b} out of range 0..255")
        # Deduplicate while preserving order so the result is stable.
        seen: set[int] = set()
        out: list[int] = []
        for b in v:
            ib = int(b)
            if ib not in seen:
                seen.add(ib)
                out.append(ib)
        return out


class ScanUntilByteResult(BaseModel):
    start_va: Optional[int] = None
    start_offset: Optional[int] = None
    found: bool = Field(
        ..., description="True iff a sentinel byte was hit before max_scan_bytes ran out."
    )
    sentinel_value: Optional[int] = Field(
        None, description="The sentinel byte that hit, or None if not found."
    )
    sentinel_offset: Optional[int] = Field(
        None,
        description="File offset of the sentinel byte itself (independent of include_sentinel).",
    )
    sentinel_va: Optional[int] = Field(
        None, description="VA of the sentinel byte if a starting VA was provided."
    )
    bytes_consumed: int = Field(
        ..., description="Number of bytes returned in `data_hex` (length of the scanned slice)."
    )
    data_hex: str = Field(
        ..., description="Hex of the scanned slice. By default does NOT include the sentinel."
    )
    truncated: bool = Field(
        ...,
        description="True iff the scan stopped because of max_scan_bytes (not because a sentinel hit).",
    )
    evidence_node_id: Optional[str] = None


class ScanUntilByteTool(MemoryTool[ScanUntilByteArgs, ScanUntilByteResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="scan_until_byte",
                description=(
                    "Walk forward from a VA or file offset until any of the given "
                    "sentinel bytes is hit (default 0x00). Use to locate C-string "
                    "terminators, code-cave padding boundaries, record separators, "
                    "or any byte-driven boundary. Returns offset+VA of the sentinel "
                    "and the bytes consumed up to (or including) it."
                ),
                tags=("bytes", "kb"),
            ),
            ScanUntilByteArgs,
            ScanUntilByteResult,
        )

    def _resolve_offset(
        self, ctx: MemoryContext, args: ScanUntilByteArgs
    ) -> tuple[Optional[int], Optional[int]]:
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
        return None, 0

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ScanUntilByteArgs,
    ) -> ScanUntilByteResult:
        s_va, s_off = self._resolve_offset(ctx, args)
        cap = max(0, min(int(args.max_scan_bytes), ctx.budgets.max_read_bytes))
        if s_off is None or cap == 0:
            return ScanUntilByteResult(
                start_va=s_va,
                start_offset=s_off,
                found=False,
                bytes_consumed=0,
                data_hex="",
                truncated=cap == 0,
            )

        try:
            with open(ctx.file_path, "rb") as f:
                f.seek(s_off)
                buf = f.read(cap)
        except FileNotFoundError:
            buf = b""

        sentinel_set = set(args.sentinels)
        hit_idx: Optional[int] = None
        for i, b in enumerate(buf):
            if b in sentinel_set:
                hit_idx = i
                break

        if hit_idx is None:
            slice_len = len(buf)
            data = buf[:slice_len]
            return ScanUntilByteResult(
                start_va=s_va,
                start_offset=s_off,
                found=False,
                bytes_consumed=slice_len,
                data_hex=data.hex(),
                truncated=slice_len == cap,
            )

        sentinel_val = buf[hit_idx]
        end_idx = hit_idx + 1 if args.include_sentinel else hit_idx
        data = buf[:end_idx]
        sentinel_offset = s_off + hit_idx
        sentinel_va = (s_va + hit_idx) if s_va is not None else None

        ev_id: Optional[str] = None
        if args.add_to_kb:
            label = (
                f"scan@0x{s_va:x}→0x{sentinel_val:02x}"
                if s_va is not None
                else f"scan@off:{s_off}→0x{sentinel_val:02x}"
            )
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label=label,
                    props={
                        "start_va": s_va,
                        "start_offset": s_off,
                        "sentinel": sentinel_val,
                        "sentinel_offset": sentinel_offset,
                        "bytes_consumed": len(data),
                    },
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return ScanUntilByteResult(
            start_va=s_va,
            start_offset=s_off,
            found=True,
            sentinel_value=sentinel_val,
            sentinel_offset=sentinel_offset,
            sentinel_va=sentinel_va,
            bytes_consumed=len(data),
            data_hex=data.hex(),
            truncated=False,
            evidence_node_id=ev_id,
        )


def build_tool() -> MemoryTool[ScanUntilByteArgs, ScanUntilByteResult]:
    return ScanUntilByteTool()
