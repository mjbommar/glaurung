"""Tool: IDA-style byte-pattern search with ``??`` wildcards.

Handy for hunting known opcode sequences (jump gadgets, crypto S-box
prologues, syscall stubs, etc.) in the raw file bytes. Accepts the
classic hex-with-wildcards syntax that most RE tools expose:

    "48 8B ?? ?? ?? 89 ??"      # seven bytes, five wildcards
    "48?8B????????8B"            # whitespace optional

Matches are reported as (file-offset, virtual-address-if-resolvable)
pairs together with a short surrounding byte context.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class SearchBytePatternArgs(BaseModel):
    pattern: str = Field(
        ...,
        description="Hex pattern with optional ``??`` wildcards, e.g. "
                    "'48 8B ?? ?? ?? 89 ??'. Whitespace is optional.",
    )
    max_results: int = Field(64, description="Cap on returned matches")
    max_scan_bytes: int | None = Field(
        None,
        description="Cap on bytes scanned (defaults to ctx.budgets.max_read_bytes)",
    )
    resolve_va: bool = Field(
        True,
        description="When True, attempt to resolve each match's file offset to "
                    "a virtual address via the ELF/PE/Mach-O section map.",
    )
    context_bytes: int = Field(
        8,
        description="Number of bytes of surrounding context to include per hit.",
    )


class BytePatternMatch(BaseModel):
    offset: int
    va: Optional[int] = None
    context_hex: str = Field(
        ..., description="Hex dump of offset-context_bytes .. offset+len+context_bytes"
    )


class SearchBytePatternResult(BaseModel):
    pattern: str
    pattern_len: int
    matches: List[BytePatternMatch]
    scanned_bytes: int


_HEX_RE = re.compile(r"^[0-9a-fA-F?]+$")


def _parse_pattern(pattern: str) -> Tuple[bytes, bytes]:
    """Return ``(needle, mask)`` where a mask byte of 0xFF means
    'exact match' and 0x00 means 'wildcard'.

    The parser tolerates whitespace and rejects anything that leaves
    the pattern with an odd nibble count (each byte needs two chars).
    """
    stripped = re.sub(r"\s+", "", pattern)
    if not stripped or not _HEX_RE.match(stripped):
        raise ValueError(
            f"invalid byte pattern {pattern!r} — expected hex/?? nibbles"
        )
    if len(stripped) % 2 != 0:
        raise ValueError(
            f"byte pattern has odd nibble count ({len(stripped)}): {pattern!r}"
        )
    needle = bytearray(len(stripped) // 2)
    mask = bytearray(len(stripped) // 2)
    for i in range(0, len(stripped), 2):
        hi, lo = stripped[i], stripped[i + 1]
        if hi == "?" and lo == "?":
            needle[i // 2] = 0
            mask[i // 2] = 0
            continue
        if hi == "?" or lo == "?":
            # Nibble-level wildcarding ("4?" / "?8") is possible but we keep
            # the interface byte-level like IDA's "B".
            raise ValueError(
                f"half-byte wildcards are not supported (got '{hi}{lo}')"
            )
        needle[i // 2] = int(hi + lo, 16)
        mask[i // 2] = 0xFF
    return bytes(needle), bytes(mask)


def _search(data: bytes, needle: bytes, mask: bytes, limit: int) -> List[int]:
    """Masked substring search. Straight-line — pattern lengths are small and
    this is I/O bound in practice.
    """
    out: List[int] = []
    n = len(needle)
    if n == 0:
        return out
    # Fast path: no wildcards — delegate to bytes.find loop.
    if all(m == 0xFF for m in mask):
        start = 0
        while True:
            pos = data.find(needle, start)
            if pos < 0:
                break
            out.append(pos)
            if len(out) >= limit:
                break
            start = pos + 1
        return out
    # Masked search.
    end = len(data) - n + 1
    for i in range(end):
        ok = True
        for j in range(n):
            if mask[j] == 0xFF and data[i + j] != needle[j]:
                ok = False
                break
        if ok:
            out.append(i)
            if len(out) >= limit:
                break
    return out


class SearchBytePatternTool(
    MemoryTool[SearchBytePatternArgs, SearchBytePatternResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="search_byte_pattern",
                description="Search file bytes for a hex pattern with '??' "
                            "wildcards (IDA/Ghidra style). Returns file "
                            "offsets and, when possible, virtual addresses.",
                tags=("analysis", "bytes"),
            ),
            SearchBytePatternArgs,
            SearchBytePatternResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: SearchBytePatternArgs,
    ) -> SearchBytePatternResult:
        try:
            needle, mask = _parse_pattern(args.pattern)
        except ValueError:
            # Return an empty result rather than raising so an LLM agent
            # that hands us a malformed pattern can read the zero-match
            # reply and try again.
            return SearchBytePatternResult(
                pattern=args.pattern, pattern_len=0, matches=[], scanned_bytes=0
            )
        max_bytes = args.max_scan_bytes or ctx.budgets.max_read_bytes
        try:
            with open(ctx.file_path, "rb") as f:
                data = f.read(max_bytes)
        except FileNotFoundError:
            data = b""

        positions = _search(data, needle, mask, max(1, args.max_results))

        matches: List[BytePatternMatch] = []
        for pos in positions:
            va: Optional[int] = None
            if args.resolve_va:
                va = _offset_to_va(str(ctx.file_path), pos, ctx)
            ctx_lo = max(0, pos - args.context_bytes)
            ctx_hi = min(len(data), pos + len(needle) + args.context_bytes)
            matches.append(
                BytePatternMatch(
                    offset=pos,
                    va=va,
                    context_hex=data[ctx_lo:ctx_hi].hex(),
                )
            )

        return SearchBytePatternResult(
            pattern=args.pattern,
            pattern_len=len(needle),
            matches=matches,
            scanned_bytes=len(data),
        )


def _offset_to_va(path: str, offset: int, ctx: MemoryContext) -> Optional[int]:
    """Best-effort file-offset → VA resolution.

    ``glaurung.analysis`` ships the opposite direction (``va_to_file_offset_path``)
    but not the inverse. Rather than ship a second API we probe a small set
    of candidate VAs derived from typical load bases — this keeps the tool
    useful for ELF/PE without growing the Rust surface.
    """
    # Try a handful of common load bases. If any round-trips cleanly we
    # accept it. This is approximate but good enough for RE navigation.
    for base in (0x400000, 0x10000000, 0x140000000, 0x0, 0x10000):
        cand = base + offset
        try:
            back = g.analysis.va_to_file_offset_path(path, cand)
        except Exception:
            back = None
        if back == offset:
            return cand
    return None


def build_tool() -> MemoryTool[SearchBytePatternArgs, SearchBytePatternResult]:
    return SearchBytePatternTool()
