from __future__ import annotations

import re
from typing import Iterable, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


EncKind = Literal["ascii", "utf16le", "utf16be"]


def _scan_ascii(data: bytes, min_len: int) -> Iterable[tuple[str, int, EncKind]]:
    start = None
    for i, b in enumerate(data):
        if 32 <= b < 127:  # printable ASCII
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                yield data[start:i].decode("ascii", errors="ignore"), start, "ascii"
            start = None
    if start is not None and len(data) - start >= min_len:
        yield data[start:].decode("ascii", errors="ignore"), start, "ascii"


def _scan_utf16le(data: bytes, min_len: int) -> Iterable[tuple[str, int, EncKind]]:
    if len(data) < 2:
        return
    run = []  # list of (byte, index)
    i = 0
    while i + 1 < len(data):
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            run.append((lo, i))
            i += 2
            continue
        if run:
            if len(run) >= min_len:
                text = bytes(b for b, _ in run).decode("ascii", errors="ignore")
                start = run[0][1]
                yield text, start, "utf16le"
            run.clear()
        i += 2
    if run and len(run) >= min_len:
        text = bytes(b for b, _ in run).decode("ascii", errors="ignore")
        start = run[0][1]
        yield text, start, "utf16le"


def _scan_utf16be(data: bytes, min_len: int) -> Iterable[tuple[str, int, EncKind]]:
    if len(data) < 2:
        return
    run = []
    i = 0
    while i + 1 < len(data):
        hi = data[i]
        lo = data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            run.append((lo, i))
            i += 2
            continue
        if run:
            if len(run) >= min_len:
                text = bytes(b for b, _ in run).decode("ascii", errors="ignore")
                start = run[0][1]
                yield text, start, "utf16be"
            run.clear()
        i += 2
    if run and len(run) >= min_len:
        text = bytes(b for b, _ in run).decode("ascii", errors="ignore")
        start = run[0][1]
        yield text, start, "utf16be"


class StringsSearchArgs(BaseModel):
    query: str = Field(..., description="Substring or regex to search within strings")
    case_sensitive: bool = False
    regex: bool = False
    encodings: list[EncKind] = Field(
        default_factory=lambda: ["ascii", "utf16le", "utf16be"],
        description="Encodings to scan",
    )
    min_length: int = 4
    max_results: int | None = None
    max_scan_bytes: int | None = None
    add_to_kb: bool = True


class StringMatch(BaseModel):
    text: str
    offset: int
    encoding: EncKind


class StringsSearchResult(BaseModel):
    matches: list[StringMatch]
    scanned_bytes: int
    evidence_node_id: str | None = None


class StringsSearchTool(MemoryTool[StringsSearchArgs, StringsSearchResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="search_strings",
                description="Scan file bytes for ASCII/UTF16 strings and search by pattern.",
                tags=("strings", "kb"),
            ),
            StringsSearchArgs,
            StringsSearchResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: StringsSearchArgs
    ) -> StringsSearchResult:
        max_bytes = args.max_scan_bytes or ctx.budgets.max_read_bytes
        buf = b""
        try:
            with open(ctx.file_path, "rb") as f:
                buf = f.read(max_bytes)
        except FileNotFoundError:
            buf = b""

        scanners: list = []
        if "ascii" in args.encodings:
            scanners.append(_scan_ascii(buf, args.min_length))
        if "utf16le" in args.encodings:
            scanners.append(_scan_utf16le(buf, args.min_length))
        if "utf16be" in args.encodings:
            scanners.append(_scan_utf16be(buf, args.min_length))

        # Build matcher
        if args.regex:
            flags = 0 if args.case_sensitive else re.IGNORECASE
            try:
                pattern = re.compile(args.query, flags)
            except re.error:
                pattern = None
        else:
            pattern = None
            q = args.query if args.case_sensitive else args.query.lower()

        out: list[StringMatch] = []
        limit = args.max_results or ctx.budgets.max_results
        for it in scanners:
            for text, off, enc in it:
                if pattern is not None:
                    if not pattern.search(text):
                        continue
                else:
                    hay = text if args.case_sensitive else text.lower()
                    if q not in hay:
                        continue
                out.append(StringMatch(text=text, offset=off, encoding=enc))
                if len(out) >= limit:
                    break
            if len(out) >= limit:
                break

        ev_id = None
        if args.add_to_kb and out:
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="search_strings",
                    props={"query": args.query, "count": len(out)},
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return StringsSearchResult(
            matches=out, scanned_bytes=len(buf), evidence_node_id=ev_id
        )


def build_tool() -> MemoryTool[StringsSearchArgs, StringsSearchResult]:
    return StringsSearchTool()
