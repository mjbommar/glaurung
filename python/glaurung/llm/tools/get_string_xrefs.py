"""Tool: find the set of functions that reference a given string.

Useful reverse-engineering move — "where is this C2 hostname or error
message used?" — that mirrors IDA's "Jump to xref" for strings.
Implemented on top of :func:`glaurung.ir.decompile_all` rather than a
raw address-based scan because the ``strings_fold`` IR pass already
substitutes string constants into the pseudocode for us.
"""

from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class StringXrefsArgs(BaseModel):
    query: str = Field(..., description="Substring of a string literal to locate")
    case_sensitive: bool = Field(False, description="Case-sensitive match (default off)")
    regex: bool = Field(False, description="Treat query as a Python regex")
    max_functions: int = Field(
        64, description="Maximum functions to decompile while searching"
    )
    max_snippet_chars: int = Field(
        120,
        description="Length of the surrounding pseudocode snippet returned for "
                    "each hit (helps the agent see context without pulling the "
                    "full decompilation).",
    )
    timeout_ms: int = Field(400, description="Per-function decompile timeout")


class StringXrefHit(BaseModel):
    func_name: str
    entry_va: int
    line_no: int = Field(
        ..., description="1-based pseudocode line where the match occurred"
    )
    snippet: str


class StringXrefsResult(BaseModel):
    query: str
    hits: List[StringXrefHit]
    functions_scanned: int


class GetStringXrefsTool(MemoryTool[StringXrefsArgs, StringXrefsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="get_string_xrefs",
                description="Return every function whose decompilation contains "
                            "the given string substring. Case-insensitive by "
                            "default; set regex=True to match a pattern. "
                            "Capped at max_functions decompilations.",
                tags=("analysis", "strings", "xrefs"),
            ),
            StringXrefsArgs,
            StringXrefsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: StringXrefsArgs,
    ) -> StringXrefsResult:
        if args.regex:
            flags = 0 if args.case_sensitive else re.IGNORECASE
            try:
                pattern = re.compile(args.query, flags)
            except re.error:
                return StringXrefsResult(
                    query=args.query, hits=[], functions_scanned=0
                )
            matcher = pattern.search
        else:
            needle = args.query if args.case_sensitive else args.query.lower()

            def matcher(hay: str) -> bool:
                h = hay if args.case_sensitive else hay.lower()
                return needle in h

        try:
            triples = g.ir.decompile_all(
                str(ctx.file_path),
                limit=max(1, int(args.max_functions)),
                timeout_ms=max(200, int(args.timeout_ms)),
            )
        except Exception:
            triples = []

        hits: List[StringXrefHit] = []
        half = max(0, args.max_snippet_chars // 2)
        for name, entry_va, text in triples:
            for ln_idx, line in enumerate(text.splitlines(), start=1):
                if not matcher(line):
                    continue
                # Compact to a snippet centred on the first match.
                if args.regex:
                    m = re.search(
                        args.query,
                        line,
                        0 if args.case_sensitive else re.IGNORECASE,
                    )
                    pos = m.start() if m else 0
                else:
                    hay = line if args.case_sensitive else line.lower()
                    pos = hay.find(needle)
                    if pos < 0:
                        pos = 0
                lo = max(0, pos - half)
                hi = min(len(line), pos + half + len(args.query))
                snippet = line[lo:hi].strip()
                hits.append(
                    StringXrefHit(
                        func_name=name,
                        entry_va=int(entry_va),
                        line_no=ln_idx,
                        snippet=snippet,
                    )
                )
                # One hit per function is enough — matching lines within the
                # same function are noise for cross-reference purposes.
                break

        return StringXrefsResult(
            query=args.query,
            hits=hits,
            functions_scanned=len(triples),
        )


def build_tool() -> MemoryTool[StringXrefsArgs, StringXrefsResult]:
    return GetStringXrefsTool()
