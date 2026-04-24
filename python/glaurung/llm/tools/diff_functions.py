"""Tool: diff two functions' decompilations (bindiff-lite).

Useful for "is this function basically the same as the one from the
previous build?" questions — one of the oldest workflows in RE. We
diff at the pseudocode level (post-``strings_fold`` / naming) rather
than raw instructions because the decompiler already normalises out
the noise (register allocator churn, stack offsets, function names)
that makes raw-bytes diffs hopelessly noisy.

Caller specifies two ``(path, va)`` pairs. The second path defaults to
``ctx.file_path`` so the common "diff two funcs in this binary" case
stays concise.
"""

from __future__ import annotations

import difflib
from typing import List, Optional

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class DiffFunctionsArgs(BaseModel):
    va_a: int = Field(..., description="Entry VA of the first function")
    va_b: int = Field(..., description="Entry VA of the second function")
    path_a: Optional[str] = Field(
        None, description="Path to binary A — defaults to ctx.file_path"
    )
    path_b: Optional[str] = Field(
        None, description="Path to binary B — defaults to ctx.file_path"
    )
    style: str = Field("c", description="Decompile style: 'c' (default) or 'plain'")
    timeout_ms: int = Field(500, description="Per-function decompile timeout")
    max_diff_lines: int = Field(
        200, description="Cap on unified-diff lines returned"
    )


class DiffFunctionsResult(BaseModel):
    path_a: str
    va_a: int
    path_b: str
    va_b: int
    similarity: float = Field(
        ..., description="0.0–1.0 line-level similarity (difflib.SequenceMatcher ratio)"
    )
    unified_diff: List[str] = Field(
        ..., description="Unified diff of the two decompilations"
    )
    truncated: bool = False
    lines_a: int
    lines_b: int


class DiffFunctionsTool(MemoryTool[DiffFunctionsArgs, DiffFunctionsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="diff_functions",
                description="Diff the decompilations of two functions (same or "
                            "different binary). Returns unified diff plus a "
                            "line-level similarity ratio.",
                tags=("analysis", "diff"),
            ),
            DiffFunctionsArgs,
            DiffFunctionsResult,
        )

    def _decompile(self, path: str, va: int, style: str, timeout_ms: int) -> str:
        style_arg = "c" if style.lower() in ("c", "c-like", "clike") else ""
        try:
            return g.ir.decompile_at(
                path, int(va), timeout_ms=max(200, int(timeout_ms)), style=style_arg
            )
        except Exception as e:
            return f"// decompile failed: {e}"

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: DiffFunctionsArgs,
    ) -> DiffFunctionsResult:
        path_a = args.path_a or str(ctx.file_path)
        path_b = args.path_b or str(ctx.file_path)

        code_a = self._decompile(path_a, args.va_a, args.style, args.timeout_ms)
        code_b = self._decompile(path_b, args.va_b, args.style, args.timeout_ms)

        lines_a = code_a.splitlines()
        lines_b = code_b.splitlines()

        ratio = difflib.SequenceMatcher(None, lines_a, lines_b).ratio()

        diff = list(
            difflib.unified_diff(
                lines_a,
                lines_b,
                fromfile=f"{path_a}:{args.va_a:#x}",
                tofile=f"{path_b}:{args.va_b:#x}",
                lineterm="",
            )
        )
        truncated = False
        if len(diff) > args.max_diff_lines:
            truncated = True
            diff = diff[: args.max_diff_lines] + [
                f"... (diff truncated at {args.max_diff_lines} lines, "
                f"{len(diff) - args.max_diff_lines} more)"
            ]

        return DiffFunctionsResult(
            path_a=path_a,
            va_a=int(args.va_a),
            path_b=path_b,
            va_b=int(args.va_b),
            similarity=ratio,
            unified_diff=diff,
            truncated=truncated,
            lines_a=len(lines_a),
            lines_b=len(lines_b),
        )


def build_tool() -> MemoryTool[DiffFunctionsArgs, DiffFunctionsResult]:
    return DiffFunctionsTool()
