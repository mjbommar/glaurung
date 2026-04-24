"""Tool: return decompiled pseudocode for a single function.

Thin wrapper around :func:`glaurung.ir.decompile_at` that exposes it as
an agent-callable tool. Agents can request either the default (typed,
register-level) or C-like (stripped) rendering.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class DecompileFunctionArgs(BaseModel):
    va: int = Field(..., description="Entry VA of the function to decompile")
    style: str = Field(
        "c",
        description="Rendering style: 'c' for C-like (default) or 'plain' for "
                    "the register-level form with type annotations.",
    )
    timeout_ms: int = Field(500, description="Per-function analysis timeout in ms")


class DecompileFunctionResult(BaseModel):
    entry_va: int
    pseudocode: str
    style: str
    truncated: bool = Field(
        False,
        description="True when the pseudocode was truncated for length in the prompt.",
    )


class DecompileFunctionTool(
    MemoryTool[DecompileFunctionArgs, DecompileFunctionResult]
):
    """Decompile one function and return its pseudocode string."""

    MAX_LINES = 400

    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="decompile_function",
                description="Decompile the function at the given entry VA and "
                            "return C-like pseudocode. Use style='c' for "
                            "compact output or 'plain' for register-level "
                            "detail.",
                tags=("analysis", "decompiler"),
            ),
            DecompileFunctionArgs,
            DecompileFunctionResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: DecompileFunctionArgs,
    ) -> DecompileFunctionResult:
        style = "c" if str(args.style).lower() in ("c", "c-like", "clike") else ""
        try:
            text = g.ir.decompile_at(
                str(ctx.file_path),
                int(args.va),
                timeout_ms=max(200, int(args.timeout_ms)),
                style=style,
            )
        except Exception as e:
            # Surface the failure in-band so the agent can continue; the
            # pseudocode body itself carries the explanation.
            return DecompileFunctionResult(
                entry_va=int(args.va),
                pseudocode=f"// decompile failed: {e}",
                style="c" if style == "c" else "plain",
                truncated=False,
            )
        lines = text.splitlines()
        truncated = False
        if len(lines) > self.MAX_LINES:
            truncated = True
            lines = lines[: self.MAX_LINES] + [
                f"... ({len(text.splitlines()) - self.MAX_LINES} more lines truncated)"
            ]
        return DecompileFunctionResult(
            entry_va=int(args.va),
            pseudocode="\n".join(lines),
            style="c" if style == "c" else "plain",
            truncated=truncated,
        )


def build_tool() -> MemoryTool[DecompileFunctionArgs, DecompileFunctionResult]:
    return DecompileFunctionTool()
