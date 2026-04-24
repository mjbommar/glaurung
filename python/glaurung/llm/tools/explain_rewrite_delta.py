"""Tool #25: human-facing explanation of per-function rewrite delta.

Layer 4 user-facing transparency. Without this nobody can responsibly
ship recovered source — reviewers cannot tell where hallucination
might hide. This tool writes a short markdown note for each
non-trivial function explaining:

- What the LLM did (renamed variables, replaced a loop with memcpy,
  consolidated error returns into an enum, …)
- What it assumed that isn't mechanically provable
- What a human reviewer should double-check before merging

The output is markdown — the orchestrator writes one ``.rewrite.md``
file per function next to the ``.c``/``.rs``/``.go``/``.py`` file so
reviewers see the diff notes right next to the code they describe.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


class ExplainRewriteDeltaArgs(BaseModel):
    function_name: str
    entry_va: int
    original_pseudocode: str
    final_source: str
    target_language: str = "c"
    assumptions: List[str] = Field(
        default_factory=list,
        description="The 'assumptions' list produced by #14 (and carried "
                    "through #17/#24 as appropriate).",
    )
    divergences: List[str] = Field(
        default_factory=list,
        description="Short description of any divergences #17 flagged — "
                    "included in the delta note so reviewers see the "
                    "verification history alongside the rewrite.",
    )
    use_llm: bool = True


class RewriteDeltaNote(BaseModel):
    markdown: str = Field(
        ...,
        description="Full markdown body — goes into `<function>.rewrite.md`.",
    )
    review_checklist: List[str] = Field(
        default_factory=list,
        description="Short bullet list of specific things a reviewer should "
                    "verify before merging. Extracted so orchestrators can "
                    "aggregate all checklists into a top-level review TODO.",
    )
    confidence: float = Field(ge=0.0, le=1.0)


class ExplainRewriteDeltaResult(BaseModel):
    function_name: str
    note: RewriteDeltaNote
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(args: ExplainRewriteDeltaArgs) -> RewriteDeltaNote:
    """Offline delta note — structured but shallow."""
    checklist: List[str] = []
    lines = [
        f"# Rewrite notes — `{args.function_name}` @ {args.entry_va:#x}",
        "",
        f"*Target language: {args.target_language}*",
        "",
        "## Assumptions",
        "",
    ]
    if args.assumptions:
        for a in args.assumptions:
            lines.append(f"- {a}")
            checklist.append(f"verify: {a[:80]}")
    else:
        lines.append("_No assumptions declared by the rewriter._")
    lines.append("")
    if args.divergences:
        lines.append("## Divergences flagged")
        lines.append("")
        for d in args.divergences:
            lines.append(f"- {d}")
            checklist.append(f"resolve divergence: {d[:80]}")
    lines.append("")
    lines.append("## Reviewer TODO")
    lines.append("")
    if checklist:
        for c in checklist:
            lines.append(f"- [ ] {c}")
    else:
        lines.append("_No outstanding items._")
    return RewriteDeltaNote(
        markdown="\n".join(lines),
        review_checklist=checklist,
        confidence=0.4 if args.assumptions or args.divergences else 0.3,
    )


_SYSTEM_PROMPT = (
    "You are writing a short markdown note for a reviewer auditing "
    "one recovered function. You will be shown the original "
    "pseudocode, the final rewritten source, the rewriter's declared "
    "assumptions, and any divergences a verification step flagged. "
    "Produce a concise note (< 40 lines) describing: what the LLM "
    "pipeline did to this function (renamed locals, replaced loops, "
    "consolidated error paths, …), what it assumed that is not "
    "mechanically provable, and a short reviewer checklist of "
    "specific items to verify before merging. Be honest and "
    "specific — this note is the user's audit trail."
)


def _build_prompt(args: ExplainRewriteDeltaArgs) -> str:
    parts = [
        f"Function: {args.function_name} @ {args.entry_va:#x}",
        f"Target language: {args.target_language}",
        f"Original pseudocode:\n```\n{args.original_pseudocode}\n```",
        f"Final source:\n```\n{args.final_source}\n```",
    ]
    if args.assumptions:
        parts.append(
            "Rewriter declared assumptions:\n"
            + "\n".join(f"  - {a}" for a in args.assumptions)
        )
    if args.divergences:
        parts.append(
            "Divergences flagged:\n"
            + "\n".join(f"  - {d}" for d in args.divergences)
        )
    parts.append(
        "Return a RewriteDeltaNote with a markdown body and a flat "
        "review_checklist of actionable items."
    )
    return "\n\n".join(parts)


class ExplainRewriteDeltaTool(
    MemoryTool[ExplainRewriteDeltaArgs, ExplainRewriteDeltaResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="explain_rewrite_delta",
                description="Write a per-function markdown note explaining "
                            "what the pipeline did, what it assumed, and "
                            "what a reviewer should verify.",
                tags=("llm", "docs", "audit", "layer4"),
            ),
            ExplainRewriteDeltaArgs,
            ExplainRewriteDeltaResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ExplainRewriteDeltaArgs,
    ) -> ExplainRewriteDeltaResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return ExplainRewriteDeltaResult(
                function_name=args.function_name, note=heur, source="heuristic"
            )

        prompt = _build_prompt(args)
        note = run_structured_llm(
            prompt=prompt,
            output_type=RewriteDeltaNote,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if note is heur else "llm"
        return ExplainRewriteDeltaResult(
            function_name=args.function_name, note=note, source=source
        )


def build_tool() -> MemoryTool[
    ExplainRewriteDeltaArgs, ExplainRewriteDeltaResult
]:
    return ExplainRewriteDeltaTool()
