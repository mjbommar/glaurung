"""Tool #16: propose a function name after the rewrite pass.

Layer 2 function-level. Runs *after* #14 rewrites the function, not
before. The distinction matters: clean source with named locals and
symbolic constants is radically more nameable than raw pseudocode.
The existing :mod:`glaurung.llm.tools.suggest_function_name` operates
on pseudocode and is the bootstrap pass; this tool operates on the
*output* of the rewrite and produces the final name the tree will
ship with.

The output carries the canonical name *and* a list of rejected
candidates so #19 ``reconcile_function_identity`` has the full slate
of names proposed across the project to arbitrate.
"""

from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


_SLUG_RE = re.compile(r"[^A-Za-z0-9_]+")


def _slugify(text: str) -> str:
    n = _SLUG_RE.sub("_", text).strip("_").lower()
    return n or "func"


class ProposeFunctionNamePostRewriteArgs(BaseModel):
    entry_va: int
    rewritten_source: str = Field(..., description="Output of #14")
    role: Optional[str] = Field(None, description="Role label from #13")
    printed_strings: List[str] = Field(
        default_factory=list,
        description="String literals the function uses. Strong naming signal.",
    )
    current_name: Optional[str] = Field(
        None,
        description="Name this function was known by before the rewrite "
                    "(from suggest_function_name or the symbol table).",
    )
    use_llm: bool = True


class RejectedCandidate(BaseModel):
    name: str
    reason: str = Field(..., description="Why this name lost to the canonical one")


class PostRewriteName(BaseModel):
    canonical_name: str = Field(..., description="Final snake_case name")
    justification: str = Field(
        ..., description="One-line reason the chosen name fits the evidence"
    )
    rejected_candidates: List[RejectedCandidate] = Field(
        default_factory=list,
        description="Alternatives considered and why they were rejected — "
                    "fed into #19 for cross-function reconciliation.",
    )
    confidence: float = Field(ge=0.0, le=1.0)


class ProposeFunctionNamePostRewriteResult(BaseModel):
    entry_va: int
    name: PostRewriteName
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(args: ProposeFunctionNamePostRewriteArgs) -> PostRewriteName:
    # Respect the existing name when we have one and it looks good.
    if args.current_name and not re.fullmatch(
        r"(sub_.*|func_.*|unknown.*)", args.current_name, re.IGNORECASE
    ):
        return PostRewriteName(
            canonical_name=_slugify(args.current_name),
            justification="retained pre-rewrite name",
            rejected_candidates=[],
            confidence=0.55,
        )
    # Try to harvest a name from the first printed string.
    if args.printed_strings:
        stem = _slugify(args.printed_strings[0])[:24]
        if stem:
            return PostRewriteName(
                canonical_name=stem,
                justification=f"derived from first printed string {args.printed_strings[0]!r}",
                rejected_candidates=[],
                confidence=0.35,
            )
    return PostRewriteName(
        canonical_name=f"sub_{args.entry_va:x}",
        justification="no distinguishing evidence — kept VA-based stub",
        rejected_candidates=[],
        confidence=0.15,
    )


_SYSTEM_PROMPT = (
    "You are naming a reverse-engineered function that has *already* "
    "been rewritten into idiomatic source. The clean source, the role "
    "label, and the strings it prints together form strong evidence. "
    "Pick the single best snake_case name — descriptive of purpose, "
    "2–4 words, verb + object when the function is an action. Record "
    "at least two plausible alternatives as rejected_candidates, each "
    "with a one-line reason they are slightly weaker. Be honest about "
    "confidence — a wrapper is hard to name precisely."
)


def _build_prompt(args: ProposeFunctionNamePostRewriteArgs) -> str:
    parts = []
    if args.current_name:
        parts.append(f"Current name: {args.current_name}")
    if args.role:
        parts.append(f"Role: {args.role}")
    parts.append(f"Rewritten source:\n```\n{args.rewritten_source}\n```")
    if args.printed_strings:
        parts.append(
            "Strings printed:\n"
            + "\n".join(f"  - {s!r}" for s in args.printed_strings[:8])
        )
    parts.append(
        "Return canonical_name, justification, rejected_candidates "
        "(at least two), confidence."
    )
    return "\n\n".join(parts)


class ProposeFunctionNamePostRewriteTool(
    MemoryTool[
        ProposeFunctionNamePostRewriteArgs,
        ProposeFunctionNamePostRewriteResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="propose_function_name_post_rewrite",
                description="Pick the final function name from the rewritten "
                            "source, role label, and printed strings. Runs "
                            "after #14; outputs are fed into #19.",
                tags=("llm", "naming", "layer2"),
            ),
            ProposeFunctionNamePostRewriteArgs,
            ProposeFunctionNamePostRewriteResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ProposeFunctionNamePostRewriteArgs,
    ) -> ProposeFunctionNamePostRewriteResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return ProposeFunctionNamePostRewriteResult(
                entry_va=int(args.entry_va), name=heur, source="heuristic"
            )

        prompt = _build_prompt(args)
        name = run_structured_llm(
            prompt=prompt,
            output_type=PostRewriteName,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        # Sanitise so downstream code can trust the identifier.
        name = PostRewriteName(
            canonical_name=_slugify(name.canonical_name),
            justification=name.justification,
            rejected_candidates=name.rejected_candidates,
            confidence=name.confidence,
        )
        source = "heuristic" if name.canonical_name == heur.canonical_name else "llm"
        return ProposeFunctionNamePostRewriteResult(
            entry_va=int(args.entry_va), name=name, source=source
        )


def build_tool() -> MemoryTool[
    ProposeFunctionNamePostRewriteArgs,
    ProposeFunctionNamePostRewriteResult,
]:
    return ProposeFunctionNamePostRewriteTool()
