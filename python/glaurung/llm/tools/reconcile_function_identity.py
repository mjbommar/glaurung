"""Tool #19: reconcile multiple proposed names for the same function.

Layer 3 cross-function coherence. Across a pipeline run, the same
function may receive three different names: one from
``suggest_function_name`` on raw pseudocode, one from
``propose_function_name_post_rewrite``, and one the user entered in
their KB. Mechanical tie-breakers pick shortest or most-frequent; an
LLM picks the *most specific*.

Input: a list of candidate names plus brief justifications. Output:
the canonical name, the alternatives demoted to aliases, and the
one-line reason the winner was chosen. Feeds
``rename_in_kb`` with the final decision.
"""

from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


_SPECIFICITY_WORDS = {
    # low-specificity hedge stems that should lose ties
    "do", "handle", "process", "data", "work", "thing", "helper", "util",
    "func", "function", "impl", "internal",
}


class CandidateName(BaseModel):
    name: str
    justification: str = ""
    source_tool: str = Field(
        "", description="Which tool proposed this name (for provenance)"
    )
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class ReconcileFunctionIdentityArgs(BaseModel):
    entry_va: int
    candidates: List[CandidateName]
    use_llm: bool = True


class ReconciledIdentity(BaseModel):
    canonical_name: str
    aliases: List[str] = Field(default_factory=list)
    justification: str
    confidence: float = Field(ge=0.0, le=1.0)


class ReconcileFunctionIdentityResult(BaseModel):
    entry_va: int
    reconciled: ReconciledIdentity
    source: str = Field(..., description="'llm' | 'heuristic'")


def _specificity_score(name: str) -> int:
    """Higher = more specific. Rewards length and semantic verbs."""
    parts = [p for p in re.split(r"[_\W]+", name.lower()) if p]
    if not parts:
        return 0
    penalty = sum(1 for p in parts if p in _SPECIFICITY_WORDS)
    return len(parts) - penalty


def _heuristic(args: ReconcileFunctionIdentityArgs) -> ReconciledIdentity:
    if not args.candidates:
        return ReconciledIdentity(
            canonical_name=f"sub_{args.entry_va:x}",
            aliases=[],
            justification="no candidates",
            confidence=0.1,
        )
    # Rank candidates by specificity score, then by confidence.
    ranked = sorted(
        args.candidates,
        key=lambda c: (
            _specificity_score(c.name),
            c.confidence,
            -len(c.name),  # shorter wins when tied
        ),
        reverse=True,
    )
    winner = ranked[0]
    aliases = [c.name for c in ranked[1:] if c.name != winner.name]
    return ReconciledIdentity(
        canonical_name=winner.name,
        aliases=aliases,
        justification=(
            f"highest specificity score + confidence "
            f"(from {winner.source_tool or 'unknown'})"
        ),
        confidence=min(0.7, 0.4 + 0.1 * _specificity_score(winner.name)),
    )


_SYSTEM_PROMPT = (
    "You are reconciling multiple candidate names for a single "
    "function. Pick the single *most specific* name — the one that "
    "describes what the function does in terms of the project's "
    "domain. Reject vague names ('do_work', 'process_data', "
    "'handle_request'). If two names are equally specific, prefer "
    "the one with the higher source confidence. List the other "
    "proposals as aliases so other tools can find the function by "
    "either name. Give a one-line justification citing the specific "
    "word that makes the winner better."
)


def _build_prompt(args: ReconcileFunctionIdentityArgs) -> str:
    parts = [f"Entry VA: {args.entry_va:#x}", "Candidate names:"]
    for c in args.candidates:
        parts.append(
            f"  - {c.name}  (from {c.source_tool or 'unknown'}, "
            f"conf={c.confidence:.2f}): {c.justification}"
        )
    parts.append(
        "Return canonical_name, aliases (all losers), justification, "
        "confidence."
    )
    return "\n\n".join(parts)


class ReconcileFunctionIdentityTool(
    MemoryTool[
        ReconcileFunctionIdentityArgs, ReconcileFunctionIdentityResult
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="reconcile_function_identity",
                description="Choose a canonical name for a function given "
                            "multiple candidates proposed by different "
                            "pipeline stages. LLM favours specificity.",
                tags=("llm", "naming", "layer3"),
            ),
            ReconcileFunctionIdentityArgs,
            ReconcileFunctionIdentityResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ReconcileFunctionIdentityArgs,
    ) -> ReconcileFunctionIdentityResult:
        heur = _heuristic(args)
        if not args.use_llm or len(args.candidates) <= 1:
            return ReconcileFunctionIdentityResult(
                entry_va=int(args.entry_va), reconciled=heur, source="heuristic"
            )

        prompt = _build_prompt(args)
        reconciled = run_structured_llm(
            prompt=prompt,
            output_type=ReconciledIdentity,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if reconciled is heur else "llm"
        return ReconcileFunctionIdentityResult(
            entry_va=int(args.entry_va), reconciled=reconciled, source=source
        )


def build_tool() -> MemoryTool[
    ReconcileFunctionIdentityArgs, ReconcileFunctionIdentityResult
]:
    return ReconcileFunctionIdentityTool()
