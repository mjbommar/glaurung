"""Tool #17: adversarially verify a function rewrite matches the binary.

Layer 2 gate. The rewriter (#14) is the single most creative step in
the pipeline — which makes it the single most likely to hallucinate.
This tool runs an LLM-as-skeptic: given the original pseudocode and
the rewritten source, list every observable behaviour that might
differ. Not a proof — a pragmatic catch for the ~80 % of rewrite
mistakes where an error check was silently dropped, a ``malloc``
size changed, or sign-extension differed.

The output is consumed by the orchestrator as a *publish gate*: if
any `high`-severity divergence is reported, the rewrite for that
function stays marked provisional until a human (or a second rewrite
pass) resolves it.
"""

from __future__ import annotations

from typing import List, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


DivergenceKind = Literal[
    "missing_error_check",
    "changed_constant",
    "changed_width",
    "sign_extension",
    "dropped_side_effect",
    "dropped_call",
    "added_call",
    "control_flow",
    "memory_safety",
    "other",
]
Severity = Literal["low", "medium", "high"]


class VerifySemanticEquivalenceArgs(BaseModel):
    original_pseudocode: str = Field(
        ..., description="Raw decompiler output for the function"
    )
    rewritten_source: str = Field(
        ..., description="Layer-2 rewrite from #14"
    )
    rewrite_assumptions: List[str] = Field(
        default_factory=list,
        description="The `assumptions` list returned by #14 — the LLM sees "
                    "what the rewriter flagged as non-mechanical and can "
                    "challenge those directly.",
    )
    use_llm: bool = True


class Divergence(BaseModel):
    kind: DivergenceKind
    location: str = Field(
        ...,
        description="Line number or short quote pinpointing where the "
                    "divergence appears in the rewrite",
    )
    severity: Severity
    description: str
    recommended_action: str = Field(
        "", description="Short suggestion — 'add missing errno check', …"
    )


class EquivalenceVerdict(BaseModel):
    equivalent: bool = Field(
        ...,
        description="True only when no divergences of severity >= medium "
                    "were found.",
    )
    divergences: List[Divergence] = Field(default_factory=list)
    summary: str = Field(
        "", description="One-paragraph summary of findings"
    )
    confidence: float = Field(ge=0.0, le=1.0)


class VerifySemanticEquivalenceResult(BaseModel):
    verdict: EquivalenceVerdict
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic() -> EquivalenceVerdict:
    """Offline mode cannot verify — report UNKNOWN with zero confidence
    and a single informative divergence so reviewers see the gap."""
    return EquivalenceVerdict(
        equivalent=False,
        divergences=[
            Divergence(
                kind="other",
                location="(n/a)",
                severity="low",
                description="LLM unavailable; equivalence could not be checked",
                recommended_action="run with LLM credentials or review by hand",
            )
        ],
        summary="offline — no verification performed",
        confidence=0.0,
    )


_SYSTEM_PROMPT = (
    "You are an adversarial reviewer auditing a decompiler-to-source "
    "rewrite. You will be shown the original pseudocode and the "
    "rewriter's output, plus the rewriter's own declared assumptions. "
    "List every observable behaviour that might differ between the "
    "two — focus on error checks that were dropped, numeric constants "
    "that changed, integer widths or signedness that changed, calls "
    "that were added or removed, side effects (global writes, errno, "
    "file descriptors) that are no longer visible, and control-flow "
    "differences. Cite the exact line or short quote for each "
    "divergence. Rate severity conservatively: `high` for anything "
    "that could change correctness (dropped NULL check, wrong size to "
    "memcpy), `medium` for likely-correctness-affecting ambiguity, "
    "`low` for stylistic or obvious equivalents. Set `equivalent` to "
    "False if *any* divergence is medium or high."
)


def _build_prompt(args: VerifySemanticEquivalenceArgs) -> str:
    parts = [
        f"Original pseudocode:\n```\n{args.original_pseudocode}\n```",
        f"Rewritten source:\n```\n{args.rewritten_source}\n```",
    ]
    if args.rewrite_assumptions:
        parts.append(
            "Rewriter declared assumptions:\n"
            + "\n".join(f"  - {a}" for a in args.rewrite_assumptions)
        )
    parts.append(
        "List every divergence with location, severity (low/medium/high), "
        "description, recommended_action. Then set equivalent = True only "
        "if nothing is medium or high."
    )
    return "\n\n".join(parts)


class VerifySemanticEquivalenceTool(
    MemoryTool[
        VerifySemanticEquivalenceArgs, VerifySemanticEquivalenceResult
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="verify_semantic_equivalence",
                description="Adversarial LLM check that a Layer-2 rewrite "
                            "matches the original pseudocode — flags dropped "
                            "error checks, changed widths, missing side "
                            "effects. Blocks publishing when divergent.",
                tags=("llm", "audit", "layer2"),
            ),
            VerifySemanticEquivalenceArgs,
            VerifySemanticEquivalenceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: VerifySemanticEquivalenceArgs,
    ) -> VerifySemanticEquivalenceResult:
        if not args.use_llm:
            return VerifySemanticEquivalenceResult(
                verdict=_heuristic(), source="heuristic"
            )

        prompt = _build_prompt(args)
        verdict = run_structured_llm(
            prompt=prompt,
            output_type=EquivalenceVerdict,
            system_prompt=_SYSTEM_PROMPT,
            fallback=_heuristic,
        )
        # Recompute equivalent in case the LLM returned inconsistent fields.
        has_serious = any(d.severity in ("medium", "high") for d in verdict.divergences)
        if has_serious and verdict.equivalent:
            verdict = EquivalenceVerdict(
                equivalent=False,
                divergences=verdict.divergences,
                summary=verdict.summary,
                confidence=verdict.confidence,
            )
        source = "llm" if verdict.confidence > 0 else "heuristic"
        return VerifySemanticEquivalenceResult(verdict=verdict, source=source)


def build_tool() -> MemoryTool[
    VerifySemanticEquivalenceArgs, VerifySemanticEquivalenceResult
]:
    return VerifySemanticEquivalenceTool()
