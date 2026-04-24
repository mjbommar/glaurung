"""Tool #23: adversarial audit of a full recovered tree.

Layer 4 gate. A single expensive LLM call that sees the project at
*tree scale* and looks for failures only visible holistically:

- Dead code retained in the rewrite (functions nobody calls).
- Error paths missing or silenced during rewrite.
- Functions the rewriter "made up" without binary backing.
- Signature mismatches between a function and its callers.
- Overall consistency — does the module decomposition actually
  reflect the callgraph, or does everything call `util`?

Output is a prioritised punch list the user must work through before
publishing. The audit is deliberately the final gate: every earlier
tool has already signed off on its own piece, but only this one can
see the full picture.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


Severity = Literal["low", "medium", "high", "blocker"]


class FunctionSummaryEntry(BaseModel):
    name: str
    entry_va: int
    module: str = ""
    summary: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    assumptions: List[str] = Field(default_factory=list)


class BinaryMetadata(BaseModel):
    imports_count: int = 0
    exports_count: int = 0
    functions_count: int = 0
    strings_count: int = 0
    size_bytes: int = 0
    format: Optional[str] = None


class AuditRecoveredSourceArgs(BaseModel):
    project_name: str
    functions: List[FunctionSummaryEntry]
    modules: List[str] = Field(default_factory=list)
    binary_metadata: BinaryMetadata
    use_llm: bool = True


class AuditFinding(BaseModel):
    kind: Literal[
        "dead_code",
        "missing_error_path",
        "invented_function",
        "signature_mismatch",
        "module_coherence",
        "confidence_gap",
        "assumption_risk",
        "other",
    ]
    severity: Severity
    location: str = Field(
        ..., description="Function name, module, or project-level descriptor"
    )
    description: str
    recommended_action: str = ""


class AuditReport(BaseModel):
    findings: List[AuditFinding] = Field(default_factory=list)
    summary: str = Field(
        "", description="One-paragraph headline summary of audit"
    )
    blocker_count: int = 0
    passed: bool = Field(
        False,
        description="True when there are zero blockers and zero highs.",
    )
    confidence: float = Field(ge=0.0, le=1.0)


class AuditRecoveredSourceResult(BaseModel):
    report: AuditReport
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(args: AuditRecoveredSourceArgs) -> AuditReport:
    findings: List[AuditFinding] = []
    # Low-confidence functions are a blanket risk.
    low_conf = [f for f in args.functions if f.confidence < 0.4]
    if low_conf:
        findings.append(
            AuditFinding(
                kind="confidence_gap",
                severity="medium" if len(low_conf) < 10 else "high",
                location=f"{len(low_conf)} function(s)",
                description=(
                    f"{len(low_conf)} functions were rewritten with <0.4 "
                    "confidence — manual review recommended."
                ),
                recommended_action="re-run rewrite with richer caller context "
                                   "or review by hand",
            )
        )
    # Functions with many assumptions — inherent risk.
    noisy = [f for f in args.functions if len(f.assumptions) >= 5]
    if noisy:
        findings.append(
            AuditFinding(
                kind="assumption_risk",
                severity="medium",
                location=f"{len(noisy)} function(s)",
                description=f"{len(noisy)} functions carry ≥5 rewrite "
                            "assumptions; each is a potential divergence.",
                recommended_action="audit assumption lists; run #17 on each",
            )
        )
    # Coverage: did we recover remotely enough functions from the binary?
    if args.binary_metadata.functions_count:
        coverage = len(args.functions) / args.binary_metadata.functions_count
        if coverage < 0.5:
            findings.append(
                AuditFinding(
                    kind="module_coherence",
                    severity="high",
                    location=args.project_name,
                    description=(
                        f"Only {len(args.functions)} of "
                        f"{args.binary_metadata.functions_count} binary "
                        "functions were recovered."
                    ),
                    recommended_action="rewrite more functions before publish",
                )
            )
    blocker_count = sum(1 for f in findings if f.severity == "blocker")
    high_count = sum(1 for f in findings if f.severity == "high")
    passed = blocker_count == 0 and high_count == 0
    return AuditReport(
        findings=findings,
        summary=(
            f"{len(findings)} finding(s); "
            f"{blocker_count} blocker(s), {high_count} high severity."
        ),
        blocker_count=blocker_count,
        passed=passed,
        confidence=0.35,
    )


_SYSTEM_PROMPT = (
    "You are auditing a reverse-engineered source tree at project "
    "scale. You will receive a summary of every recovered function "
    "(name, module, one-line summary, confidence, declared "
    "rewriter-assumptions) plus the original binary's metadata. "
    "Look for tree-scale failures: dead code that no caller reaches, "
    "error paths that were silenced during rewrite, functions the "
    "pipeline invented without binary backing, signature mismatches "
    "between a function and how its callers use it, and module "
    "decompositions that ignore the actual callgraph. Report each "
    "finding with location, severity (low, medium, high, blocker), "
    "description, and recommended action. Set passed=True only when "
    "there are zero high and zero blocker findings."
)


def _build_prompt(args: AuditRecoveredSourceArgs) -> str:
    parts = [f"Project: {args.project_name}"]
    parts.append(f"Binary metadata: {args.binary_metadata.model_dump_json()}")
    parts.append(f"Modules ({len(args.modules)}):")
    for m in args.modules:
        parts.append(f"  - {m}")
    parts.append(f"Functions ({len(args.functions)}):")
    for f in args.functions[:200]:  # cap to keep prompt bounded
        parts.append(
            f"  {f.name}  module={f.module}  conf={f.confidence:.2f}  "
            f"assumptions={len(f.assumptions)}  -- {f.summary[:60]}"
        )
    parts.append(
        "Produce an AuditReport with findings, summary, blocker_count, "
        "passed, confidence. Be thorough."
    )
    return "\n\n".join(parts)


class AuditRecoveredSourceTool(
    MemoryTool[AuditRecoveredSourceArgs, AuditRecoveredSourceResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="audit_recovered_source",
                description="Tree-scale adversarial audit of a recovered "
                            "source project — flags dead code, missing "
                            "error paths, invented functions, coherence gaps.",
                tags=("llm", "audit", "layer4"),
            ),
            AuditRecoveredSourceArgs,
            AuditRecoveredSourceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: AuditRecoveredSourceArgs,
    ) -> AuditRecoveredSourceResult:
        heur = _heuristic(args)
        if not args.use_llm:
            return AuditRecoveredSourceResult(report=heur, source="heuristic")

        prompt = _build_prompt(args)
        report = run_structured_llm(
            prompt=prompt,
            output_type=AuditReport,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        # Recompute pass/blocker from the LLM's own findings to avoid
        # lying to the user if the model marked passed=True while
        # citing high-severity issues.
        blocker_count = sum(1 for f in report.findings if f.severity == "blocker")
        high_count = sum(1 for f in report.findings if f.severity == "high")
        passed = blocker_count == 0 and high_count == 0
        report = AuditReport(
            findings=report.findings,
            summary=report.summary,
            blocker_count=blocker_count,
            passed=passed,
            confidence=report.confidence,
        )
        source = "llm" if report.confidence > 0 else "heuristic"
        return AuditRecoveredSourceResult(report=report, source=source)


def build_tool() -> MemoryTool[
    AuditRecoveredSourceArgs, AuditRecoveredSourceResult
]:
    return AuditRecoveredSourceTool()
