from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from .windows_function_start_explain import (
    WindowsFunctionStartExplainArgs,
    WindowsFunctionStartExplainResult,
    WindowsFunctionStartExplainTool,
)


SimdStartClassification = Literal[
    "not_simd_start",
    "strict_function",
    "accept_pdata_or_provenance",
    "candidate_requires_boundary_review",
    "body_split_candidate",
    "likely_vector_block_label",
    "reject_false_start",
    "review_unknown",
]

SimdClassifierConfidence = Literal["high", "medium", "low"]


class WindowsSimdStartClassifierArgs(BaseModel):
    comparison_path: str | None = Field(
        None,
        description="Optional Glaurung/Ghidra comparison JSON path.",
    )
    diagnostics_path: str | None = Field(
        None,
        description="Optional per-address diagnostics JSON path.",
    )
    file: str = Field(
        ...,
        description="Binary filename or unique path substring from the comparison artifact.",
    )
    va: int | None = Field(None, description="Virtual address to classify.")
    address: str | None = Field(
        None,
        description="Hex virtual address to classify, such as 0x180033b20.",
    )
    max_refs: int = Field(
        8,
        ge=0,
        le=64,
        description="Maximum refs to request from windows_function_start_explain.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact SIMD classifier evidence node.",
    )


class WindowsSimdStartClassifierResult(BaseModel):
    file: str
    va: int
    address: str
    is_simd_head: bool
    simd_prefix: str | None = None
    classification: SimdStartClassification
    confidence: SimdClassifierConfidence
    final_state: str
    recommended_action: str
    reason_codes: list[str] = Field(default_factory=list)
    explanation: WindowsFunctionStartExplainResult
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSimdStartClassifierTool(
    MemoryTool[WindowsSimdStartClassifierArgs, WindowsSimdStartClassifierResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_simd_start_classifier",
                description=(
                    "Classify SIMD-headed Windows function-start candidates with "
                    "context from .pdata, Ghidra deltas, containing functions, "
                    "labels, code-pointer refs, and provenance. This prevents "
                    "blind promotion of vector-instruction interiors."
                ),
                tags=("windows", "pe", "ghidra", "function-start", "simd"),
            ),
            WindowsSimdStartClassifierArgs,
            WindowsSimdStartClassifierResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSimdStartClassifierArgs,
    ) -> WindowsSimdStartClassifierResult:
        explanation = WindowsFunctionStartExplainTool().run(
            ctx,
            kb,
            WindowsFunctionStartExplainArgs(
                comparison_path=args.comparison_path,
                diagnostics_path=args.diagnostics_path,
                file=args.file,
                va=args.va,
                address=args.address,
                max_refs=args.max_refs,
                add_to_kb=False,
            ),
        )
        simd_prefix = _simd_prefix(explanation)
        classification, confidence, reason_codes, action, notes = _classify(
            explanation,
            simd_prefix,
        )
        evidence_bundle = _evidence_bundle(
            explanation=explanation,
            classification=classification,
            confidence=confidence,
            reason_codes=reason_codes,
            notes=notes,
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_simd_start_classifier",
                    props={
                        "file": explanation.file,
                        "address": explanation.address,
                        "classification": classification,
                        "confidence": confidence,
                        "recommended_action": action,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSimdStartClassifierResult(
            file=explanation.file,
            va=explanation.va,
            address=explanation.address,
            is_simd_head=simd_prefix is not None,
            simd_prefix=simd_prefix,
            classification=classification,
            confidence=confidence,
            final_state=explanation.final_state,
            recommended_action=action,
            reason_codes=reason_codes,
            explanation=explanation,
            evidence_bundle=evidence_bundle,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _classify(
    explanation: WindowsFunctionStartExplainResult,
    simd_prefix: str | None,
) -> tuple[
    SimdStartClassification,
    SimdClassifierConfidence,
    list[str],
    str,
    list[str],
]:
    reason_codes = _dedupe([*explanation.reason_codes])
    notes = [
        "SIMD start classification is functionization evidence, not vulnerability evidence."
    ]
    if simd_prefix is None:
        return (
            "not_simd_start",
            "high",
            _dedupe([*reason_codes, "not_simd_head"]),
            explanation.recommended_action,
            notes,
        )

    reason_codes.append("simd_head")
    reason_codes.append(f"simd_prefix_{simd_prefix}")
    if explanation.pdata is None or not explanation.pdata.is_pdata_start:
        reason_codes.append("no_pdata_start")
    if explanation.in_ghidra:
        reason_codes.append("ghidra_has_start")
    if explanation.in_glaurung_function:
        reason_codes.append("inside_glaurung_function")
    if explanation.pdata is not None and explanation.pdata.pdata_body_overlap_starts:
        reason_codes.append("pdata_body_overlap")
    if not explanation.provenance and not explanation.code_pointer_refs:
        reason_codes.append("no_external_provenance")

    if explanation.final_state == "strict_function":
        return (
            "strict_function",
            "high",
            _dedupe(reason_codes),
            "keep_strict_function",
            notes,
        )
    if _has_strong_provenance(explanation):
        return (
            "accept_pdata_or_provenance",
            "high",
            _dedupe(reason_codes),
            "keep_or_promote_with_recorded_provenance",
            notes,
        )
    if explanation.containing_function is not None and explanation.in_ghidra:
        owner_size = explanation.containing_function.total_size or 0
        if owner_size >= 1024 or "pdata_body_overlap" in reason_codes:
            return (
                "body_split_candidate",
                "medium",
                _dedupe([*reason_codes, "owner_body_split_review"]),
                "review_as_body_split_candidate",
                notes,
            )
        return (
            "likely_vector_block_label",
            "medium",
            _dedupe([*reason_codes, "small_owner_vector_block"]),
            "keep_as_label_pending_xref_or_boundary_evidence",
            notes,
        )
    if explanation.in_ghidra:
        ghidra_body = explanation.ghidra.body_size if explanation.ghidra else 0
        confidence: SimdClassifierConfidence = "medium" if ghidra_body >= 24 else "low"
        return (
            "candidate_requires_boundary_review",
            confidence,
            _dedupe([*reason_codes, f"ghidra_body_size_{ghidra_body}"]),
            "keep_as_candidate_pending_boundary_evidence",
            notes,
        )
    if explanation.final_state == "glaurung_only" and not explanation.in_ghidra:
        return (
            "reject_false_start",
            "high",
            _dedupe([*reason_codes, "glaurung_only_no_ghidra"]),
            "demote_to_rejected_start",
            notes,
        )
    return (
        "review_unknown",
        "low",
        _dedupe(reason_codes),
        "review_with_windows_function_start_explain",
        notes,
    )


def _has_strong_provenance(explanation: WindowsFunctionStartExplainResult) -> bool:
    if explanation.pdata is not None and explanation.pdata.is_pdata_start:
        return True
    if explanation.code_pointer_refs:
        return True
    strong_seed_kinds = {"pdata", "export", "direct_call", "vtable", "data_ref"}
    return bool(strong_seed_kinds.intersection(explanation.seed_kinds))


def _simd_prefix(explanation: WindowsFunctionStartExplainResult) -> str | None:
    if explanation.bytes is None:
        return None
    hex_bytes = explanation.bytes.hex.lower()
    for prefix in ("660f", "f20f", "f30f", "0f10", "0f11", "0f28", "0f29", "c4", "c5"):
        if hex_bytes.startswith(prefix):
            return prefix
    return None


def _evidence_bundle(
    *,
    explanation: WindowsFunctionStartExplainResult,
    classification: SimdStartClassification,
    confidence: SimdClassifierConfidence,
    reason_codes: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    confidence_value = {"high": 0.9, "medium": 0.6, "low": 0.3}[confidence]
    return make_windows_evidence_bundle(
        claim_level="functionization_review_not_vulnerability",
        subject=WindowsEvidenceSubject(
            kind="functionization",
            file=explanation.file,
            va=explanation.va,
            attributes={
                "classification": classification,
                "final_state": explanation.final_state,
                "recommended_action": explanation.recommended_action,
            },
        ),
        source_tools=[
            "windows_simd_start_classifier",
            "windows_function_start_explain",
        ],
        evidence_refs=[
            evidence_ref(
                kind="address",
                source="windows_simd_start_classifier",
                summary=f"{explanation.address}: {classification}",
                address=explanation.va,
                confidence=confidence_value,
                reason_codes=reason_codes,
                provenance=[explanation.path],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            ghidra_missing_entries=1 if explanation.diagnostic_kind == "missing" else 0,
            ghidra_extra_entries=1 if explanation.diagnostic_kind == "extra" else 0,
        ),
        confidence=confidence_value,
        confidence_reason=f"{classification}:{confidence}",
        reason_codes=reason_codes,
        blockers=(
            ["address-level boundary evidence required"]
            if classification
            in {
                "candidate_requires_boundary_review",
                "body_split_candidate",
                "review_unknown",
            }
            else []
        ),
        next_actions=[_next_action_for_classification(classification)],
        notes=notes,
    )


def _next_action_for_classification(
    classification: SimdStartClassification,
) -> str:
    if classification == "body_split_candidate":
        return "windows_function_body_split_candidates"
    if classification == "candidate_requires_boundary_review":
        return "windows_function_start_explain"
    if classification == "reject_false_start":
        return "record demotion or suppression in windows_analyst_notebook"
    return "review functionization evidence"


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsSimdStartClassifierTool:
    return WindowsSimdStartClassifierTool()
