from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


WindowsEvidenceClaimLevel = Literal[
    "triage_evidence_bundle_not_finding",
    "functionization_review_not_vulnerability",
    "candidate_not_finding",
    "validation_plan_not_reproduction",
    "runtime_artifact_bundle_not_finding",
]

WindowsEvidenceSubjectKind = Literal[
    "generic",
    "functionization",
    "boundary_diff",
    "candidate",
    "validation_plan",
    "runtime_artifacts",
]

WindowsEvidenceRefKind = Literal[
    "address",
    "artifact",
    "candidate",
    "diagnostic",
    "functionization",
    "ghidra_delta",
    "project_fact",
    "tool_result",
    "validation",
]


class WindowsEvidenceSubject(BaseModel):
    kind: WindowsEvidenceSubjectKind = "generic"
    file: str | None = None
    binary: str | None = None
    build: str | None = None
    component: str | None = None
    target_id: str | None = None
    entrypoint: str | None = None
    candidate_id: str | None = None
    validation_id: str | None = None
    va: int | None = None
    va_hex: str | None = None
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class WindowsEvidenceReference(BaseModel):
    kind: WindowsEvidenceRefKind
    source: str
    summary: str
    address: int | None = None
    address_hex: str | None = None
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)


class WindowsEvidenceCoverage(BaseModel):
    fact_coverage: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    current_capabilities: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    ghidra_missing_entries: int | None = None
    ghidra_extra_entries: int | None = None
    validation_status: str | None = None
    validation_ready: bool | None = None
    runtime_artifact_count: int | None = None
    stale_or_blocking_facts: list[str] = Field(default_factory=list)


class WindowsEvidenceBundle(BaseModel):
    bundle_id: str
    claim_level: WindowsEvidenceClaimLevel
    subject: WindowsEvidenceSubject
    source_tools: list[str] = Field(default_factory=list)
    tool_sequence: list[str] = Field(default_factory=list)
    evidence_refs: list[WindowsEvidenceReference] = Field(default_factory=list)
    coverage: WindowsEvidenceCoverage = Field(default_factory=WindowsEvidenceCoverage)
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    confidence_reason: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WindowsAgentEvidenceBundleArgs(BaseModel):
    bundle_id: str | None = Field(
        None,
        description="Optional stable id. If absent, one is derived from the bundle body.",
    )
    claim_level: WindowsEvidenceClaimLevel = Field(
        "triage_evidence_bundle_not_finding",
        description="Bounded claim level. This schema never represents reproduction.",
    )
    subject: WindowsEvidenceSubject = Field(
        default_factory=WindowsEvidenceSubject,
        description="Primary binary, function, candidate, or validation subject.",
    )
    source_tools: list[str] = Field(
        default_factory=list,
        description="Tools that produced the facts in this bundle.",
    )
    tool_sequence: list[str] = Field(
        default_factory=list,
        description="Ordered tool calls for replayable agent workflows.",
    )
    evidence_refs: list[WindowsEvidenceReference] = Field(
        default_factory=list,
        description="Atomic evidence references with provenance and reason codes.",
    )
    coverage: WindowsEvidenceCoverage = Field(
        default_factory=WindowsEvidenceCoverage,
        description="Project fact, Ghidra-delta, and validation coverage summary.",
    )
    confidence: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Optional normalized confidence for this bounded claim.",
    )
    confidence_reason: str | None = Field(None)
    reason_codes: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    add_to_kb: bool = Field(
        False,
        description="If true, add the bundle as a compact KB evidence node.",
    )


class WindowsAgentEvidenceBundleResult(BaseModel):
    bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None


class WindowsAgentEvidenceBundleTool(
    MemoryTool[WindowsAgentEvidenceBundleArgs, WindowsAgentEvidenceBundleResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_agent_evidence_bundle",
                description=(
                    "Normalize Windows candidate, functionization, Ghidra-delta, "
                    "and validation facts into a bounded evidence bundle. This "
                    "is a provenance schema, not a finding verdict."
                ),
                tags=("windows", "pe", "evidence", "agentic", "review"),
            ),
            WindowsAgentEvidenceBundleArgs,
            WindowsAgentEvidenceBundleResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsAgentEvidenceBundleArgs,
    ) -> WindowsAgentEvidenceBundleResult:
        bundle = make_windows_evidence_bundle(
            bundle_id=args.bundle_id,
            claim_level=args.claim_level,
            subject=args.subject,
            source_tools=args.source_tools,
            tool_sequence=args.tool_sequence,
            evidence_refs=args.evidence_refs,
            coverage=args.coverage,
            confidence=args.confidence,
            confidence_reason=args.confidence_reason,
            reason_codes=args.reason_codes,
            blockers=args.blockers,
            next_actions=args.next_actions,
            notes=args.notes,
        )
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_agent_evidence_bundle",
                    props={
                        "bundle_id": bundle.bundle_id,
                        "claim_level": bundle.claim_level,
                        "subject_kind": bundle.subject.kind,
                        "source_tools": bundle.source_tools,
                        "blocker_count": len(bundle.blockers),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsAgentEvidenceBundleResult(
            bundle=bundle,
            evidence_node_id=evidence_node_id,
        )


def make_windows_evidence_bundle(
    *,
    claim_level: WindowsEvidenceClaimLevel,
    subject: WindowsEvidenceSubject,
    bundle_id: str | None = None,
    source_tools: list[str] | None = None,
    tool_sequence: list[str] | None = None,
    evidence_refs: list[WindowsEvidenceReference] | None = None,
    coverage: WindowsEvidenceCoverage | None = None,
    confidence: float | None = None,
    confidence_reason: str | None = None,
    reason_codes: list[str] | None = None,
    blockers: list[str] | None = None,
    next_actions: list[str] | None = None,
    notes: list[str] | None = None,
) -> WindowsEvidenceBundle:
    subject = _normalize_subject(subject)
    refs = [_normalize_ref(ref) for ref in (evidence_refs or [])]
    bundle = WindowsEvidenceBundle(
        bundle_id=bundle_id or "",
        claim_level=claim_level,
        subject=subject,
        source_tools=_dedupe(source_tools or []),
        tool_sequence=list(tool_sequence or []),
        evidence_refs=refs,
        coverage=coverage or WindowsEvidenceCoverage(),
        confidence=confidence,
        confidence_reason=confidence_reason,
        reason_codes=_dedupe(reason_codes or []),
        blockers=_dedupe(blockers or []),
        next_actions=_dedupe(next_actions or []),
        notes=_dedupe(notes or []),
    )
    if not bundle.bundle_id:
        bundle.bundle_id = _default_bundle_id(bundle)
    return bundle


def evidence_ref(
    *,
    kind: WindowsEvidenceRefKind,
    source: str,
    summary: str,
    address: int | None = None,
    confidence: float | None = None,
    reason_codes: list[str] | None = None,
    provenance: list[str] | None = None,
) -> WindowsEvidenceReference:
    return _normalize_ref(
        WindowsEvidenceReference(
            kind=kind,
            source=source,
            summary=summary,
            address=address,
            confidence=confidence,
            reason_codes=reason_codes or [],
            provenance=provenance or [],
        )
    )


def _normalize_subject(subject: WindowsEvidenceSubject) -> WindowsEvidenceSubject:
    if subject.va is not None and not subject.va_hex:
        subject = subject.model_copy(update={"va_hex": f"0x{subject.va:x}"})
    return subject


def _normalize_ref(ref: WindowsEvidenceReference) -> WindowsEvidenceReference:
    if ref.address is not None and not ref.address_hex:
        ref = ref.model_copy(update={"address_hex": f"0x{ref.address:x}"})
    return ref


def _default_bundle_id(bundle: WindowsEvidenceBundle) -> str:
    payload = bundle.model_dump(mode="json", exclude={"bundle_id"})
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"win-evidence-{digest}"


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsAgentEvidenceBundleTool:
    return WindowsAgentEvidenceBundleTool()
