from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


GateStatus = Literal[
    "unknown",
    "missing",
    "gate_before_sink",
    "gate_after_sink",
    "gate_same_line",
    "dominated",
    "not_dominated",
]
CandidatePriority = Literal["low", "medium", "high"]


class WindowsReviewPathStep(BaseModel):
    function: str
    symbol: str | None = None
    arg_index: int | None = None
    role: str | None = None
    evidence: str | None = None


class WindowsReviewEvidence(BaseModel):
    source: str
    summary: str
    provenance: list[str] = Field(default_factory=list)


class WindowsEmitReviewPacketArgs(BaseModel):
    candidate_id: str | None = Field(
        None,
        description="Optional stable candidate id. If absent, one is derived.",
    )
    binary: str = Field(..., description="Binary or driver name.")
    build: str | None = Field(None, description="Windows build or product version.")
    entrypoint: str = Field(..., description="Surface entrypoint or audited function.")
    attacker_class: str = Field(
        ...,
        description="Attacker class, e.g. local_unprivileged, appcontainer, remote.",
    )
    source_role: str = Field(
        ...,
        description="Role of attacker-controlled value: buffer, length, handle, etc.",
    )
    source_arg: str | None = Field(
        None,
        description="Optional source argument name, index, or expression.",
    )
    sink_symbol: str = Field(..., description="Security-relevant operation symbol.")
    sink_kind: str = Field(
        ...,
        description="Security-relevant operation family: copy, write, free, etc.",
    )
    required_gates: list[str] = Field(
        default_factory=list,
        description="Gate semantics expected before the sink.",
    )
    gate_status: GateStatus = Field(
        "unknown",
        description="Current gate evidence for the source-to-sink path.",
    )
    path: list[WindowsReviewPathStep] = Field(
        default_factory=list,
        description="Observed source-to-sink path steps.",
    )
    evidence: list[WindowsReviewEvidence] = Field(
        default_factory=list,
        description="Atomic observations that support or weaken the packet.",
    )
    provenance: list[str] = Field(
        default_factory=list,
        description="Overall fact provenance: PE, PDB, ASB metadata, IR, dynamic trace.",
    )
    notes: list[str] = Field(default_factory=list)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact review-packet evidence node to the KB.",
    )


class WindowsReviewPacket(BaseModel):
    candidate_id: str
    claim_level: Literal["candidate_not_finding"] = "candidate_not_finding"
    binary: str
    build: str | None
    entrypoint: str
    attacker_class: str
    source_role: str
    source_arg: str | None
    sink_symbol: str
    sink_kind: str
    required_gates: list[str]
    gate_status: GateStatus
    path: list[WindowsReviewPathStep]
    evidence: list[WindowsReviewEvidence]
    provenance: list[str]
    priority: CandidatePriority
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_reason: str
    next_validation: list[str]
    false_positive_questions: list[str]
    notes: list[str] = Field(default_factory=list)


class WindowsEmitReviewPacketResult(BaseModel):
    packet: WindowsReviewPacket
    evidence_node_id: str | None = None


class WindowsEmitReviewPacketTool(
    MemoryTool[WindowsEmitReviewPacketArgs, WindowsEmitReviewPacketResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_emit_review_packet",
                description=(
                    "Normalize Windows source/sink/gate/path observations into a "
                    "review packet for candidate triage. This does not claim a bug."
                ),
                tags=("windows", "pe", "review", "candidate", "triage"),
            ),
            WindowsEmitReviewPacketArgs,
            WindowsEmitReviewPacketResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsEmitReviewPacketArgs,
    ) -> WindowsEmitReviewPacketResult:
        provenance = _dedupe(args.provenance + _evidence_provenance(args.evidence))
        priority = _priority(args)
        confidence, reason = _confidence(args, provenance)
        packet = WindowsReviewPacket(
            candidate_id=args.candidate_id or _candidate_id(args),
            binary=args.binary,
            build=args.build,
            entrypoint=args.entrypoint,
            attacker_class=args.attacker_class,
            source_role=args.source_role,
            source_arg=args.source_arg,
            sink_symbol=args.sink_symbol,
            sink_kind=args.sink_kind,
            required_gates=args.required_gates,
            gate_status=args.gate_status,
            path=args.path,
            evidence=args.evidence,
            provenance=provenance,
            priority=priority,
            confidence=confidence,
            confidence_reason=reason,
            next_validation=_next_validation(args, priority),
            false_positive_questions=_false_positive_questions(args),
            notes=[
                "review packet only; VM or dynamic validation is required before finding promotion",
                *args.notes,
            ],
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_emit_review_packet",
                    props={
                        "candidate_id": packet.candidate_id,
                        "priority": packet.priority,
                        "confidence": packet.confidence,
                        "gate_status": packet.gate_status,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsEmitReviewPacketResult(
            packet=packet,
            evidence_node_id=evidence_node_id,
        )


def _candidate_id(args: WindowsEmitReviewPacketArgs) -> str:
    raw = "-".join(
        [
            args.binary,
            args.build or "unknown-build",
            args.entrypoint,
            args.source_role,
            args.sink_symbol,
        ]
    )
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-").lower()


def _evidence_provenance(evidence: list[WindowsReviewEvidence]) -> list[str]:
    out: list[str] = []
    for item in evidence:
        out.extend(item.provenance)
        if item.source:
            out.append(item.source)
    return out


def _priority(args: WindowsEmitReviewPacketArgs) -> CandidatePriority:
    score = 0
    attacker = args.attacker_class.lower()
    if any(token in attacker for token in ("remote", "network", "unpriv", "low", "appcontainer")):
        score += 2
    if args.sink_kind.lower() in {
        "copy",
        "write",
        "free",
        "refcount",
        "completion",
        "lock",
        "irql",
    }:
        score += 2
    if args.gate_status in {"missing", "gate_after_sink", "not_dominated"}:
        score += 2
    elif args.gate_status in {"unknown", "gate_same_line"}:
        score += 1
    if args.path:
        score += 1
    if len(args.path) > 3:
        score -= 1
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _confidence(
    args: WindowsEmitReviewPacketArgs,
    provenance: list[str],
) -> tuple[float, str]:
    score = 0.2
    reasons: list[str] = ["base packet fields supplied"]
    provenance_text = " ".join(provenance).lower()
    if any(token in provenance_text for token in ("pdb", "symbol", "prototype")):
        score += 0.15
        reasons.append("symbol/type provenance present")
    if any(token in provenance_text for token in ("ir", "cfg", "decompiler", "pseudocode")):
        score += 0.15
        reasons.append("code-path evidence present")
    if "asb" in provenance_text or "metadata" in provenance_text:
        score += 0.15
        reasons.append("ASB semantic metadata present")
    if any(token in provenance_text for token in ("dynamic", "trace", "vm", "kd")):
        score += 0.2
        reasons.append("dynamic evidence present")
    if args.path:
        score += min(0.15, 0.05 * len(args.path))
        reasons.append("source-to-sink path supplied")
    if args.required_gates:
        score += 0.05
        reasons.append("expected gate semantics supplied")
    if args.gate_status == "unknown":
        score -= 0.1
        reasons.append("gate status unknown")
    if not args.evidence:
        score -= 0.1
        reasons.append("no atomic evidence items supplied")
    return max(0.0, min(0.95, round(score, 2))), "; ".join(reasons)


def _next_validation(
    args: WindowsEmitReviewPacketArgs,
    priority: CandidatePriority,
) -> list[str]:
    steps = [
        "verify the source role against the function prototype or PDB type data",
        "replace line-order or pseudocode evidence with CFG dominance/path facts",
    ]
    if args.gate_status in {"missing", "gate_after_sink", "not_dominated"}:
        steps.append("trace whether any equivalent gate exists on all paths to the sink")
    elif args.gate_status in {"gate_before_sink", "gate_same_line", "unknown"}:
        steps.append("prove or reject that the observed gate dominates the sink")
    if priority == "high":
        steps.append("build a VM validation plan for the shortest reachable surface")
    return steps


def _false_positive_questions(args: WindowsEmitReviewPacketArgs) -> list[str]:
    questions = [
        "Is the source value actually attacker-controlled for this build and caller class?",
        "Does the source-to-sink path require a prior privilege, mode, object, or state gate?",
        "Do the sink arguments consume the same value, or only a sanitized copy?",
        "Do all feasible paths reach the sink, or only an unreachable/error path?",
    ]
    if args.required_gates:
        questions.append("Does an equivalent gate exist under a different wrapper or helper name?")
    if args.sink_kind.lower() in {"copy", "write"}:
        questions.append("Are size/count units consistent between source, checks, and sink?")
    if args.sink_kind.lower() in {"free", "refcount", "completion"}:
        questions.append("Does ownership transfer or reference lifetime invalidate the apparent path?")
    return questions


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def build_tool() -> MemoryTool[
    WindowsEmitReviewPacketArgs, WindowsEmitReviewPacketResult
]:
    return WindowsEmitReviewPacketTool()
