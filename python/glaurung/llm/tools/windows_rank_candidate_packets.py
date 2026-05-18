from __future__ import annotations

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import WindowsReviewPacket
from .windows_emit_vm_validation_plan import WindowsVmValidationPlan


class WindowsRankCandidatePacketsArgs(BaseModel):
    packets: list[WindowsReviewPacket] = Field(
        ...,
        description="Review packets emitted by windows_emit_review_packet or composer.",
    )
    validation_plans: list[WindowsVmValidationPlan] = Field(
        default_factory=list,
        description=(
            "Optional VM validation plans emitted by windows_emit_vm_validation_plan. "
            "Plans are joined by candidate_id and used to expose runtime blockers."
        ),
    )
    max_results: int = Field(20, description="Maximum ranked packets to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact ranking evidence node to the KB.",
    )


class RankedWindowsCandidate(BaseModel):
    rank: int
    score: float
    packet: WindowsReviewPacket
    validation_plan: WindowsVmValidationPlan | None = None
    validation_blockers: list[str] = Field(default_factory=list)
    reasons: list[str]
    validation_ready: bool


class WindowsRankCandidatePacketsResult(BaseModel):
    ranked: list[RankedWindowsCandidate]
    input_count: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsRankCandidatePacketsTool(
    MemoryTool[WindowsRankCandidatePacketsArgs, WindowsRankCandidatePacketsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_rank_candidate_packets",
                description=(
                    "Rank Windows review packets for validation priority using "
                    "attacker class, sink risk, gate status, confidence, and provenance."
                ),
                tags=("windows", "pe", "candidate", "ranking", "triage"),
            ),
            WindowsRankCandidatePacketsArgs,
            WindowsRankCandidatePacketsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRankCandidatePacketsArgs,
    ) -> WindowsRankCandidatePacketsResult:
        validation_plans = _validation_plans_by_candidate(args.validation_plans)
        ranked = [
            RankedWindowsCandidate(
                rank=0,
                score=score,
                packet=packet,
                validation_plan=validation_plan,
                validation_blockers=_validation_blockers(validation_plan),
                reasons=reasons,
                validation_ready=_validation_ready(packet, validation_plan),
            )
            for packet in args.packets
            for validation_plan in [validation_plans.get(packet.candidate_id)]
            for score, reasons in [_score_packet(packet, validation_plan)]
        ]
        ranked.sort(key=lambda item: item.score, reverse=True)
        ranked = ranked[: max(0, args.max_results)]
        for idx, item in enumerate(ranked, start=1):
            item.rank = idx

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_rank_candidate_packets",
                    props={
                        "input_count": len(args.packets),
                        "ranked_count": len(ranked),
                        "top_candidate": ranked[0].packet.candidate_id if ranked else None,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsRankCandidatePacketsResult(
            ranked=ranked,
            input_count=len(args.packets),
            evidence_node_id=evidence_node_id,
            notes=[
                "ranking is triage priority only; it does not promote candidates to findings"
            ],
        )


def _score_packet(
    packet: WindowsReviewPacket,
    validation_plan: WindowsVmValidationPlan | None = None,
) -> tuple[float, list[str]]:
    score = packet.confidence * 30.0
    reasons = [f"confidence contributes {packet.confidence:.2f}"]

    if packet.priority == "high":
        score += 30.0
        reasons.append("packet priority is high")
    elif packet.priority == "medium":
        score += 15.0
        reasons.append("packet priority is medium")

    attacker = packet.attacker_class.lower()
    if any(token in attacker for token in ("remote", "network")):
        score += 20.0
        reasons.append("remote or network attacker class")
    elif any(token in attacker for token in ("unpriv", "low", "appcontainer", "lpac")):
        score += 15.0
        reasons.append("low-privilege attacker class")

    if packet.sink_kind.lower() in {"copy", "write"}:
        score += 15.0
        reasons.append("memory write/copy sink")
    elif packet.sink_kind.lower() in {"free", "refcount", "completion"}:
        score += 12.0
        reasons.append("lifetime or ownership sink")
    elif packet.sink_kind.lower() in {"lock", "irql"}:
        score += 8.0
        reasons.append("context or locking sink")

    if packet.gate_status in {"missing", "not_dominated"}:
        score += 20.0
        reasons.append("gate appears missing or non-dominating")
    elif packet.gate_status == "gate_after_sink":
        score += 16.0
        reasons.append("gate appears after sink")
    elif packet.gate_status in {"unknown", "gate_same_line"}:
        score += 8.0
        reasons.append("gate evidence is weak or unresolved")
    elif packet.gate_status == "dominated":
        score -= 12.0
        reasons.append("gate is recorded as dominated")
    if packet.missing_required_gates:
        score += min(12.0, 4.0 * len(packet.missing_required_gates))
        reasons.append(
            "missing required gate semantics: "
            + ", ".join(packet.missing_required_gates[:4])
        )
    if packet.proven_gates and not packet.missing_required_gates:
        score -= 4.0
        reasons.append("all required gate semantics are recorded as proven")

    provenance = " ".join(packet.provenance).lower()
    if any(token in provenance for token in ("dynamic", "trace", "vm", "kd")):
        score += 12.0
        reasons.append("dynamic or VM provenance present")
    if any(token in provenance for token in ("ir", "cfg")):
        score += 8.0
        reasons.append("IR or CFG provenance present")
    if any(token in provenance for token in ("pseudocode", "decompiler")):
        score -= 4.0
        reasons.append("currently depends on pseudocode/decompiler evidence")
    if not packet.path:
        score -= 10.0
        reasons.append("no source-to-sink path supplied")
    if not packet.promotion_preconditions_met:
        score -= 25.0
        reasons.append("promotion preconditions are not met")
    if packet.promotion_blockers:
        score -= min(20.0, 5.0 * len(packet.promotion_blockers))
        reasons.append("packet has promotion blockers")
    if validation_plan is not None:
        if validation_plan.ready_for_validation:
            score += 10.0
            reasons.append("VM validation plan is ready")
        else:
            score -= min(18.0, 6.0 * len(validation_plan.blockers))
            reasons.append("VM validation plan has runtime blockers")

    return round(max(0.0, score), 2), reasons


def _validation_ready(
    packet: WindowsReviewPacket,
    validation_plan: WindowsVmValidationPlan | None = None,
) -> bool:
    attacker = packet.attacker_class.lower()
    reachable = any(
        token in attacker for token in ("remote", "network", "unpriv", "low", "appcontainer", "lpac")
    )
    gate_concern = packet.gate_status in {
        "missing",
        "not_dominated",
        "gate_after_sink",
        "unknown",
    }
    packet_ready = (
        reachable
        and gate_concern
        and bool(packet.path)
        and packet.promotion_preconditions_met
        and not packet.promotion_blockers
    )
    if validation_plan is None:
        return packet_ready
    return packet_ready and validation_plan.ready_for_validation


def _validation_blockers(
    validation_plan: WindowsVmValidationPlan | None,
) -> list[str]:
    if validation_plan is None:
        return []
    return list(validation_plan.blockers)


def _validation_plans_by_candidate(
    plans: list[WindowsVmValidationPlan],
) -> dict[str, WindowsVmValidationPlan]:
    out: dict[str, WindowsVmValidationPlan] = {}
    for plan in plans:
        out.setdefault(plan.candidate_id, plan)
    return out


def build_tool() -> MemoryTool[
    WindowsRankCandidatePacketsArgs, WindowsRankCandidatePacketsResult
]:
    return WindowsRankCandidatePacketsTool()
