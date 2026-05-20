from __future__ import annotations

import re

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import (
    WindowsEmitReviewPacketArgs,
    WindowsEmitReviewPacketTool,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from .windows_operation_classification_backlog import (
    SecurityRelevance,
    WindowsOperationBacklogEntry,
    WindowsOperationClassificationBacklogArgs,
    WindowsOperationClassificationBacklogTool,
)


class WindowsOperationBacklogPacketsArgs(BaseModel):
    backlog_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-operation-classification-backlog.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(None, description="Optional target id filter.")
    component: str | None = Field(None, description="Optional component filter.")
    symbol: str | None = Field(None, description="Optional exact backlog symbol filter.")
    triage_category: str | None = Field(None, description="Optional triage category filter.")
    required_capability: str | None = Field(
        None,
        description="Optional required Glaurung/ASB capability filter.",
    )
    likely_security_relevance: SecurityRelevance | None = Field(
        None,
        description="Optional security-relevance filter.",
    )
    min_callsite_count: int = Field(0, ge=0)
    attacker_class: str = Field(
        "unknown",
        description="Attacker class to attach to emitted operation backlog packets.",
    )
    required_project_facts: list[str] = Field(
        default_factory=lambda: [
            "function_names",
            "call_xrefs",
            "operation_classification",
            "source_arg_roles",
            "gate_semantics",
        ],
        description="Project fact classes required before backlog packets can promote.",
    )
    max_packets: int = Field(16, ge=0, le=256)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-backlog packet evidence node.",
    )


class WindowsOperationBacklogPacketsResult(BaseModel):
    backlog_path: str
    backlog_entry_count_total: int
    matched_backlog_entry_count: int
    packet_count: int
    entries: list[WindowsOperationBacklogEntry]
    packets: list[WindowsReviewPacket]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsOperationBacklogPacketsTool(
    MemoryTool[WindowsOperationBacklogPacketsArgs, WindowsOperationBacklogPacketsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_operation_backlog_packets",
                description=(
                    "Convert ASB Windows operation-classification backlog entries "
                    "into bounded review packets. These are classifier work items, "
                    "not vulnerability findings."
                ),
                tags=("windows", "pe", "metadata", "operations", "backlog", "packet"),
            ),
            WindowsOperationBacklogPacketsArgs,
            WindowsOperationBacklogPacketsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsOperationBacklogPacketsArgs,
    ) -> WindowsOperationBacklogPacketsResult:
        backlog = WindowsOperationClassificationBacklogTool().run(
            ctx,
            kb,
            WindowsOperationClassificationBacklogArgs(
                backlog_path=args.backlog_path,
                target_id=args.target_id,
                component=args.component,
                symbol=args.symbol,
                triage_category=args.triage_category,
                required_capability=args.required_capability,
                likely_security_relevance=args.likely_security_relevance,
                min_callsite_count=args.min_callsite_count,
                add_to_kb=False,
            ),
        )
        packets: list[WindowsReviewPacket] = []
        emitter = WindowsEmitReviewPacketTool()
        for entry in backlog.entries[: args.max_packets]:
            packets.append(
                emitter.run(ctx, kb, _packet_args(entry, args)).packet
            )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_operation_backlog_packets",
                    props={
                        "backlog_path": backlog.backlog_path,
                        "target_id": args.target_id,
                        "component": args.component,
                        "symbol": args.symbol,
                        "packet_count": len(packets),
                        "matched_backlog_entry_count": len(backlog.entries),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsOperationBacklogPacketsResult(
            backlog_path=backlog.backlog_path,
            backlog_entry_count_total=backlog.entry_count_total,
            matched_backlog_entry_count=len(backlog.entries),
            packet_count=len(packets),
            entries=backlog.entries[: args.max_packets],
            packets=packets,
            evidence_node_id=evidence_node_id,
            notes=[
                "operation backlog packets are classifier work items, not sink proof",
                "packets require project callsite, source, gate, and runtime evidence before promotion",
            ],
        )


def _packet_args(
    entry: WindowsOperationBacklogEntry,
    args: WindowsOperationBacklogPacketsArgs,
) -> WindowsEmitReviewPacketArgs:
    sink_kind = _first(entry.candidate_operation_kinds, entry.triage_category)
    entrypoint = _first(entry.sample_callers, entry.symbol)
    evidence = [
        WindowsReviewEvidence(
            source="asb_operation_classification_backlog",
            summary=(
                f"{entry.id}: {entry.symbol}; relevance="
                f"{entry.likely_security_relevance}; observed_calls="
                f"{entry.observed_callsite_count}"
            ),
            provenance=[
                f"backlog:{entry.id}",
                f"source_snapshot:{entry.source_snapshot_id}",
                f"triage_category:{entry.triage_category}",
                *[
                    f"candidate_operation_kind:{kind}"
                    for kind in entry.candidate_operation_kinds
                ],
            ],
        ),
        WindowsReviewEvidence(
            source="asb_operation_classification_backlog_next_actions",
            summary="; ".join(entry.recommended_next_actions[:6]),
            provenance=[f"backlog:{entry.id}", "recommended_next_actions"],
        ),
    ]
    return WindowsEmitReviewPacketArgs(
        candidate_id=f"backlog-{_slug(entry.id)}-{_slug(entry.symbol)}",
        binary=entry.component,
        build=entry.build_label,
        entrypoint=entrypoint,
        attacker_class=args.attacker_class,
        source_role="unknown_operation_source",
        source_refinement_status="missing",
        source_refinement_sources=[f"operation_backlog:{entry.id}"],
        source_refinement_blockers=[
            "operation backlog has symbol/callsite metadata but no source value proof",
            *entry.required_capabilities,
        ],
        sink_symbol=entry.symbol,
        sink_kind=sink_kind,
        required_gates=list(entry.required_capabilities),
        missing_required_gates=list(entry.required_capabilities),
        gate_status="unknown",
        path=[
            WindowsReviewPathStep(
                function=entrypoint,
                symbol=entry.symbol,
                role="operation_backlog_symbol",
                evidence=f"asb_operation_classification_backlog:{entry.id}",
            )
        ],
        evidence=evidence,
        provenance=[
            "asb_operation_classification_backlog",
            "operation_classifier_work_item",
            f"likely_security_relevance:{entry.likely_security_relevance}",
        ],
        required_project_facts=list(args.required_project_facts),
        notes=[
            f"generated from operation classification backlog {entry.id}",
            "this packet prioritizes classifier coverage, not a confirmed sink path",
        ],
    )


def _first(values: list[str], fallback: str) -> str:
    for value in values:
        if value:
            return value
    return fallback


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower()


def build_tool() -> MemoryTool[
    WindowsOperationBacklogPacketsArgs,
    WindowsOperationBacklogPacketsResult,
]:
    return WindowsOperationBacklogPacketsTool()
