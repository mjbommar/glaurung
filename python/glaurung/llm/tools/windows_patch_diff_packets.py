from __future__ import annotations

import re
from pathlib import Path

from pydantic import Field

from ..agents.windows_patch_diff_review import (
    WindowsPatchDiffReviewConfig,
    WindowsPatchDiffReviewItem,
    WindowsPatchDiffReviewResult,
    run_windows_patch_diff_review,
)
from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import (
    WindowsDiffContext,
    WindowsEmitReviewPacketArgs,
    WindowsEmitReviewPacketTool,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)


class WindowsPatchDiffPacketsArgs(WindowsPatchDiffReviewConfig):
    attacker_class: str = Field(
        "unknown",
        description="Attacker class to attach to emitted patch-diff packets.",
    )
    required_project_facts: list[str] = Field(
        default_factory=lambda: [
            "function_names",
            "call_xrefs",
            "cfg",
            "decompile_context",
            "source_arg_roles",
            "gate_semantics",
        ],
        description="Project fact classes required before patch-diff packets can promote.",
    )
    max_packets: int = Field(16, ge=0, le=128)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact patch-diff packet evidence node.",
    )


class WindowsPatchDiffPacketsResult(WindowsPatchDiffReviewResult):
    packet_count: int
    packets: list[WindowsReviewPacket]
    evidence_node_id: str | None = None


class WindowsPatchDiffPacketsTool(
    MemoryTool[WindowsPatchDiffPacketsArgs, WindowsPatchDiffPacketsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_patch_diff_packets",
                description=(
                    "Convert deterministic Windows patch-diff review items into "
                    "bounded non-finding review packets for validation planning."
                ),
                tags=("windows", "pe", "patch", "diff", "packet"),
            ),
            WindowsPatchDiffPacketsArgs,
            WindowsPatchDiffPacketsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsPatchDiffPacketsArgs,
    ) -> WindowsPatchDiffPacketsResult:
        review = run_windows_patch_diff_review(args)
        emitter = WindowsEmitReviewPacketTool()
        packets = [
            emitter.run(ctx, kb, _packet_args(item, review, args)).packet
            for item in review.review_items[: args.max_packets]
        ]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_patch_diff_packets",
                    props={
                        "binary_a": args.binary_a,
                        "binary_b": args.binary_b,
                        "review_item_count": len(review.review_items),
                        "packet_count": len(packets),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsPatchDiffPacketsResult(
            binary_diff=review.binary_diff,
            seed_triage=review.seed_triage,
            security_facts=review.security_facts,
            prototype_diff=review.prototype_diff,
            boundary_diff=review.boundary_diff,
            data_table_diff=review.data_table_diff,
            review_items=review.review_items,
            function_identity_count=review.function_identity_count,
            pdb_identity_record_count=review.pdb_identity_record_count,
            pdb_identity_manifest_path=review.pdb_identity_manifest_path,
            tool_sequence=[
                *review.tool_sequence,
                "windows_patch_diff_packets",
            ],
            evidence_bundle=review.evidence_bundle,
            notes=[
                *review.notes,
                "patch-diff packets preserve changed-function triage as candidate_not_finding",
            ],
            packet_count=len(packets),
            packets=packets,
            evidence_node_id=evidence_node_id,
        )


def _packet_args(
    item: WindowsPatchDiffReviewItem,
    review: WindowsPatchDiffReviewResult,
    args: WindowsPatchDiffPacketsArgs,
) -> WindowsEmitReviewPacketArgs:
    binary = Path(args.binary_b).name
    function = item.function or str(item.next_args.get("item_id") or item.kind)
    sink_kind = f"patch_diff_{item.kind}"
    source_blockers = [
        "patch-diff changed area has no attacker-controlled source proof",
    ]
    if item.confidence < 0.5:
        source_blockers.append("patch-diff function identity confidence is low")
    source_blockers.extend(args.functionization_blockers)
    evidence = [
        WindowsReviewEvidence(
            source="windows_patch_diff_review",
            summary=f"rank {item.rank}: {item.summary}",
            provenance=[
                f"review_kind:{item.kind}",
                f"review_priority:{item.priority}",
                f"review_confidence:{item.confidence}",
                *item.match_basis,
                *item.reason_codes,
            ],
        ),
        WindowsReviewEvidence(
            source="windows_binary_diff_summary",
            summary=(
                f"changed={review.binary_diff.changed}; "
                f"added={review.binary_diff.added}; "
                f"removed={review.binary_diff.removed}"
            ),
            provenance=[args.binary_a, args.binary_b],
        ),
    ]
    if review.pdb_identity_manifest_path:
        evidence.append(
            WindowsReviewEvidence(
                source="windows_pdb_identity_manifest",
                summary=f"{review.pdb_identity_record_count} cached PDB identity record(s)",
                provenance=[review.pdb_identity_manifest_path],
            )
        )
    return WindowsEmitReviewPacketArgs(
        candidate_id=f"patchdiff-{_slug(item.kind)}-{_slug(function)}",
        binary=binary,
        build=None,
        entrypoint=function,
        attacker_class=args.attacker_class,
        source_role="unknown_patch_diff_source",
        source_refinement_status="missing",
        source_refinement_sources=[
            "windows_patch_diff_review",
            *item.match_basis,
        ],
        source_refinement_blockers=source_blockers,
        sink_symbol=function,
        sink_kind=sink_kind,
        gate_status="unknown",
        path=[
            WindowsReviewPathStep(
                function=function,
                symbol=function,
                role="patch_diff_review_item",
                evidence=f"windows_patch_diff_review:rank:{item.rank}",
            )
        ],
        evidence=evidence,
        provenance=[
            "windows_patch_diff_review",
            "windows_binary_diff_summary",
            *review.tool_sequence,
        ],
        diff_context=WindowsDiffContext(
            pre_build=Path(args.binary_a).name,
            post_build=Path(args.binary_b).name,
            changed_functions=[function] if item.function else [],
            diff_signals=[*item.reason_codes, *item.match_basis],
            notes=[
                item.summary,
                "patch-diff packet is a validation seed, not a vulnerability finding",
            ],
        ),
        required_project_facts=list(args.required_project_facts),
        notes=[
            "emitted from patch-diff review",
            "source, gate, and runtime evidence are required before promotion",
        ],
    )


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower()


def build_tool() -> MemoryTool[
    WindowsPatchDiffPacketsArgs,
    WindowsPatchDiffPacketsResult,
]:
    return WindowsPatchDiffPacketsTool()
