from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_emit_review_packet import (
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from glaurung.llm.tools.windows_rank_candidate_packets import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _packet(
    candidate_id: str,
    *,
    attacker_class: str,
    sink_kind: str,
    gate_status: str,
    priority: str,
    confidence: float,
    provenance: list[str] | None = None,
    proven_gates: list[str] | None = None,
    missing_required_gates: list[str] | None = None,
    promotion_preconditions_met: bool = True,
    promotion_blockers: list[str] | None = None,
) -> WindowsReviewPacket:
    return WindowsReviewPacket(
        candidate_id=candidate_id,
        binary="ntoskrnl.exe",
        build="26100.1",
        entrypoint="nt!NtExample",
        attacker_class=attacker_class,
        source_role="output_buffer",
        source_arg="arg1",
        sink_symbol="RtlCopyMemory",
        sink_kind=sink_kind,
        required_gates=["destination_range_valid"],
        proven_gates=proven_gates or [],
        missing_required_gates=missing_required_gates or [],
        gate_status=gate_status,  # type: ignore[arg-type]
        path=[
            WindowsReviewPathStep(
                function="nt!NtExample",
                symbol="RtlCopyMemory",
                arg_index=0,
                role="destination_buffer",
            )
        ],
        evidence=[
            WindowsReviewEvidence(
                source="test",
                summary="synthetic packet",
                provenance=provenance or ["pseudocode_candidate_composition"],
            )
        ],
        provenance=provenance or ["pseudocode_candidate_composition"],
        required_project_facts=["function_names", "call_xrefs"],
        promotion_preconditions_met=promotion_preconditions_met,
        promotion_blockers=promotion_blockers or [],
        priority=priority,  # type: ignore[arg-type]
        confidence=confidence,
        confidence_reason="test",
        next_validation=["test validation"],
        false_positive_questions=["test question"],
    )


def test_windows_rank_candidate_packets_orders_by_validation_priority(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    lower = _packet(
        "internal-safe",
        attacker_class="kernel_internal",
        sink_kind="copy",
        gate_status="dominated",
        priority="low",
        confidence=0.8,
        provenance=["cfg", "asb_pe_gate_metadata"],
    )
    higher = _packet(
        "remote-missing-gate",
        attacker_class="remote_network",
        sink_kind="copy",
        gate_status="missing",
        priority="high",
        confidence=0.65,
        provenance=["ir_fact", "asb_pe_sink_metadata"],
    )
    blocked = _packet(
        "blocked-missing-facts",
        attacker_class="remote_network",
        sink_kind="copy",
        gate_status="missing",
        priority="high",
        confidence=0.9,
        provenance=["ir_fact", "asb_pe_sink_metadata"],
        promotion_preconditions_met=False,
        promotion_blockers=["missing project fact coverage context"],
    )
    partial_gate = _packet(
        "partial-gate-coverage",
        attacker_class="local_unprivileged",
        sink_kind="copy",
        gate_status="unknown",
        priority="high",
        confidence=0.7,
        provenance=["cfg", "asb_pe_gate_metadata"],
        proven_gates=["destination_range_valid"],
        missing_required_gates=["byte_count_bounded"],
        promotion_preconditions_met=False,
        promotion_blockers=["required gate coverage unresolved: byte_count_bounded"],
    )

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(packets=[lower, blocked, higher, partial_gate], add_to_kb=True),
    )

    assert result.input_count == 4
    assert result.ranked[0].packet.candidate_id == "remote-missing-gate"
    assert result.ranked[0].rank == 1
    assert result.ranked[0].validation_ready is True
    assert any("remote or network" in reason for reason in result.ranked[0].reasons)
    blocked_rank = next(
        item for item in result.ranked if item.packet.candidate_id == "blocked-missing-facts"
    )
    assert blocked_rank.validation_ready is False
    assert any("promotion preconditions" in reason for reason in blocked_rank.reasons)
    partial_rank = next(
        item for item in result.ranked if item.packet.candidate_id == "partial-gate-coverage"
    )
    assert partial_rank.validation_ready is False
    assert any("missing required gate semantics" in reason for reason in partial_rank.reasons)
    assert result.ranked[-1].packet.candidate_id == "internal-safe"
    assert result.ranked[-1].validation_ready is False
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_rank_candidate_packets"
        for node in ctx.kb.nodes()
    )


def test_windows_rank_candidate_packets_honors_max_results(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            packets=[
                _packet(
                    "one",
                    attacker_class="local_unprivileged",
                    sink_kind="copy",
                    gate_status="missing",
                    priority="high",
                    confidence=0.6,
                ),
                _packet(
                    "two",
                    attacker_class="local_unprivileged",
                    sink_kind="free",
                    gate_status="missing",
                    priority="high",
                    confidence=0.6,
                ),
            ],
            max_results=1,
        ),
    )

    assert len(result.ranked) == 1
    assert result.ranked[0].rank == 1


def test_memory_agent_registers_windows_rank_candidate_packets() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_rank_candidate_packets" in agent._function_toolset.tools
