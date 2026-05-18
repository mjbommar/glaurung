from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_emit_review_packet import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_emit_review_packet_normalizes_candidate(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary="ntoskrnl.exe",
            build="26100.1",
            entrypoint="nt!NtExample",
            attacker_class="local_unprivileged",
            source_role="length",
            source_arg="arg2",
            sink_symbol="RtlCopyMemory",
            sink_kind="copy",
            required_gates=["byte_count_bounded", "destination_range_valid"],
            gate_status="missing",
            path=[
                {
                    "function": "nt!NtExample",
                    "symbol": "nt!Helper",
                    "arg_index": 2,
                    "role": "length",
                    "evidence": "arg2 passed to helper",
                },
                {
                    "function": "nt!Helper",
                    "symbol": "RtlCopyMemory",
                    "arg_index": 2,
                    "role": "byte_count",
                    "evidence": "helper count reaches copy",
                },
            ],
            evidence=[
                {
                    "source": "windows_trace_onehop_flow",
                    "summary": "source arg reaches helper-local copy length",
                    "provenance": ["asb_pe_sink_metadata", "supplied_pseudocode"],
                },
                {
                    "source": "windows_check_gate_to_sink",
                    "summary": "no matching gate around copy sink",
                    "provenance": ["asb_pe_gate_metadata"],
                },
            ],
            provenance=["pdb_public_symbol"],
            add_to_kb=True,
        ),
    )

    packet = result.packet
    assert packet.claim_level == "candidate_not_finding"
    assert packet.candidate_id == (
        "ntoskrnl.exe-26100.1-nt-ntexample-length-rtlcopymemory"
    )
    assert packet.priority == "high"
    assert packet.confidence >= 0.6
    assert "VM validation" in " ".join(packet.next_validation)
    assert any("size/count units" in q for q in packet.false_positive_questions)
    assert "review packet only" in packet.notes[0]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_emit_review_packet"
        for node in ctx.kb.nodes()
    )


def test_windows_emit_review_packet_keeps_safe_gate_lower_priority(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="manual-id",
            binary="driver.sys",
            entrypoint="DriverEntry",
            attacker_class="kernel_internal",
            source_role="handle",
            sink_symbol="ObDereferenceObject",
            sink_kind="refcount",
            gate_status="dominated",
            evidence=[
                {
                    "source": "windows_check_gate_to_sink",
                    "summary": "gate dominates sink in CFG evidence",
                    "provenance": ["cfg", "asb_pe_gate_metadata"],
                }
            ],
        ),
    )

    assert result.packet.candidate_id == "manual-id"
    assert result.packet.priority == "low"
    assert result.packet.confidence_reason
    assert any("ownership transfer" in q for q in result.packet.false_positive_questions)


def test_memory_agent_registers_windows_emit_review_packet() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_emit_review_packet" in agent._function_toolset.tools
