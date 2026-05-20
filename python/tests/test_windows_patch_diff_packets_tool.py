from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_patch_diff_packets import build_tool

import glaurung as g


_SWITCHY_V1 = Path("samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2")
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_patch_diff_packets_emit_review_packets(tmp_path: Path) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            max_diff_rows=16,
            max_items=8,
            max_packets=4,
            add_to_kb=True,
        ),
    )

    assert result.claim_level == "patch_diff_review_not_finding"
    assert result.review_items
    assert result.packet_count > 0
    assert len(result.packets) == result.packet_count
    packet = result.packets[0]
    assert packet.claim_level == "candidate_not_finding"
    assert packet.candidate_id.startswith("patchdiff-")
    assert packet.binary == b.name
    assert packet.diff_context is not None
    assert packet.diff_context.changed_functions
    assert packet.source_refinement_status == "missing"
    assert any("patch-diff" in item for item in packet.source_refinement_blockers)
    assert packet.promotion_preconditions_met is False
    assert "windows_patch_diff_packets" in result.tool_sequence
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_patch_diff_packets"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_patch_diff_packets() -> None:
    agent = create_memory_agent()

    assert "windows_patch_diff_packets" in agent._function_toolset.tools
