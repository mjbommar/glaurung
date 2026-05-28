from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_simd_start_classifier import build_tool


COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)
DIAGNOSTICS = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_simd_start_classifier_keeps_npu_simd_as_boundary_candidate(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            file="windows-update-intel-npu-ze_loader.dll",
            address="0x180033b20",
        ),
    )

    assert result.is_simd_head is True
    assert result.simd_prefix == "0f10"
    assert result.classification == "candidate_requires_boundary_review"
    assert result.confidence == "medium"
    assert "simd_head" in result.reason_codes
    assert "pdata_body_overlap" in result.reason_codes
    assert result.recommended_action == "keep_as_candidate_pending_boundary_evidence"
    assert (
        result.evidence_bundle.claim_level == "functionization_review_not_vulnerability"
    )


def test_windows_simd_start_classifier_flags_inside_owner_as_body_split_candidate(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            file="windows-update-intel-npu-npu_d3d12_umd.dll",
            address="0x1801857d4",
        ),
    )

    assert result.is_simd_head is True
    assert result.simd_prefix == "c4"
    assert result.classification == "body_split_candidate"
    assert result.explanation.containing_function is not None
    assert "owner_body_split_review" in result.reason_codes
    assert result.recommended_action == "review_as_body_split_candidate"


def test_windows_simd_start_classifier_delegates_non_simd_thunk(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            file="win10-dismcore.dll",
            address="0x18001f590",
        ),
    )

    assert result.is_simd_head is False
    assert result.classification == "not_simd_start"
    assert result.final_state == "strict_function"
    assert result.recommended_action == "keep_strict_function"


def test_memory_agent_registers_windows_simd_start_classifier() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_simd_start_classifier" in agent._function_toolset.tools
