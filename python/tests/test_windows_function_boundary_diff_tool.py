from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_function_boundary_diff import build_tool


COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_function_boundary_diff_ranks_missing_functionization_gaps(
    tmp_path: Path,
) -> None:
    assert COMPARISON.exists()
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            comparison_path=str(COMPARISON),
            sort_by="missing",
            max_rows=5,
        ),
    )

    assert result.file_count_total == 30
    assert result.total_missing_entries == 1041
    assert result.total_extra_entries == 3116
    assert result.rows[0].file == "windows-update-intel-npu-ze_loader.dll"
    assert result.rows[0].missing_entries == 240
    assert "tiny_function_recall_gap" in result.rows[0].cause_buckets
    assert "windows_function_start_explain" in result.rows[0].next_tools
    assert result.rows[1].file == "win11-webservices.dll"
    assert (
        result.evidence_bundle.claim_level == "functionization_review_not_vulnerability"
    )
    assert result.evidence_bundle.coverage.ghidra_missing_entries == 1041
    assert result.evidence_bundle.coverage.ghidra_extra_entries == 3116
    assert "windows_function_boundary_diff" in result.evidence_bundle.source_tools


def test_windows_function_boundary_diff_filters_one_file_and_adds_evidence(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            comparison_path=str(COMPARISON),
            file="windows-update-amd-xilinx-xrt_coreutil.dll",
            add_to_kb=True,
        ),
    )

    assert result.file_count_total == 30
    assert result.filtered_file_count == 1
    assert result.rows[0].file == "windows-update-amd-xilinx-xrt_coreutil.dll"
    assert result.rows[0].extra_entries == 963
    assert "precision_priority" in result.rows[0].cause_buckets
    assert "windows_candidate_start_worklist" in result.rows[0].next_tools
    assert result.evidence_node_id is not None


def test_memory_agent_registers_windows_function_boundary_diff() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_function_boundary_diff" in agent._function_toolset.tools
