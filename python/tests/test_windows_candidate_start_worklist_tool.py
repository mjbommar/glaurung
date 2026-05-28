from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_candidate_start_worklist import build_tool


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


def _write_scan_rejection_worklist_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    comparison = tmp_path / "comparison.json"
    diagnostics = tmp_path / "diagnostics.json"
    comparison.write_text(
        json.dumps(
            [
                {
                    "file": "synthetic.dll",
                    "path": str(tmp_path / "synthetic.dll"),
                    "glaurung": {
                        "functions": 0,
                        "stats": {
                            "function_seed_kinds": [],
                            "seed_provenance": [],
                            "code_labels": [],
                            "scan_rejections": [
                                {
                                    "va": 0x180001234,
                                    "source_va": 0x180004000,
                                    "reason": "body_overlap:tiny_stub",
                                    "detail": "candidate lies inside owner body",
                                }
                            ],
                        },
                    },
                    "ghidra": {"metrics": {"internal_functions": 0}, "functions": []},
                    "address_gap": {"extra_entries": 1, "missing_entries": 0},
                }
            ]
        ),
        encoding="utf-8",
    )
    diagnostics.write_text(
        json.dumps(
            [
                {
                    "file": "synthetic.dll",
                    "path": str(tmp_path / "synthetic.dll"),
                    "missing": [],
                    "extra": [{"va": 0x180001234, "bytes": {"hex": "31c0c3"}}],
                }
            ]
        ),
        encoding="utf-8",
    )
    return comparison, diagnostics


def test_windows_candidate_start_worklist_ranks_npu_simd_missing_starts(
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
            diagnostic_kind="missing",
            max_rows=5,
        ),
    )

    assert result.total_candidates > 0
    assert result.rows[0].diagnostic_kind == "missing"
    assert result.rows[0].final_state == "ghidra_only"
    assert "simd_head" in result.rows[0].reason_codes
    assert result.rows[0].next_tool == "windows_function_start_explain"


def test_windows_candidate_start_worklist_surfaces_netwtw_padding_rejects(
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
            file="windows-update-intel-wifi-NETwtw10.sys",
            diagnostic_kind="extra",
            max_rows=5,
            add_to_kb=True,
        ),
    )

    assert result.rows[0].address == "0x1400041a6"
    assert result.rows[0].final_state == "glaurung_only"
    assert "padding_run" in result.rows[0].reason_codes
    assert result.rows[0].recommended_action == "demote_to_rejected_start"
    assert result.evidence_node_id is not None


def test_windows_candidate_start_worklist_carries_scan_rejection_reasons(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    comparison, diagnostics = _write_scan_rejection_worklist_artifacts(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            comparison_path=str(comparison),
            diagnostics_path=str(diagnostics),
            file="synthetic.dll",
            diagnostic_kind="extra",
            max_rows=1,
        ),
    )

    assert result.returned_candidates == 1
    row = result.rows[0]
    assert row.address == "0x180001234"
    assert "scan_rejection:body_overlap:tiny_stub" in row.reason_codes
    assert row.scan_rejection_reasons == ["body_overlap:tiny_stub"]


def test_memory_agent_registers_windows_candidate_start_worklist() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_candidate_start_worklist" in agent._function_toolset.tools
