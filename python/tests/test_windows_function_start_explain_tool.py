from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_function_start_explain import build_tool


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


def _write_scan_rejection_artifacts(tmp_path: Path) -> tuple[Path, Path]:
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
                    "address_gap": {},
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
                    "extra": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    return comparison, diagnostics


def test_windows_function_start_explain_reports_simd_ghidra_only_start(
    tmp_path: Path,
) -> None:
    assert COMPARISON.exists()
    assert DIAGNOSTICS.exists()
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

    assert result.file == "windows-update-intel-npu-ze_loader.dll"
    assert result.address == "0x180033b20"
    assert result.final_state == "ghidra_only"
    assert result.in_ghidra is True
    assert result.in_glaurung_function is False
    assert "simd_head" in result.reason_codes
    assert "pdata_body_overlap" in result.reason_codes
    assert result.bytes is not None
    assert result.bytes.hex.startswith("0f1002")
    assert result.ghidra is not None
    assert result.ghidra.body_size == 29
    assert result.diagnostic_kind == "missing"


def test_windows_function_start_explain_marks_padding_false_positive(
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
            address="0x1400041a6",
        ),
    )

    assert result.final_state == "glaurung_only"
    assert result.in_glaurung_function is True
    assert result.in_ghidra is False
    assert result.seed_kinds == ["data_ref"]
    assert "padding_run" in result.reason_codes
    assert "data_ref_seed" in result.reason_codes
    assert result.recommended_action == "demote_to_rejected_start"
    assert result.bytes is not None
    assert result.bytes.hex.startswith("cccccccc")


def test_windows_function_start_explain_uses_post_fix_state_for_recovered_thunk(
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
            file="win10-dismcore.dll",
            address="0x18001f590",
        ),
    )

    assert result.final_state == "strict_function"
    assert result.in_glaurung_function is True
    assert result.in_ghidra is True
    assert result.ghidra is not None
    assert result.ghidra.thunk is True
    assert "rex_import_jump_thunk" in result.reason_codes
    assert result.diagnostic_kind == "missing"
    assert any(
        "post-fix comparison marks it recovered" in note for note in result.notes
    )


def test_windows_function_start_explain_surfaces_scan_rejection_records(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    comparison, diagnostics = _write_scan_rejection_artifacts(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            comparison_path=str(comparison),
            diagnostics_path=str(diagnostics),
            file="synthetic.dll",
            address="0x180001234",
        ),
    )

    assert result.final_state == "candidate"
    assert result.recommended_action == "keep_rejected_start_record"
    assert "scan_rejection:body_overlap:tiny_stub" in result.reason_codes
    assert result.scan_rejections[0].address == "0x180001234"
    assert result.scan_rejections[0].source == "0x180004000"
    assert result.scan_rejections[0].detail == "candidate lies inside owner body"


def test_memory_agent_registers_windows_function_start_explain() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_function_start_explain" in agent._function_toolset.tools
