from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_scan_rejection_dashboard import build_tool


SURFACE_PEN = Path(
    "samples/binaries/platforms/windows/vendor/realworld/"
    "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"
)
VWIFIFLT = Path("samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys")


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    return MemoryContext(file_path=str(path), artifact=artifact)


def test_windows_scan_rejection_dashboard_correlates_rejected_addresses(
    tmp_path: Path,
) -> None:
    diagnostics = tmp_path / "diagnostics.json"
    diagnostics.write_text(
        json.dumps(
            [
                {
                    "path": "driver.sys",
                    "missing_count": 1,
                    "extra_count": 2,
                    "missing": [{"va": 0x1000, "address": "0x1000"}],
                    "extra": [{"va": 0x9000, "address": "0x9000"}],
                    "stats": {
                        "scan_rejection_counts": {
                            "body_overlap:tiny_stub": 2,
                            "data_ref:weak_pointer": 1,
                        },
                        "scan_rejections": [
                            {
                                "va": 0x1000,
                                "source_va": 0x900,
                                "reason": "body_overlap:tiny_stub",
                                "detail": "owner=0x900",
                            },
                            {
                                "va": 0x2000,
                                "source_va": None,
                                "reason": "body_overlap:tiny_stub",
                                "detail": "owner=0x800",
                            },
                            {
                                "va": 0x3000,
                                "source_va": 0x700,
                                "reason": "data_ref:weak_pointer",
                                "detail": "table=.rdata",
                            },
                        ],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    tool = build_tool()
    ctx = _ctx(tmp_path)
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(diagnostics_path=str(diagnostics), max_rows=4),
    )

    assert result.claim_level == "scan_rejection_dashboard_not_finding"
    assert result.total_rejection_count == 3
    overlap = next(row for row in result.rows if row.reason == "body_overlap:tiny_stub")
    assert overlap.count == 2
    assert overlap.ghidra_missing_address_hits == 1
    assert overlap.precision_guard_count == 1
    assert overlap.estimated_precision_guard_ratio == 0.5
    assert overlap.recall_risk_level == "high"
    assert overlap.samples[0].address == "0x1000"
    assert overlap.samples[0].ghidra_missing_match is True
    assert "address_rejection_overlaps_ghidra_missing" in overlap.reason_codes
    assert result.evidence_bundle.coverage.ghidra_missing_entries == 1


def test_windows_scan_rejection_dashboard_native_replay_real_pe(
    tmp_path: Path,
) -> None:
    tool = build_tool()
    ctx = _ctx(tmp_path)
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            diagnostics_path="docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json",
            file="SurfacePenBleLcAddrAdaptationDriver.sys",
            include_native_scan=True,
            max_native_files=1,
            max_rows=16,
        ),
    )

    assert result.native_file_count == 1
    assert result.total_rejection_count > 0
    reasons = {row.reason for row in result.rows}
    assert "body_overlap:tiny_stub" in reasons
    body_overlap = next(row for row in result.rows if row.reason == "body_overlap:tiny_stub")
    assert body_overlap.native_count > 0
    assert body_overlap.samples
    assert all(sample.path == str(SURFACE_PEN) for sample in body_overlap.samples)


def test_windows_scan_rejection_dashboard_native_replay_pdata_rejections(
    tmp_path: Path,
) -> None:
    tool = build_tool()
    ctx = _ctx(tmp_path)
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            diagnostics_path="docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json",
            file="win10-vwififlt.sys",
            include_native_scan=True,
            max_native_files=1,
            max_rows=16,
        ),
    )

    chained = next(row for row in result.rows if row.reason == "pdata:chained_unwind")
    assert chained.native_count == 4
    assert chained.samples
    assert chained.samples[0].path == str(VWIFIFLT)
    assert chained.samples[0].detail == (
        "PE exception directory entry is a chained unwind record"
    )
    assert "native_scan_replay" in chained.reason_codes


def test_memory_agent_registers_windows_scan_rejection_dashboard() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_scan_rejection_dashboard" in agent._function_toolset.tools
