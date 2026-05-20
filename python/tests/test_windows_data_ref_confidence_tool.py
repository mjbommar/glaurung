from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_data_ref_confidence import build_tool


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


def test_windows_data_ref_confidence_accepts_surfacepen_callback_table(
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
            file="windows-update-SurfacePenBleLcAddrAdaptationDriver.sys",
            address="0x1400074b0",
        ),
    )

    assert result.address == "0x1400074b0"
    assert result.verdict == "accept_function_start"
    assert result.confidence == "high"
    assert result.data_ref_seeded is True
    assert result.final_state == "strict_function"
    assert result.refs[0].section == ".rdata"
    assert result.refs[0].slot_size == 4
    assert result.refs[0].table_length == 384
    assert "long_table" in result.reason_codes
    assert "read_only_table_section" in result.reason_codes
    assert "not_padding" in result.reason_codes


def test_windows_data_ref_confidence_rejects_netwtw_padding_run(
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
            add_to_kb=True,
        ),
    )

    assert result.address == "0x1400041a6"
    assert result.verdict == "reject_function_start"
    assert result.confidence == "high"
    assert result.data_ref_seeded is True
    assert result.final_state == "glaurung_only"
    assert result.refs[0].section == ".data"
    assert result.refs[0].table_length == 10
    assert "padding_run" in result.reason_codes
    assert "writable_table_section" in result.reason_codes
    assert result.evidence_node_id is not None


def test_memory_agent_registers_windows_data_ref_confidence() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_data_ref_confidence" in agent._function_toolset.tools
