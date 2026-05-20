from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_function_body_split_candidates import build_tool


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


def test_windows_function_body_split_candidates_finds_webservices_overmerge(
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
            file="win10-webservices.dll",
            max_rows=24,
        ),
    )

    assert result.total_candidates == 24
    assert result.rows[0].current_state == "ghidra_only"
    assert result.rows[0].owner_entry.startswith("0x1800")
    assert result.rows[0].owner_total_size > 200_000
    assert "large_owner_function" in result.rows[0].reason_codes
    assert result.rows[0].recommended_action == "split_existing_function_body"
    assert result.rows[0].evidence_basis
    by_address = {row.address: row for row in result.rows}
    table_backed = by_address["0x180002730"]
    assert table_backed.code_pointer_ref_count == 1
    assert table_backed.split_confidence == "high"
    assert "code_pointer_ref" in table_backed.evidence_basis
    assert "owner_overlap" in table_backed.evidence_basis


def test_windows_function_body_split_candidates_keeps_pdata_overlap_context(
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
            file="windows-update-realtek-RtkAudUService64.exe",
            min_score=50,
            add_to_kb=True,
        ),
    )

    assert result.rows
    assert result.rows[0].pdata_body_overlap_starts == 2
    assert result.rows[0].split_confidence == "high"
    assert "pdata_body_overlap" in result.rows[0].evidence_basis
    assert "pdata_overlap" in result.rows[0].reason_codes
    assert result.evidence_node_id is not None


def test_memory_agent_registers_windows_function_body_split_candidates() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_function_body_split_candidates" in agent._function_toolset.tools
