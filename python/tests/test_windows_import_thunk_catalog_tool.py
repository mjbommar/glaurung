from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.windows_import_thunk_catalog import build_tool


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


def test_windows_import_thunk_catalog_marks_recovered_rex_jmp_thunks(
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
            shape="rex_import_jump",
            max_rows=8,
        ),
    )

    assert result.total_ghidra_thunks == 37
    assert result.rows
    row = result.rows[0]
    assert row.address == "0x18001f590"
    assert row.shape == "rex_import_jump"
    assert row.current_state == "strict_function"
    assert row.historical_diagnostic_kind == "missing"
    assert row.in_glaurung is True
    assert row.in_ghidra is True
    assert row.recommended_action == "keep_thunk_function"


def test_windows_import_thunk_catalog_keeps_webservices_jmp_gap_visible(
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
            file="win11-webservices.dll",
            shape="jmp_rel32",
            max_rows=4,
            add_to_kb=True,
        ),
    )

    assert result.total_missing_thunks == 14
    assert result.rows[0].address == "0x180009440"
    assert result.rows[0].shape == "jmp_rel32"
    assert result.rows[0].current_state == "ghidra_only"
    assert result.rows[0].recommended_action == "promote_or_classify_thunk"
    assert result.evidence_node_id is not None


def test_memory_agent_registers_windows_import_thunk_catalog() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_import_thunk_catalog" in agent._function_toolset.tools
