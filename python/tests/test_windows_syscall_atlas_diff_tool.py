from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_syscall_atlas_diff import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "ntdll.dll"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_syscall_atlas_diff_reports_service_number_drift(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode_a="""
fn NtOldOnly {
    ret = 0x10;
    unknown(syscall);
}
fn NtStable {
    ret = 0x20;
    unknown(syscall);
}
fn NtRenumbered {
    ret = 0x30;
    unknown(syscall);
}
""",
            pseudocode_b="""
fn NtStable {
    ret = 0x20;
    unknown(syscall);
}
fn NtRenumbered {
    ret = 0x31;
    unknown(syscall);
}
fn NtNewOnly {
    ret = 0x40;
    unknown(syscall);
}
""",
            include_same=True,
            add_to_kb=True,
        ),
    )

    by_symbol = {row.symbol: row for row in result.rows}
    assert result.syscall_count_a == 3
    assert result.syscall_count_b == 3
    assert result.same == 1
    assert result.changed == 1
    assert result.added == 1
    assert result.removed == 1
    assert result.renumbered == 1
    assert by_symbol["NtStable"].status == "same"
    assert by_symbol["NtRenumbered"].status == "changed"
    assert by_symbol["NtRenumbered"].changes == ["syscall_number"]
    assert by_symbol["NtNewOnly"].status == "added"
    assert by_symbol["NtOldOnly"].status == "removed"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_syscall_atlas_diff"
        for node in ctx.kb.nodes()
    )


def test_windows_syscall_atlas_diff_reports_raw_byte_pattern_drift(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            raw_bytes_hex_a="4c 8b d1 b8 36 00 00 00 0f 05 c3",
            raw_bytes_hex_b=(
                "4c 8b d1 b8 36 00 00 00 f6 04 25 08 03 fe 7f 01 75 03 0f 05 c3"
            ),
        ),
    )

    assert result.changed == 1
    assert result.byte_pattern_changed == 1
    assert result.stub_shape_changed == 1
    assert result.rows[0].symbol == "sub_0"
    assert result.rows[0].changes == ["byte_pattern", "stub_shape"]
    assert "raw_syscall_stub_bytes" in result.coverage


def test_windows_syscall_atlas_diff_can_ignore_raw_byte_pattern_drift(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            raw_bytes_hex_a="4c 8b d1 b8 36 00 00 00 0f 05 c3",
            raw_bytes_hex_b=(
                "4c 8b d1 b8 36 00 00 00 f6 04 25 08 03 fe 7f 01 75 03 0f 05 c3"
            ),
            compare_byte_patterns=False,
            compare_stub_shapes=False,
            include_same=True,
        ),
    )

    assert result.same == 1
    assert result.changed == 0
    assert result.rows[0].status == "same"


def test_windows_syscall_atlas_diff_reports_dispatch_shape_drift(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            raw_bytes_hex_a="4c 8b d1 b8 36 00 00 00 0f 05 c3",
            raw_bytes_hex_b=(
                "4c 8b d1 b8 36 00 00 00 "
                "f6 04 25 08 03 fe 7f 01 75 03 0f 05 c3 cd 2e c3"
            ),
            compare_byte_patterns=False,
        ),
    )

    assert result.changed == 1
    assert result.dispatch_changed == 1
    assert result.stub_shape_changed == 1
    assert result.rows[0].changes == ["dispatch_kind", "stub_shape"]


def test_windows_syscall_atlas_diff_can_filter_and_omit_rows(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode_a="""
fn NtA {
    ret = 1;
    unknown(syscall);
}
fn NtB {
    ret = 2;
    unknown(syscall);
}
""",
            pseudocode_b="""
fn NtA {
    ret = 3;
    unknown(syscall);
}
fn NtB {
    ret = 2;
    unknown(syscall);
}
""",
            status="changed",
            max_rows=0,
        ),
    )

    assert result.filtered_row_count == 1
    assert result.rows == []
    assert result.changed == 1
    assert result.same == 1


def test_memory_agent_registers_windows_syscall_atlas_diff() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_syscall_atlas_diff" in agent._function_toolset.tools
