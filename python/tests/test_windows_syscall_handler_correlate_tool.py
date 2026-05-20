from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_syscall_handler_correlate import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "ntdll.dll"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "ntoskrnl.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.execute(
            """
            CREATE TABLE function_names (
                binary_id INTEGER,
                entry_va INTEGER,
                canonical TEXT,
                demangled TEXT,
                flavor TEXT,
                set_by TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?)",
            (
                1,
                0x140123450,
                "NtQuerySystemInformation",
                None,
                "public",
                "pdb",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_syscall_handler_correlate_uses_project_function_names(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = _project(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            kernel_project_path=str(project),
            pseudocode="""
fn NtQuerySystemInformation {
    ret = 0x36;
    unknown(syscall);
}
fn NtMissingPair {
    ret = 0x777;
    unknown(syscall);
}
""",
            add_to_kb=True,
        ),
    )

    by_symbol = {row.user_stub_symbol: row for row in result.rows}
    assert result.syscall_count == 2
    assert result.correlated_count == 1
    assert result.project_correlated_count == 1
    assert result.external_correlated_count == 0
    assert result.missing_handler_count == 1
    assert by_symbol["NtQuerySystemInformation"].handler_name == (
        "NtQuerySystemInformation"
    )
    assert by_symbol["NtQuerySystemInformation"].handler_va == 0x140123450
    assert by_symbol["NtQuerySystemInformation"].handler_source == (
        "kernel_project_function_names"
    )
    assert by_symbol["NtMissingPair"].handler_source == "missing"
    assert "kernel_project_function_names" in result.coverage
    assert "syscall_handler_correlation" in result.coverage
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_syscall_handler_correlate"
        for node in ctx.kb.nodes()
    )


def test_windows_syscall_handler_correlate_uses_external_map_by_number(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn NtQuerySystemInformation {
    ret = 0x36;
    unknown(syscall);
}
""",
            handler_map_json=json.dumps(
                {
                    "0x36": {
                        "handler_name": "NtQuerySystemInformation",
                        "handler_va": "0x140123450",
                        "handler_module": "ntoskrnl.exe",
                    }
                }
            ),
        ),
    )

    assert result.correlated_count == 1
    row = result.rows[0]
    assert row.handler_source == "external_handler_map"
    assert row.handler_name == "NtQuerySystemInformation"
    assert row.handler_va == 0x140123450
    assert row.handler_module == "ntoskrnl.exe"
    assert "external_handler_map" in result.coverage


def test_windows_syscall_handler_correlate_reports_missing_without_map(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pseudocode="""
fn NtNoMap {
    ret = 1;
    unknown(syscall);
}
""",
        ),
    )

    assert result.correlated_count == 0
    assert result.missing_handler_count == 1
    assert result.rows[0].handler_source == "missing"
    assert "kernel_handler_map" in result.missing_capabilities
    assert "syscall_handler_correlation" in result.missing_capabilities


def test_memory_agent_registers_windows_syscall_handler_correlate() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_syscall_handler_correlate" in agent._function_toolset.tools
