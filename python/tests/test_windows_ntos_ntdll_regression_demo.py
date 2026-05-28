from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb import pe_direct_calls, windows_boundaries
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_api_contract_primitives import (
    build_tool as build_contract_primitives,
)
from glaurung.llm.tools.windows_api_contract_rule_scan import (
    build_tool as build_contract_rule_scan,
)
from glaurung.llm.tools.windows_bootstrap_project_facts import build_tool
from glaurung.llm.tools.windows_project_call_argument_snapshot import (
    build_tool as build_call_argument_snapshot,
)


FIXTURE_DIR = Path("tests/fixtures/msvc-pdb")
NTOSKRNL = FIXTURE_DIR / "ntoskrnl.exe"
NTDLL = FIXTURE_DIR / "ntdll.dll"


def _ctx(binary: Path) -> MemoryContext:
    artifact = g.triage.analyze_path(str(binary))
    ctx = MemoryContext(file_path=str(binary), artifact=artifact)
    import_triage(ctx.kb, artifact, str(binary))
    return ctx


@pytest.mark.skipif(
    not (NTOSKRNL.exists() and NTDLL.exists()),
    reason="Windows PDB regression fixtures missing",
)
def test_ntoskrnl_contract_demo_reaches_exp_get_process_information(
    tmp_path: Path,
) -> None:
    project = tmp_path / "ntoskrnl.glaurung"
    ctx = _ctx(NTOSKRNL)
    bootstrap = build_tool()

    result = bootstrap.run(
        ctx,
        ctx.kb,
        bootstrap.input_model(
            pe_path=str(NTOSKRNL),
            project_path=str(project),
            pdb_cache_dir=str(FIXTURE_DIR),
            index_callgraph=False,
            index_data_xrefs=False,
            index_cfg=False,
            index_cfg_dominance=False,
            index_branch_conditions=False,
        ),
    )

    assert "pdb_function_names" in result.fact_coverage
    assert "function_boundaries" in result.fact_coverage
    assert "call_xrefs" in result.fact_coverage

    kb = PersistentKnowledgeBase.open(project, binary_path=NTOSKRNL)
    try:
        target = _function_va(project, "ExpGetProcessInformation")
        boundary = windows_boundaries.best_boundary_for_va(kb, target)
        assert boundary is not None
        assert boundary.source == "pdb"
        assert boundary.end_va is not None

        pe_direct_calls.index_pe_direct_calls(
            kb,
            NTOSKRNL,
            target_entries=[target],
        )
        xrefs = kb._conn.execute(
            "SELECT src_va, src_function_va FROM xrefs "
            "WHERE binary_id = ? AND kind = 'call' AND dst_va = ? "
            "ORDER BY src_va",
            (kb.binary_id, target),
        ).fetchall()
        assert [(hex(row[0]), hex(row[1])) for row in xrefs] == [
            ("0x1407b5985", "0x1407b4c20"),
            ("0x1408fee1b", "0x14089faba"),
        ]
    finally:
        kb.close()

    snapshot_tool = build_call_argument_snapshot()
    snapshot = snapshot_tool.run(
        ctx,
        ctx.kb,
        snapshot_tool.input_model(
            binary_path=str(NTOSKRNL),
            project_path=str(project),
            callsite_va=0x1407B5985,
            max_window_bytes=8192,
            max_instructions=2000,
        ),
    )
    assert snapshot.caller_name == "ExpQuerySystemInformation"
    assert snapshot.callee_name == "ExpGetProcessInformation"
    assert [(arg.register_name, arg.expression) for arg in snapshot.arguments] == [
        ("rcx", "rbx"),
        ("rdx", "r13d"),
        ("r8", "rsp:[rsp + 0x44]"),
        ("r9", "0"),
    ]

    text = g.ir.decompile_range_at(
        str(NTOSKRNL),
        target,
        target,
        boundary.end_va,
        max_blocks=1024,
        max_instructions=50_000,
        timeout_ms=5_000,
        style="c",
        pdb_cache=str(FIXTURE_DIR),
    )
    assert "fn sub_140685720" in text
    assert "RtlCopyMemory" in text

    primitive_tool = build_contract_primitives()
    primitives = primitive_tool.run(
        ctx,
        ctx.kb,
        primitive_tool.input_model(pseudocode=text),
    )
    assert primitives.primitive_counts["user_buffer_copy"] >= 1


@pytest.mark.skipif(
    not (NTOSKRNL.exists() and NTDLL.exists()),
    reason="Windows PDB regression fixtures missing",
)
def test_ntoskrnl_contract_demo_flags_build_version_helper_path(
    tmp_path: Path,
) -> None:
    project = tmp_path / "ntoskrnl.glaurung"
    ctx = _ctx(NTOSKRNL)
    bootstrap = build_tool()

    bootstrap.run(
        ctx,
        ctx.kb,
        bootstrap.input_model(
            pe_path=str(NTOSKRNL),
            project_path=str(project),
            pdb_cache_dir=str(FIXTURE_DIR),
            index_callgraph=False,
            index_data_xrefs=False,
            index_cfg=False,
            index_cfg_dominance=False,
            index_branch_conditions=False,
            index_callsite_path_conditions=False,
        ),
    )

    kb = PersistentKnowledgeBase.open(project, binary_path=NTOSKRNL)
    try:
        target = _function_va(project, "CmQueryBuildVersionInformation")
        boundary = windows_boundaries.best_boundary_for_va(kb, target)
        assert boundary is not None
        assert boundary.source == "pdb"
        assert boundary.end_va is not None

        pe_direct_calls.index_pe_direct_calls(
            kb,
            NTOSKRNL,
            target_entries=[target],
        )
        xrefs = kb._conn.execute(
            "SELECT src_va, src_function_va FROM xrefs "
            "WHERE binary_id = ? AND kind = 'call' AND dst_va = ? "
            "ORDER BY src_va",
            (kb.binary_id, target),
        ).fetchall()
        assert [(hex(row[0]), hex(row[1])) for row in xrefs] == [
            ("0x1407b5ce3", "0x1407b4c20"),
        ]
    finally:
        kb.close()

    text = g.ir.decompile_range_at(
        str(NTOSKRNL),
        target,
        target,
        boundary.end_va,
        max_blocks=1024,
        max_instructions=50_000,
        timeout_ms=5_000,
        style="c",
        pdb_cache=str(FIXTURE_DIR),
    )
    primitive_tool = build_contract_primitives()
    primitives = primitive_tool.run(
        ctx,
        ctx.kb,
        primitive_tool.input_model(pseudocode=text),
    )
    assert primitives.primitive_counts["selector_dispatch"] >= 2
    assert primitives.primitive_counts["pointer_write"] >= 1
    assert primitives.primitive_counts["string_conversion_copy"] >= 1

    rule_tool = build_contract_rule_scan()
    rules = rule_tool.run(ctx, ctx.kb, rule_tool.input_model(pseudocode=text))
    assert any(
        finding.rule_id == "selector_global_table_to_string_copy"
        for finding in rules.findings
    )


@pytest.mark.skipif(not NTDLL.exists(), reason="ntdll fixture missing")
def test_ntdll_syscall_stub_demo_uses_pdb_boundaries(tmp_path: Path) -> None:
    project = tmp_path / "ntdll.glaurung"
    ctx = _ctx(NTDLL)
    bootstrap = build_tool()

    result = bootstrap.run(
        ctx,
        ctx.kb,
        bootstrap.input_model(
            pe_path=str(NTDLL),
            project_path=str(project),
            pdb_cache_dir=str(FIXTURE_DIR),
            index_callgraph=False,
            index_data_xrefs=False,
            index_cfg=False,
            index_cfg_dominance=False,
            index_branch_conditions=False,
        ),
    )

    assert "pdb_function_names" in result.fact_coverage
    kb = PersistentKnowledgeBase.open(project, binary_path=NTDLL)
    try:
        for name, syscall_id in (
            ("NtQuerySystemInformation", 54),
            ("NtQuerySystemInformationEx", 364),
        ):
            entry = _function_va(project, name)
            boundary = windows_boundaries.best_boundary_for_va(kb, entry)
            assert boundary is not None
            assert boundary.end_va is not None
            text = g.ir.decompile_range_at(
                str(NTDLL),
                entry,
                entry,
                boundary.end_va,
                max_blocks=64,
                max_instructions=500,
                timeout_ms=1000,
                style="c",
                pdb_cache=str(FIXTURE_DIR),
            )
            assert f"ret = {syscall_id};" in text
            assert "unknown(syscall);" in text
    finally:
        kb.close()


def _function_va(project: Path, name: str) -> int:
    conn = sqlite3.connect(project)
    try:
        row = conn.execute(
            "SELECT entry_va FROM function_names WHERE canonical = ?",
            (name,),
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, name
    return int(row[0])
