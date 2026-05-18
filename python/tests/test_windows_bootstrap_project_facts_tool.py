from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_bootstrap_project_facts import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_bootstrap_project_facts_composes_project_steps(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from glaurung.llm.kb import type_db, xref_db

    def fake_index_callgraph(*_args, **_kwargs) -> int:
        return 7

    def fake_index_data_xrefs(*_args, **_kwargs) -> int:
        return 11

    def fake_import_pe_pdb_types(*_args, **_kwargs) -> dict:
        return {
            "cache_hit": True,
            "imported_struct": 1,
            "imported_union": 1,
            "imported_function_proto": 3,
            "imported_function_name": 5,
            "public_symbols": 6,
            "skipped_manual_function_name": 0,
            "missing_layouts": ["_MISSING"],
        }

    monkeypatch.setattr(xref_db, "index_callgraph", fake_index_callgraph)
    monkeypatch.setattr(xref_db, "index_data_xrefs", fake_index_data_xrefs)
    monkeypatch.setattr(type_db, "import_pe_pdb_types", fake_import_pe_pdb_types)

    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    cache = tmp_path / "symbols"
    cache.mkdir()
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            project_path=str(tmp_path / "driver.glaurung"),
            pdb_cache_dir=str(cache),
            struct_names=["_KNOWN", "_MISSING"],
            add_to_kb=True,
        ),
    )

    assert [(step.name, step.ok, step.count) for step in result.steps] == [
        ("index_callgraph", True, 7),
        ("index_data_xrefs", True, 11),
        ("import_pdb_facts", True, 10),
    ]
    assert result.pdb_counts is not None
    assert result.pdb_counts.imported_function_name == 5
    assert result.pdb_counts.missing_layouts == ["_MISSING"]
    assert "call_xrefs" in result.fact_coverage
    assert "data_xrefs" in result.fact_coverage
    assert "pdb_type_layouts" in result.fact_coverage
    assert "pdb_function_prototypes" in result.fact_coverage
    assert "requested_type_layouts" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_bootstrap_project_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_bootstrap_project_facts_can_skip_steps(tmp_path: Path) -> None:
    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            project_path=str(tmp_path / "driver.glaurung"),
            index_callgraph=False,
            index_data_xrefs=False,
            import_pdb_facts=False,
        ),
    )

    assert [(step.name, step.ran, step.ok) for step in result.steps] == [
        ("index_callgraph", False, True),
        ("index_data_xrefs", False, True),
        ("import_pdb_facts", False, True),
    ]
    assert result.fact_coverage == []
    assert result.missing_capabilities == []


def test_windows_bootstrap_project_facts_zero_count_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from glaurung.llm.kb import xref_db

    def fake_index_callgraph(*_args, **_kwargs) -> int:
        return 0

    def fake_index_data_xrefs(*_args, **_kwargs) -> int:
        return 3

    monkeypatch.setattr(xref_db, "index_callgraph", fake_index_callgraph)
    monkeypatch.setattr(xref_db, "index_data_xrefs", fake_index_data_xrefs)

    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            project_path=str(tmp_path / "driver.glaurung"),
            import_pdb_facts=False,
        ),
    )

    assert [(step.name, step.ok, step.count) for step in result.steps] == [
        ("index_callgraph", True, 0),
        ("index_data_xrefs", True, 3),
        ("import_pdb_facts", True, 0),
        ("index_pe_direct_calls", True, 0),
    ]
    assert "call_xrefs" not in result.fact_coverage
    assert "data_xrefs" in result.fact_coverage
    assert "call_xrefs" in result.missing_capabilities
    assert "data_xrefs" not in result.missing_capabilities


def test_memory_agent_registers_windows_bootstrap_project_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_bootstrap_project_facts" in agent._function_toolset.tools
