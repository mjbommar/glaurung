from __future__ import annotations

from pathlib import Path

import pytest
import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb import type_db, xref_db
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_import_pdb_facts import build_tool


_FIXTURES = Path("tests/fixtures/msvc-pdb")


def _need_fixture(name: str) -> Path:
    path = _FIXTURES / name
    if not path.exists():
        pytest.skip(f"missing PDB fixture {path}")
    return path


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_import_pdb_facts_persists_public_names_and_types(
    tmp_path: Path,
) -> None:
    pe_path = _need_fixture("ntoskrnl.exe")
    _need_fixture("ntkrnlmp.pdb")
    ctx = _ctx(tmp_path)
    project_path = tmp_path / "ntoskrnl.glaurung"
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project_path),
            pe_path=str(pe_path),
            pdb_cache_dir=str(_FIXTURES),
            struct_names=["_EPROCESS", "_LARGE_INTEGER", "_KSPIN_LOCK"],
            max_prototypes=64,
            add_to_kb=True,
        ),
    )

    assert result.counts.cache_hit is True
    assert result.counts.imported_function_name > 1000
    assert result.counts.imported_function_proto == 64
    assert result.counts.imported_struct >= 1
    assert result.counts.imported_union >= 1
    assert result.counts.missing_layouts == ["_KSPIN_LOCK"]
    assert "pdb_function_names" in result.fact_coverage
    assert "pdb_type_layouts" in result.fact_coverage
    assert "pdb_function_prototypes" in result.fact_coverage
    assert "requested_type_layouts" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_import_pdb_facts"
        for node in ctx.kb.nodes()
    )

    kb = PersistentKnowledgeBase.open(project_path, binary_path=pe_path)
    try:
        assert type_db.get_type(kb, "_EPROCESS") is not None
        assert type_db.get_type(kb, "_LARGE_INTEGER") is not None
        release_spin_lock = xref_db.get_function_name(kb, 0x140323480)
        assert release_spin_lock is not None
        assert release_spin_lock.canonical == "KeReleaseSpinLock"
    finally:
        kb.close()


def test_windows_import_pdb_facts_can_import_public_names_only(
    tmp_path: Path,
) -> None:
    pe_path = _need_fixture("ntoskrnl.exe")
    _need_fixture("ntkrnlmp.pdb")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(tmp_path / "ntoskrnl-names.glaurung"),
            pe_path=str(pe_path),
            pdb_cache_dir=str(_FIXTURES),
            import_types=False,
        ),
    )

    assert result.counts.cache_hit is True
    assert result.counts.imported_function_name > 1000
    assert "pdb_function_names" in result.fact_coverage
    assert "pdb_type_layouts" in result.missing_capabilities
    assert "pdb_function_prototypes" in result.missing_capabilities


def test_memory_agent_registers_windows_import_pdb_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_import_pdb_facts" in agent._function_toolset.tools
