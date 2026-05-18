from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_pdb_identity_manifest import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_identity_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-identity-manifest.yaml"
    manifest.write_text(
        """
- id: win11_ltsc_ntoskrnl_ntkrnlmp
  target_id: ntoskrnl
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: ntoskrnl.exe
  expected_pdb_name: ntkrnlmp.pdb
  codeview_guid_age: CF32DE2E4A334C7C06FB63FCB6FAFB5C1
  cache_status: cached
  symbol_cache_path: /nas4/data/symbol-cache/microsoft/ntkrnlmp.pdb/CF32DE2E4A334C7C06FB63FCB6FAFB5C1/ntkrnlmp.pdb
  identity_sources: [symbol_cache_snapshot_2026_05_18]
  fact_coverage: [pdb_public_symbols, pdb_type_layouts, pdb_function_prototypes]
  missing_facts: [per_binary_identity_record_from_live_extractor]
- id: win11_ltsc_cldflt_missing_pdb
  target_id: cldflt
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: cldflt.sys
  expected_pdb_name: cldflt.pdb
  codeview_guid_age: null
  cache_status: missing_from_cache
  symbol_cache_path: null
  identity_sources: [symbol_cache_snapshot_2026_05_18]
  fact_coverage: []
  missing_facts: [codeview_guid_age, cached_pdb, pdb_type_layouts]
""",
        encoding="utf-8",
    )
    return manifest


def test_windows_pdb_identity_manifest_filters_cached_type_coverage(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            identity_path=str(_write_identity_manifest(tmp_path)),
            cache_status="cached",
            requires_fact="pdb_type_layouts",
        ),
    )

    assert result.record_count_total == 2
    assert result.cached_count_total == 1
    assert result.missing_count_total == 1
    assert [record.target_id for record in result.records] == ["ntoskrnl"]
    assert result.records[0].expected_pdb_name == "ntkrnlmp.pdb"
    assert result.records[0].codeview_guid_age == "CF32DE2E4A334C7C06FB63FCB6FAFB5C1"
    assert "symbol/type backing" in result.notes[0]


def test_windows_pdb_identity_manifest_filters_missing_pdb_and_adds_evidence(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            identity_path=str(_write_identity_manifest(tmp_path)),
            target_id="cldflt",
            missing_fact="cached_pdb",
            add_to_kb=True,
        ),
    )

    assert [record.cache_status for record in result.records] == ["missing_from_cache"]
    assert result.records[0].expected_pdb_name == "cldflt.pdb"
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_pdb_identity_manifest"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_pdb_identity_manifest() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_pdb_identity_manifest" in agent._function_toolset.tools
