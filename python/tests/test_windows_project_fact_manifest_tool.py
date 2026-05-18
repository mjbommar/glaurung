from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_fact_manifest import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_project_facts(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-project-facts.yaml"
    manifest.write_text(
        """
- id: cldflt_project
  target_id: cldflt
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: cldflt.sys
  project_path: /projects/cldflt.glaurung
  project_sha256: abc123
  project_size_bytes: 991232
  fact_sources: [unit_test]
  fact_coverage: [function_names, data_xrefs]
  missing_facts: [call_xrefs, persisted_cfg]
  counts:
    function_name_count: 974
    xref_count: 5223
    call_xref_count: 0
    data_read_xref_count: 5223
    data_write_xref_count: 0
    function_prototype_count: 0
    basic_block_count: 0
    cfg_edge_count: 0
    cfg_dominance_count: 0
    cfg_branch_fact_count: 0
- id: ntoskrnl_project
  target_id: ntoskrnl
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: ntoskrnl.exe
  project_path: /projects/ntoskrnl.glaurung
  project_sha256: def456
  project_size_bytes: 123456
  fact_sources: [unit_test]
  fact_coverage: [function_names, call_xrefs, persisted_cfg]
  missing_facts: []
  counts:
    function_name_count: 10
    xref_count: 20
    call_xref_count: 7
    data_read_xref_count: 5
    function_prototype_count: 3
    basic_block_count: 30
    cfg_edge_count: 40
    cfg_dominance_count: 30
    cfg_branch_fact_count: 12
""",
        encoding="utf-8",
    )
    return manifest


def test_windows_project_fact_manifest_filters_missing_call_xrefs(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_facts_path=str(_write_project_facts(tmp_path)),
            target_id="cldflt",
            missing_fact="call_xrefs",
            add_to_kb=True,
        ),
    )

    assert result.record_count_total == 2
    assert result.records_with_call_xrefs_total == 1
    assert result.records_with_cfg_total == 1
    assert [record.id for record in result.records] == ["cldflt_project"]
    cldflt = result.records[0]
    assert cldflt.project_path == "/projects/cldflt.glaurung"
    assert cldflt.counts.function_name_count == 974
    assert cldflt.counts.call_xref_count == 0
    assert "data_xrefs" in cldflt.fact_coverage
    assert "persisted_cfg" in cldflt.missing_facts
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_fact_manifest"
        for node in ctx.kb.nodes()
    )


def test_windows_project_fact_manifest_filters_available_capabilities(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_facts_path=str(_write_project_facts(tmp_path)),
            requires_fact="call_xrefs",
            min_call_xrefs=1,
        ),
    )

    assert [record.id for record in result.records] == ["ntoskrnl_project"]
    assert result.records[0].counts.cfg_edge_count == 40
    assert result.records[0].counts.cfg_dominance_count == 30
    assert result.records[0].counts.cfg_branch_fact_count == 12


def test_memory_agent_registers_windows_project_fact_manifest() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_fact_manifest" in agent._function_toolset.tools
