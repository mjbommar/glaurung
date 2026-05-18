from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_ghidra_delta_manifest import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_delta_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-ghidra-delta.yaml"
    manifest.write_text(
        """
- id: cldflt_cfg_path
  target_id: cldflt
  component: cldflt.sys
  build_label: win11-ltsc-v4
  fact_class: cfg_path
  coverage_state: present
  blocking: false
  ghidra_baseline: Ghidra can answer basic-block reachability and dominance.
  glaurung_status: Persisted CFG and dominance tables cover the canonical project.
  current_capabilities: [cfg_blocks, cfg_edges, cfg_dominance]
  missing_capabilities: [exception_edges]
  next_actions: [model exceptional cleanup edges]
  evidence: [pe-project-facts.yaml]
- id: cldflt_type_layout
  target_id: cldflt
  component: cldflt.sys
  build_label: win11-ltsc-v4
  fact_class: type_layout
  coverage_state: missing
  blocking: true
  ghidra_baseline: Ghidra can apply PDB structs and field offsets.
  glaurung_status: Public names are imported but type layouts are absent.
  current_capabilities: [pdb_identity, public_symbols]
  missing_capabilities: [struct_fields, field_offsets]
  next_actions: [import priority PDB type layouts]
  evidence: [pe-identity-manifest.yaml]
""",
        encoding="utf-8",
    )
    return manifest


def test_windows_ghidra_delta_manifest_filters_blocking_type_gaps(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            ghidra_delta_path=str(_write_delta_manifest(tmp_path)),
            component="cldflt.sys",
            coverage_state="missing",
            blocking_only=True,
            add_to_kb=True,
        ),
    )

    assert result.record_count_total == 2
    assert result.blocking_gap_count_total == 1
    assert [record.id for record in result.records] == ["cldflt_type_layout"]
    record = result.records[0]
    assert record.fact_class == "type_layout"
    assert "struct_fields" in record.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_ghidra_delta_manifest"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_ghidra_delta_manifest() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_ghidra_delta_manifest" in agent._function_toolset.tools
