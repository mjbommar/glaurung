from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_surface_metadata import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_metadata(tmp_path: Path) -> tuple[Path, Path]:
    sources = tmp_path / "pe-sources.yaml"
    gates = tmp_path / "pe-gates.yaml"
    sources.write_text(
        """
- id: nt_query_system_information
  surface: syscall
  symbols: [NtQuerySystemInformation, ZwQuerySystemInformation]
  attacker_class: windows-local-user
  roles:
    - index: 0
      role: selector
    - index: 1
      role: inout_buffer
      paired_length: 2
      selector: 0
    - index: 2
      role: length
""",
        encoding="utf-8",
    )
    gates.write_text(
        """
- id: probeforwrite
  symbols: [ProbeForWrite]
  gate_kind: user_pointer
  proves: [user_pointer_write_range_valid]
  required_conditions: [call_dominates_write_sink]
  invalid_when: [length_is_zero]
""",
        encoding="utf-8",
    )
    return sources, gates


def test_windows_surface_metadata_filters_sources(tmp_path: Path) -> None:
    sources, gates = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sources_path=str(sources),
            gates_path=str(gates),
            symbol="NtQuerySystemInformation",
        ),
    )

    assert result.source_count_total == 1
    assert result.gate_count_total == 1
    assert [source.id for source in result.sources] == [
        "nt_query_system_information"
    ]
    assert result.sources[0].roles[1].role == "inout_buffer"
    assert result.sources[0].roles[1].paired_length == 2
    assert result.gates == []


def test_windows_surface_metadata_filters_gates_and_adds_evidence(
    tmp_path: Path,
) -> None:
    sources, gates = _write_metadata(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            sources_path=str(sources),
            gates_path=str(gates),
            symbol="ProbeForWrite",
            add_to_kb=True,
        ),
    )

    assert result.sources == []
    assert [gate.id for gate in result.gates] == ["probeforwrite"]
    assert "length_is_zero" in result.gates[0].invalid_when
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_surface_metadata"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_surface_metadata() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_surface_metadata" in agent._function_toolset.tools
