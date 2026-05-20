from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_decompile_context_packet import build_tool


WIN64_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/"
    "hello-c-x86_64-mingw.exe"
)
FUNCTION_VA = 0x140001190


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


@pytest.mark.skipif(  # ty: ignore[unresolved-attribute]
    not WIN64_SAMPLE.exists(),
    reason="win64 PE sample missing",
)
def test_windows_decompile_context_packet_collects_bounded_function_context(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(WIN64_SAMPLE),
            function_va=FUNCTION_VA,
            max_instructions=32,
            timeout_ms=3000,
            add_to_kb=True,
        ),
    )

    packet = result.packet
    assert packet.function_va == FUNCTION_VA
    assert packet.address == "0x140001190"
    assert packet.cfg.recovered_from_analysis is True
    assert packet.cfg.basic_block_count > 0
    assert 0 < len(packet.instructions) <= 32
    assert packet.decompile_text is not None
    assert "function" in packet.decompile_text
    assert "cfg_summary" in packet.coverage
    assert "disassembly" in packet.coverage
    assert result.evidence_bundle.subject.va_hex == "0x140001190"
    assert "windows_decompile_context_packet" in result.evidence_bundle.source_tools
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_decompile_context_packet"
        for node in ctx.kb.nodes()
    )


@pytest.mark.skipif(  # ty: ignore[unresolved-attribute]
    not WIN64_SAMPLE.exists(),
    reason="win64 PE sample missing",
)
def test_windows_decompile_context_packet_joins_project_notebook_facts(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project = tmp_path / "sample.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=WIN64_SAMPLE)
    xref_db.set_function_name(kb, FUNCTION_VA, "ReviewedStartup", set_by="manual")
    xref_db.set_comment(kb, FUNCTION_VA, "manual startup review note", set_by="manual")
    xref_db.set_data_label(kb, 0x140010000, "g_NearbyTable", set_by="manual")
    kb.close()

    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(WIN64_SAMPLE),
            function_va=FUNCTION_VA,
            project_path=str(project),
            max_instructions=24,
            timeout_ms=3000,
        ),
    )

    facts = result.packet.project_facts
    assert facts is not None
    assert facts.function_name == "ReviewedStartup"
    assert facts.entry_comment == "manual startup review note"
    assert "function_names" in facts.coverage
    assert "comments" in facts.coverage
    assert "data_labels" in facts.coverage
    assert "project_facts" not in result.packet.missing_capabilities


def test_memory_agent_registers_windows_decompile_context_packet() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_decompile_context_packet" in agent._function_toolset.tools
