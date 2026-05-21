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
CALLEE_VA = 0x140002100


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
    xref_db.set_function_name(kb, CALLEE_VA, "nt!ProbeForRead", set_by="pdb")
    xref_db.set_comment(kb, FUNCTION_VA, "manual startup review note", set_by="manual")
    xref_db.set_data_label(kb, 0x140010000, "g_NearbyTable", set_by="manual")
    xref_db.set_function_prototype(
        kb,
        "ReviewedStartup",
        "NTSTATUS",
        [
            xref_db.FunctionParam("Irp", "PIRP", role="irp"),
            xref_db.FunctionParam("OutputBufferLength", "ULONG", role="length"),
        ],
        calling_convention="NTAPI",
        confidence=0.91,
        set_by="manual",
        semantics={"risk_tags": ["ioctl", "user_buffer"]},
    )
    xref_db.set_function_prototype(
        kb,
        "ProbeForRead",
        "VOID",
        [
            xref_db.FunctionParam("Address", "PVOID", role="user_pointer"),
            xref_db.FunctionParam("Length", "SIZE_T", role="length"),
            xref_db.FunctionParam("Alignment", "ULONG", role="alignment"),
        ],
        calling_convention="NTAPI",
        confidence=0.88,
        set_by="pdb",
        semantics={"risk_tags": ["probe", "user_buffer"]},
    )
    xref_db.add_xref(
        kb,
        FUNCTION_VA + 0x20,
        CALLEE_VA,
        "call",
        src_function_va=FUNCTION_VA,
    )
    kb._conn.executescript(  # noqa: SLF001
        """
CREATE TABLE IF NOT EXISTS memory_operand_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    function_name TEXT,
    instruction_va INTEGER NOT NULL,
    instruction_text TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operand_index INTEGER NOT NULL,
    operand_text TEXT NOT NULL,
    access_kind TEXT NOT NULL,
    width_bytes INTEGER,
    address_expression TEXT NOT NULL,
    base_register TEXT,
    index_register TEXT,
    scale INTEGER,
    displacement INTEGER NOT NULL DEFAULT 0,
    role_hint TEXT NOT NULL,
    base_object TEXT,
    base_object_kind TEXT,
    base_object_type TEXT,
    base_object_role TEXT,
    field_offset INTEGER NOT NULL DEFAULT 0,
    likely_field_name TEXT,
    likely_type_name TEXT,
    data_target_va INTEGER,
    data_target_kind TEXT,
    data_target_name TEXT,
    data_target_type TEXT,
    data_target_size INTEGER,
    confidence REAL NOT NULL,
    set_by TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, instruction_va, operand_index)
);
"""
    )
    kb._conn.execute(  # noqa: SLF001
        """
INSERT INTO memory_operand_facts
(binary_id, function_va, function_name, instruction_va, instruction_text,
 mnemonic, operand_index, operand_text, access_kind, width_bytes,
 address_expression, base_register, index_register, scale, displacement,
 role_hint, base_object, base_object_kind, base_object_type, base_object_role,
 field_offset, likely_field_name, likely_type_name, data_target_va,
 data_target_kind, data_target_name, data_target_type, data_target_size,
 confidence, set_by, set_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?)
""",
        (
            kb.binary_id,
            FUNCTION_VA,
            "ReviewedStartup",
            FUNCTION_VA + 0x10,
            "mov rax, qword ptr [rcx + 0x18]",
            "mov",
            1,
            "qword ptr [rcx + 0x18]",
            "read",
            8,
            "[rcx + 0x18]",
            "rcx",
            None,
            None,
            0x18,
            "user_pointer",
            "Irp",
            "user_pointer",
            "PIRP",
            "irp",
            0x18,
            "UserBuffer",
            "IRP",
            None,
            None,
            None,
            None,
            None,
            0.93,
            "unit",
            0,
        ),
    )
    kb._conn.commit()  # noqa: SLF001
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
    assert facts.function_prototype is not None
    assert facts.function_prototype.rendered.startswith("NTSTATUS ReviewedStartup")
    assert facts.function_prototype.params[0].name == "Irp"
    assert facts.function_prototype.params[0].role == "irp"
    assert "ioctl" in facts.function_prototype.risk_tags
    assert len(facts.project_calls) == 1
    assert facts.project_calls[0].target_va == CALLEE_VA
    assert facts.project_calls[0].target_name == "nt!ProbeForRead"
    assert facts.project_calls[0].sources == ["project_xrefs"]
    assert any(call.target_name == "nt!ProbeForRead" for call in result.packet.calls)
    probe_proto = next(
        proto
        for proto in facts.call_prototypes
        if proto.function_name == "ProbeForRead"
    )
    assert probe_proto.params[1].name == "Length"
    assert probe_proto.params[1].role == "length"
    assert len(facts.memory_accesses) == 1
    assert facts.memory_accesses[0].likely_field_name == "UserBuffer"
    assert facts.memory_accesses[0].base_object_kind == "user_pointer"
    assert facts.entry_comment == "manual startup review note"
    assert "function_names" in facts.coverage
    assert "function_prototype" in facts.coverage
    assert "project_call_xrefs" in facts.coverage
    assert "call_prototypes" in facts.coverage
    assert "memory_accesses" in facts.coverage
    assert "comments" in facts.coverage
    assert "data_labels" in facts.coverage
    assert "function_prototype" in result.packet.coverage
    assert "project_call_xrefs" in result.packet.coverage
    assert "call_prototypes" in result.packet.coverage
    assert "memory_accesses" in result.packet.coverage
    assert "project_facts" not in result.packet.missing_capabilities


def test_memory_agent_registers_windows_decompile_context_packet() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_decompile_context_packet" in agent._function_toolset.tools
