from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.kb import windows_boundaries, windows_function_chunks, xref_db
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_project_function_chunk_facts import build_tool


IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
PDATA_RVA = 0x3000


def _write_pe64_with_pdata_and_thunks(tmp_path: Path) -> Path:
    path = tmp_path / "driver.sys"
    data = bytearray(0x2800)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"

    coff = 0x84
    data[coff : coff + 2] = (0x8664).to_bytes(2, "little")
    data[coff + 2 : coff + 4] = (2).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xF0).to_bytes(2, "little")

    opt = coff + 20
    data[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    data[opt + 0x18 : opt + 0x20] = IMAGE_BASE.to_bytes(8, "little")
    exception_dir = opt + 0x70 + 3 * 8
    data[exception_dir : exception_dir + 4] = PDATA_RVA.to_bytes(4, "little")
    data[exception_dir + 4 : exception_dir + 8] = (24).to_bytes(4, "little")

    section = opt + 0xF0
    data[section : section + 8] = b".text\x00\x00\x00"
    data[section + 8 : section + 12] = (0x1000).to_bytes(4, "little")
    data[section + 12 : section + 16] = TEXT_RVA.to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x1000).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x400).to_bytes(4, "little")
    data[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")

    pdata_section = section + 40
    data[pdata_section : pdata_section + 8] = b".pdata\x00\x00"
    data[pdata_section + 8 : pdata_section + 12] = (0x100).to_bytes(4, "little")
    data[pdata_section + 12 : pdata_section + 16] = PDATA_RVA.to_bytes(4, "little")
    data[pdata_section + 16 : pdata_section + 20] = (0x200).to_bytes(4, "little")
    data[pdata_section + 20 : pdata_section + 24] = (0x1800).to_bytes(4, "little")
    data[pdata_section + 36 : pdata_section + 40] = (0x40000040).to_bytes(4, "little")

    pdata_off = 0x1800
    data[pdata_off : pdata_off + 4] = TEXT_RVA.to_bytes(4, "little")
    data[pdata_off + 4 : pdata_off + 8] = (TEXT_RVA + 0x60).to_bytes(4, "little")
    data[pdata_off + 8 : pdata_off + 12] = (0).to_bytes(4, "little")
    data[pdata_off + 12 : pdata_off + 16] = (TEXT_RVA + 0x200).to_bytes(4, "little")
    data[pdata_off + 16 : pdata_off + 20] = (TEXT_RVA + 0x220).to_bytes(4, "little")
    data[pdata_off + 20 : pdata_off + 24] = (0).to_bytes(4, "little")

    adjustor_off = 0x400 + 0x300
    data[adjustor_off : adjustor_off + 9] = bytes.fromhex("48 83 c1 08 e9 00 02 00 00")
    jump_thunk_off = 0x400 + 0x400
    data[jump_thunk_off : jump_thunk_off + 5] = bytes.fromhex("e9 00 01 00 00")

    path.write_bytes(data)
    return path


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_function_chunks_index_boundaries_thunks_and_shared_tails(
    tmp_path: Path,
) -> None:
    binary = _write_pe64_with_pdata_and_thunks(tmp_path)
    project_path = tmp_path / "driver.glaurung"
    kb = PersistentKnowledgeBase.open(project_path, binary_path=binary)
    try:
        dispatch = IMAGE_BASE + TEXT_RVA
        catch_funclet = dispatch + 0x20
        import_thunk = dispatch + 0x40
        shared_tail = dispatch + 0x80
        other_owner = dispatch + 0x200
        adjustor = dispatch + 0x300
        jump_thunk = dispatch + 0x400
        adjustor_target = dispatch + 0x500
        jump_target = dispatch + 0x600

        xref_db.set_function_name(kb, dispatch, "driver!Dispatch", set_by="pdb")
        xref_db.set_function_name(
            kb, catch_funclet, "driver!Dispatch$catch$0", set_by="pdb"
        )
        xref_db.set_function_name(
            kb, import_thunk, "driver!__imp_ZwClose", set_by="pdb"
        )
        xref_db.set_function_name(kb, shared_tail, "driver!SharedTail", set_by="pdb")
        xref_db.set_function_name(kb, other_owner, "driver!Other", set_by="pdb")
        xref_db.set_function_name(kb, adjustor, "driver!adjustor_thunk", set_by="pdb")
        xref_db.set_function_name(kb, jump_thunk, "driver!jump_thunk", set_by="pdb")

        xref_db.add_xref(kb, dispatch + 0x50, shared_tail, "jump", dispatch)
        xref_db.add_xref(kb, other_owner + 0x10, shared_tail, "jump", other_owner)
        xref_db.add_xref(kb, adjustor, adjustor_target, "jump", adjustor)
        xref_db.add_xref(kb, jump_thunk, jump_target, "jump", jump_thunk)

        windows_boundaries.index_function_boundaries(kb, binary)
        count = windows_function_chunks.index_function_chunks(kb, binary)

        assert count >= 9
        facts = windows_function_chunks.list_function_chunks(kb, limit=128)
        kinds = {fact.chunk_kind for fact in facts}
        assert "pdata_body" in kinds
        assert "public_symbol_range" in kinds
        assert "exception_funclet_candidate" in kinds
        assert "import_thunk" in kinds
        assert "shared_tail_candidate" in kinds
        assert "tail_jump_target" in kinds
        assert "adjustor_thunk" in kinds
        assert "jump_thunk" in kinds

        imports = [fact for fact in facts if fact.chunk_kind == "import_thunk"]
        assert imports[0].target_name == "ZwClose"
        shared = [
            fact
            for fact in facts
            if fact.chunk_kind == "shared_tail_candidate"
            and fact.chunk_start_va == shared_tail
        ]
        assert {fact.owner_entry_va for fact in shared} == {dispatch, other_owner}
    finally:
        kb.close()


def test_windows_project_function_chunk_facts_filters_and_adds_evidence(
    tmp_path: Path,
) -> None:
    binary = _write_pe64_with_pdata_and_thunks(tmp_path)
    project_path = tmp_path / "driver.glaurung"
    kb = PersistentKnowledgeBase.open(project_path, binary_path=binary)
    try:
        owner = IMAGE_BASE + TEXT_RVA
        target = owner + 0x80
        xref_db.set_function_name(kb, owner, "driver!Dispatch", set_by="pdb")
        xref_db.set_function_name(kb, target, "driver!SharedTail", set_by="pdb")
        xref_db.add_xref(kb, owner + 0x50, target, "jump", owner)
        xref_db.add_xref(kb, owner + 0x200, target, "jump", owner + 0x200)
        windows_function_chunks.index_function_chunks(kb, binary)
    finally:
        kb.close()

    ctx = _ctx(tmp_path)
    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project_path),
            chunk_kind="shared_tail_candidate",
            add_to_kb=True,
        ),
    )

    assert result.chunk_count == 2
    assert "function_chunk_facts" in result.coverage
    assert "tailcall_chunk_facts" in result.coverage
    assert result.evidence_node_id is not None


def test_windows_project_function_chunk_facts_filters_by_contained_va(
    tmp_path: Path,
) -> None:
    binary = _write_pe64_with_pdata_and_thunks(tmp_path)
    project_path = tmp_path / "driver.glaurung"
    kb = PersistentKnowledgeBase.open(project_path, binary_path=binary)
    try:
        owner = IMAGE_BASE + TEXT_RVA
        xref_db.set_function_name(kb, owner, "driver!Dispatch", set_by="pdb")
        windows_function_chunks.index_function_chunks(kb, binary)
    finally:
        kb.close()

    ctx = _ctx(tmp_path)
    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(project_path),
            va=IMAGE_BASE + TEXT_RVA + 0x10,
            chunk_kind="pdata_body",
        ),
    )

    assert result.chunk_count == 1
    assert result.chunks[0].owner_entry_va == IMAGE_BASE + TEXT_RVA
    assert result.chunks[0].chunk_end_va == IMAGE_BASE + TEXT_RVA + 0x60
    assert "range_backed_chunk_facts" in result.coverage


def test_windows_project_function_chunk_facts_cli_json(tmp_path: Path, capsys) -> None:
    binary = _write_pe64_with_pdata_and_thunks(tmp_path)
    project_path = tmp_path / "driver.glaurung"
    kb = PersistentKnowledgeBase.open(project_path, binary_path=binary)
    try:
        owner = IMAGE_BASE + TEXT_RVA
        target = owner + 0x80
        xref_db.set_function_name(kb, owner, "driver!Dispatch", set_by="pdb")
        xref_db.set_function_name(kb, target, "driver!SharedTail", set_by="pdb")
        xref_db.add_xref(kb, owner + 0x50, target, "jump", owner)
        xref_db.add_xref(kb, owner + 0x200, target, "jump", owner + 0x200)
        windows_function_chunks.index_function_chunks(kb, binary)
    finally:
        kb.close()

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-function-chunks",
            "--project-path",
            str(project_path),
            "--chunk-kind",
            "shared_tail_candidate",
            "--va",
            hex(target),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["chunk_count"] == 2
    assert output["chunks"][0]["chunk_kind"] == "shared_tail_candidate"
    assert output["chunks"][0]["chunk_start_va"] == target


def test_memory_agent_registers_windows_project_function_chunk_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_function_chunk_facts" in agent._function_toolset.tools
