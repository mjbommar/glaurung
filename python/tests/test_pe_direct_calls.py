from __future__ import annotations

from pathlib import Path

from glaurung.llm.kb import pe_direct_calls, xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000


def _write_minimal_pe64(tmp_path: Path) -> Path:
    path = tmp_path / "driver.sys"
    data = bytearray(0x400)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"

    coff = 0x84
    data[coff : coff + 2] = (0x8664).to_bytes(2, "little")
    data[coff + 2 : coff + 4] = (1).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xF0).to_bytes(2, "little")

    opt = coff + 20
    data[opt : opt + 2] = (0x20B).to_bytes(2, "little")
    data[opt + 0x18 : opt + 0x20] = IMAGE_BASE.to_bytes(8, "little")

    section = opt + 0xF0
    data[section : section + 8] = b".text\x00\x00\x00"
    data[section + 8 : section + 12] = (0x100).to_bytes(4, "little")
    data[section + 12 : section + 16] = TEXT_RVA.to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x200).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")

    src_va = IMAGE_BASE + TEXT_RVA
    dst_va = IMAGE_BASE + TEXT_RVA + 0x20
    rel = dst_va - (src_va + 5)
    data[0x200] = 0xE8
    data[0x201:0x205] = rel.to_bytes(4, "little", signed=True)
    path.write_bytes(data)
    return path


def test_pe_direct_calls_indexes_known_function_targets(tmp_path: Path) -> None:
    binary = _write_minimal_pe64(tmp_path)
    project = tmp_path / "driver.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    try:
        caller = IMAGE_BASE + TEXT_RVA
        callee = IMAGE_BASE + TEXT_RVA + 0x20
        xref_db.set_function_name(kb, caller, "driver!Caller", set_by="pdb")
        xref_db.set_function_name(kb, callee, "driver!Callee", set_by="pdb")

        assert pe_direct_calls.index_pe_direct_calls(kb, binary) == 1

        rows = xref_db.list_xrefs_from(kb, caller, kinds=["call"])
        assert len(rows) == 1
        assert rows[0].src_va == caller
        assert rows[0].dst_va == callee
        assert rows[0].src_function_va == caller
    finally:
        kb.close()
