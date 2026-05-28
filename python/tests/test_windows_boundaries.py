from __future__ import annotations

from pathlib import Path

from glaurung.llm.kb import pe_direct_calls, windows_boundaries, xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
PDATA_RVA = 0x2000


def _write_pe64_with_pdata(tmp_path: Path) -> Path:
    path = tmp_path / "driver.sys"
    data = bytearray(0x600)
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
    data[exception_dir + 4 : exception_dir + 8] = (12).to_bytes(4, "little")

    section = opt + 0xF0
    data[section : section + 8] = b".text\x00\x00\x00"
    data[section + 8 : section + 12] = (0x100).to_bytes(4, "little")
    data[section + 12 : section + 16] = TEXT_RVA.to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x200).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")

    pdata_section = section + 40
    data[pdata_section : pdata_section + 8] = b".pdata\x00\x00"
    data[pdata_section + 8 : pdata_section + 12] = (0x100).to_bytes(4, "little")
    data[pdata_section + 12 : pdata_section + 16] = PDATA_RVA.to_bytes(4, "little")
    data[pdata_section + 16 : pdata_section + 20] = (0x200).to_bytes(4, "little")
    data[pdata_section + 20 : pdata_section + 24] = (0x400).to_bytes(4, "little")
    data[pdata_section + 36 : pdata_section + 40] = (0x40000040).to_bytes(4, "little")

    src_va = IMAGE_BASE + TEXT_RVA
    dst_va = IMAGE_BASE + TEXT_RVA + 0x20
    rel = dst_va - (src_va + 5)
    data[0x200] = 0xE8
    data[0x201:0x205] = rel.to_bytes(4, "little", signed=True)

    data[0x400:0x404] = TEXT_RVA.to_bytes(4, "little")
    data[0x404:0x408] = (TEXT_RVA + 0x30).to_bytes(4, "little")
    data[0x408:0x40C] = (0).to_bytes(4, "little")
    path.write_bytes(data)
    return path


def test_windows_boundaries_index_pdata_pdb_and_call_targets(tmp_path: Path) -> None:
    binary = _write_pe64_with_pdata(tmp_path)
    project = tmp_path / "driver.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    try:
        caller = IMAGE_BASE + TEXT_RVA
        callee = IMAGE_BASE + TEXT_RVA + 0x20
        public_a = IMAGE_BASE + TEXT_RVA + 0x50
        public_b = IMAGE_BASE + TEXT_RVA + 0x70
        xref_db.set_function_name(kb, caller, "driver!Caller", set_by="pdb")
        xref_db.set_function_name(kb, callee, "driver!Callee", set_by="pdb")
        xref_db.set_function_name(kb, public_a, "driver!PublicA", set_by="pdb")
        xref_db.set_function_name(kb, public_b, "driver!PublicB", set_by="pdb")
        assert pe_direct_calls.index_pe_direct_calls(kb, binary) == 1

        count = windows_boundaries.index_function_boundaries(kb, binary)

        assert count >= 4
        sources = {item.source for item in windows_boundaries.list_boundaries(kb)}
        assert {
            "pdata",
            "pdb",
            "pdb_public_inside_pdata",
            "pdb_symbol_adjacency",
            "call_target",
        } <= sources
        best = windows_boundaries.best_boundary_for_va(kb, caller + 4)
        assert best is not None
        assert best.entry_va == caller
        assert best.source == "pdb"
        assert best.end_va == caller + 0x30
        assert best.detail is not None
        assert best.detail["range_source"] == "pdata"

        interior = windows_boundaries.best_boundary_for_va(kb, callee)
        assert interior is not None
        assert interior.entry_va == caller
        assert interior.source == "pdb"

        exact_interior = windows_boundaries.boundary_for_entry(kb, callee)
        assert exact_interior is not None
        assert exact_interior.entry_va == callee
        assert exact_interior.source == "pdb_public_inside_pdata"
        assert exact_interior.end_va == caller + 0x30
        assert exact_interior.detail is not None
        assert exact_interior.detail["range_source"] == "containing_pdata_end"

        adjacent = windows_boundaries.boundary_for_entry(kb, public_a)
        assert adjacent is not None
        assert adjacent.source == "pdb_symbol_adjacency"
        assert adjacent.end_va == public_b
        assert adjacent.detail is not None
        assert adjacent.detail["range_source"] == "symbol_adjacency"
        assert adjacent.detail["next_symbol_va"] == hex(public_b)

        containing_adjacent = windows_boundaries.best_boundary_for_va(kb, public_a + 4)
        assert containing_adjacent is not None
        assert containing_adjacent.entry_va == public_a
        assert containing_adjacent.source == "pdb_symbol_adjacency"
    finally:
        kb.close()


def test_windows_boundaries_unknown_end_call_targets_only_match_entry(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "unknown-end.sys"
    binary.write_bytes(b"MZ")
    project = tmp_path / "unknown-end.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    try:
        caller = 0x140001000
        callee = 0x140002000
        xref_db.add_xref(kb, caller, callee, "call", src_function_va=caller)

        windows_boundaries.index_function_boundaries(kb, binary)

        exact = windows_boundaries.best_boundary_for_va(kb, callee)
        assert exact is not None
        assert exact.entry_va == callee
        assert exact.source == "call_target"
        assert exact.end_va is None

        assert windows_boundaries.best_boundary_for_va(kb, callee + 1) is None
    finally:
        kb.close()
