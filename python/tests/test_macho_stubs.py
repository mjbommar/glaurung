"""Integration tests for the Mach-O stubs / lazy-pointer resolver.

Ground truth comes from `llvm-otool -Iv` on the committed sample at
`samples/binaries/platforms/darwin/amd64/export/native/multi_import-macho`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


SAMPLE = Path(
    "samples/binaries/platforms/darwin/amd64/export/native/multi_import-macho"
)

# VAs verified with `llvm-otool -Iv`:
#   __TEXT,__stubs  (6-byte entries)
EXPECTED_STUB_VAS = {
    0x100000618: "free@stub",
    0x10000061E: "puts@stub",
    0x100000624: "printf@stub",
    0x10000062A: "strlen@stub",
    0x100000630: "malloc@stub",
}
#   __DATA,__la_symbol_ptr  (8-byte entries)
EXPECTED_LAPTR_VAS = {
    0x100003000: "free@laptr",
    0x100003008: "puts@laptr",
    0x100003010: "printf@laptr",
    0x100003018: "strlen@laptr",
    0x100003020: "malloc@laptr",
}


@pytest.mark.skipif(not SAMPLE.exists(), reason="Mach-O sample not present")
def test_macho_stubs_map_returns_stubs_and_laptr():
    entries = g.analysis.macho_stubs_map_path(str(SAMPLE))
    by_va = {int(va): str(name) for va, name in entries}

    for va, name in EXPECTED_STUB_VAS.items():
        assert by_va.get(va) == name, f"expected {name} at 0x{va:x}, got {by_va.get(va)!r}"
    for va, name in EXPECTED_LAPTR_VAS.items():
        assert by_va.get(va) == name, f"expected {name} at 0x{va:x}, got {by_va.get(va)!r}"


@pytest.mark.skipif(not SAMPLE.exists(), reason="Mach-O sample not present")
def test_macho_stubs_map_is_sorted_by_va():
    entries = g.analysis.macho_stubs_map_path(str(SAMPLE))
    vas = [int(v) for v, _ in entries]
    assert vas == sorted(vas)


def test_macho_stubs_map_empty_on_non_macho(tmp_path: Path):
    # ELF magic — must return empty.
    p = tmp_path / "not-macho"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 512)
    entries = g.analysis.macho_stubs_map_path(str(p))
    assert entries == []


@pytest.mark.skipif(not SAMPLE.exists(), reason="Mach-O sample not present")
def test_macho_stubs_feed_into_evidence_bundle():
    from glaurung.llm.evidence import _collect_symbols, AnnotateBudgets

    summary = _collect_symbols(str(SAMPLE), AnnotateBudgets())
    # The committed sample links against free/puts/printf/strlen/malloc via stubs.
    assert 0x100000618 in summary.macho_stub_map
    assert summary.macho_stub_map[0x100000618] == "free@stub"
