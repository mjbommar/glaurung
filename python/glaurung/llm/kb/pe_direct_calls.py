"""Conservative PE direct-call xref recovery.

This fallback fills a specific PE gap in the generic callgraph indexer:
scan executable sections for x86/x64 ``E8 rel32`` calls and persist only
those whose target is an already-known function entry. The target filter
keeps the pass deliberately conservative; PDB public/function names make
the useful Windows case work without treating arbitrary bytes as code.
"""

from __future__ import annotations

import bisect
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .persistent import PersistentKnowledgeBase
from . import xref_db


@dataclass(frozen=True)
class PeExecutableSection:
    va_start: int
    raw_start: int
    raw_size: int


def index_pe_direct_calls(
    kb: PersistentKnowledgeBase,
    binary_path: str | Path,
) -> int:
    """Persist direct PE ``E8 rel32`` calls to known function entries.

    Returns the number of new or existing rows represented by this pass.
    The function never deletes rows; it is intended as a supplement when
    the generic analyzer has no PE call edges.
    """

    xref_db._ensure_schema(kb._conn)
    functions = _function_entries(kb)
    if len(functions) < 2:
        return 0
    entries = [entry for entry, _name in functions]
    known_targets = set(entries)

    data = Path(binary_path).read_bytes()
    sections = _executable_sections(data)
    if not sections:
        return 0

    rows: list[tuple[int, int, int, str, Optional[int], int]] = []
    seen: set[tuple[int, int, str]] = set()
    now = int(time.time())
    for section in sections:
        end = min(len(data), section.raw_start + section.raw_size)
        blob = data[section.raw_start:end]
        for offset in range(0, max(0, len(blob) - 4)):
            if blob[offset] != 0xE8:
                continue
            src_va = section.va_start + offset
            rel = int.from_bytes(blob[offset + 1 : offset + 5], "little", signed=True)
            dst_va = (src_va + 5 + rel) & 0xFFFFFFFFFFFFFFFF
            if dst_va not in known_targets:
                continue
            src_function_va = _containing_function(entries, src_va)
            if src_function_va is None:
                continue
            key = (src_va, dst_va, "call")
            if key in seen:
                continue
            seen.add(key)
            rows.append((kb.binary_id, src_va, dst_va, "call", src_function_va, now))

    if not rows:
        return 0
    cur = kb._conn.cursor()
    cur.executemany(
        "INSERT OR IGNORE INTO xrefs "
        "(binary_id, src_va, dst_va, kind, src_function_va, indexed_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    kb._conn.commit()
    return xref_db._row_count(kb, "call")


def _function_entries(kb: PersistentKnowledgeBase) -> list[tuple[int, str]]:
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_va, canonical FROM function_names "
        "WHERE binary_id = ? ORDER BY entry_va",
        (kb.binary_id,),
    )
    return [(int(row[0]), str(row[1])) for row in cur.fetchall()]


def _containing_function(entries: list[int], va: int) -> int | None:
    idx = bisect.bisect_right(entries, va) - 1
    if idx < 0:
        return None
    if idx + 1 < len(entries) and va >= entries[idx + 1]:
        return None
    return entries[idx]


def _executable_sections(data: bytes) -> list[PeExecutableSection]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    if pe_off + 0x18 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
        return []

    coff = pe_off + 4
    section_count = int.from_bytes(data[coff + 2 : coff + 4], "little")
    optional_size = int.from_bytes(data[coff + 16 : coff + 18], "little")
    opt = coff + 20
    if opt + optional_size > len(data):
        return []
    magic = int.from_bytes(data[opt : opt + 2], "little")
    if magic == 0x10B:
        image_base = int.from_bytes(data[opt + 0x1C : opt + 0x20], "little")
    elif magic == 0x20B:
        image_base = int.from_bytes(data[opt + 0x18 : opt + 0x20], "little")
    else:
        return []

    section_table = opt + optional_size
    sections: list[PeExecutableSection] = []
    for index in range(section_count):
        off = section_table + index * 40
        if off + 40 > len(data):
            break
        virtual_size = int.from_bytes(data[off + 8 : off + 12], "little")
        virtual_address = int.from_bytes(data[off + 12 : off + 16], "little")
        raw_size = int.from_bytes(data[off + 16 : off + 20], "little")
        raw_start = int.from_bytes(data[off + 20 : off + 24], "little")
        characteristics = int.from_bytes(data[off + 36 : off + 40], "little")
        if not characteristics & 0x20000000:
            continue
        size = raw_size or virtual_size
        if raw_start >= len(data) or size <= 0:
            continue
        sections.append(
            PeExecutableSection(
                va_start=image_base + virtual_address,
                raw_start=raw_start,
                raw_size=size,
            )
        )
    return sections
