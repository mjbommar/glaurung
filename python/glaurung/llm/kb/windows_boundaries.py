"""Windows function-boundary candidates for project databases.

This module records a confidence-ranked boundary table from sources that are
available before a full CFG succeeds: PDB/public names, PE exception
directory (``.pdata``), and direct-call targets already persisted in xrefs.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .persistent import PersistentKnowledgeBase
from . import xref_db


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS function_boundaries (
    boundary_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    end_va INTEGER,
    size INTEGER,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    name TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    indexed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_function_boundaries_entry
    ON function_boundaries(binary_id, entry_va);
CREATE INDEX IF NOT EXISTS idx_function_boundaries_source
    ON function_boundaries(binary_id, source);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_function_boundary_source
    ON function_boundaries(binary_id, entry_va, source);
"""


@dataclass(frozen=True)
class FunctionBoundaryCandidate:
    entry_va: int
    end_va: int | None
    source: str
    confidence: float
    name: str | None = None
    detail: dict | None = None

    @property
    def size(self) -> int | None:
        if self.end_va is None or self.end_va <= self.entry_va:
            return None
        return self.end_va - self.entry_va


@dataclass(frozen=True)
class _PeSection:
    name: str
    va_start: int
    va_end: int
    raw_start: int
    raw_end: int
    executable: bool

    def contains_va(self, va: int) -> bool:
        return self.va_start <= va < self.va_end

    def rva_to_offset(self, image_base: int, rva: int) -> int | None:
        va = image_base + rva
        if not self.contains_va(va):
            return None
        off = self.raw_start + (va - self.va_start)
        if off >= self.raw_end:
            return None
        return off


@dataclass(frozen=True)
class _PeLayout:
    image_base: int
    sections: list[_PeSection]
    exception_rva: int
    exception_size: int

    def section_for_va(self, va: int) -> _PeSection | None:
        return next(
            (section for section in self.sections if section.contains_va(va)), None
        )

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            off = section.rva_to_offset(self.image_base, rva)
            if off is not None:
                return off
        return None


def ensure_schema(kb: PersistentKnowledgeBase) -> None:
    xref_db._ensure_schema(kb._conn)
    kb._conn.executescript(_SCHEMA_SQL)
    kb._conn.commit()


def index_function_boundaries(
    kb: PersistentKnowledgeBase,
    binary_path: str | Path,
    *,
    force: bool = False,
) -> int:
    """Persist confidence-ranked Windows function-boundary candidates."""

    ensure_schema(kb)
    cur = kb._conn.cursor()
    if force:
        cur.execute(
            "DELETE FROM function_boundaries WHERE binary_id = ?",
            (kb.binary_id,),
        )

    data = Path(binary_path).read_bytes()
    layout = _parse_pe_layout(data)
    candidates: list[FunctionBoundaryCandidate] = []
    pdata_candidates: list[FunctionBoundaryCandidate] = []
    if layout is not None:
        pdata_candidates = list(_pdata_boundaries(data, layout))
        candidates.extend(pdata_candidates)
    candidates.extend(_function_name_boundaries(kb, layout, pdata_candidates))
    candidates.extend(_call_target_boundaries(kb, layout))

    now = int(time.time())
    rows = [
        (
            kb.binary_id,
            item.entry_va,
            item.end_va,
            item.size,
            item.source,
            item.confidence,
            item.name,
            json.dumps(item.detail or {}, sort_keys=True),
            now,
        )
        for item in _dedupe_candidates(candidates)
    ]
    cur.executemany(
        "INSERT OR REPLACE INTO function_boundaries "
        "(binary_id, entry_va, end_va, size, source, confidence, name, detail_json, indexed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    kb._conn.commit()
    return row_count(kb)


def best_boundary_for_va(
    kb: PersistentKnowledgeBase,
    va: int,
) -> FunctionBoundaryCandidate | None:
    ensure_schema(kb)
    row = kb._conn.execute(
        """
SELECT entry_va, end_va, source, confidence, name, detail_json
FROM function_boundaries
WHERE binary_id = ?
  AND entry_va <= ?
  AND (end_va > ? OR (end_va IS NULL AND entry_va = ?))
ORDER BY confidence DESC, entry_va DESC
LIMIT 1
""",
        (kb.binary_id, va, va, va),
    ).fetchone()
    if row is None:
        return None
    return _row_to_candidate(row)


def boundary_for_entry(
    kb: PersistentKnowledgeBase,
    entry_va: int,
) -> FunctionBoundaryCandidate | None:
    """Return the best exact-entry boundary candidate.

    This differs from :func:`best_boundary_for_va`: a VA inside a larger
    ``.pdata`` body should usually resolve to the owner for "containing
    function" questions, but exact-entry decompile or review workflows need the
    best row whose entry is exactly the requested public/candidate start.
    """

    ensure_schema(kb)
    row = kb._conn.execute(
        """
SELECT entry_va, end_va, source, confidence, name, detail_json
FROM function_boundaries
WHERE binary_id = ? AND entry_va = ?
ORDER BY
  CASE WHEN end_va IS NULL THEN 1 ELSE 0 END,
  confidence DESC,
  source
LIMIT 1
""",
        (kb.binary_id, entry_va),
    ).fetchone()
    if row is None:
        return None
    return _row_to_candidate(row)


def list_boundaries(
    kb: PersistentKnowledgeBase,
    *,
    source: str | None = None,
    limit: int = 100,
) -> list[FunctionBoundaryCandidate]:
    ensure_schema(kb)
    params: list[object] = [kb.binary_id]
    where = "binary_id = ?"
    if source:
        where += " AND source = ?"
        params.append(source)
    rows = kb._conn.execute(
        f"""
SELECT entry_va, end_va, source, confidence, name, detail_json
FROM function_boundaries
WHERE {where}
ORDER BY entry_va, confidence DESC
LIMIT ?
""",
        (*params, limit),
    ).fetchall()
    return [_row_to_candidate(row) for row in rows]


def row_count(kb: PersistentKnowledgeBase) -> int:
    ensure_schema(kb)
    row = kb._conn.execute(
        "SELECT COUNT(*) FROM function_boundaries WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    return int(row[0]) if row else 0


def _row_to_candidate(row: tuple) -> FunctionBoundaryCandidate:
    detail = json.loads(row[5] or "{}")
    return FunctionBoundaryCandidate(
        entry_va=int(row[0]),
        end_va=int(row[1]) if row[1] is not None else None,
        source=str(row[2]),
        confidence=float(row[3]),
        name=str(row[4]) if row[4] is not None else None,
        detail=detail if isinstance(detail, dict) else {},
    )


def _function_name_boundaries(
    kb: PersistentKnowledgeBase,
    layout: _PeLayout | None,
    pdata_candidates: list[FunctionBoundaryCandidate],
) -> Iterable[FunctionBoundaryCandidate]:
    rows = kb._conn.execute(
        "SELECT entry_va, canonical, set_by FROM function_names "
        "WHERE binary_id = ? ORDER BY entry_va",
        (kb.binary_id,),
    ).fetchall()
    entries = [
        (int(row[0]), str(row[1]), str(row[2] or "function_name")) for row in rows
    ]
    pdata_by_entry = {item.entry_va: item for item in pdata_candidates}
    for idx, (entry, name, set_by) in enumerate(entries):
        section = layout.section_for_va(entry) if layout is not None else None
        if layout is not None and (section is None or not section.executable):
            continue
        same_pdata = pdata_by_entry.get(entry)
        containing_pdata = _containing_boundary(pdata_candidates, entry)
        source = "pdb" if set_by == "pdb" else "function_name"
        confidence = 0.95 if source == "pdb" else 0.72
        detail = {"set_by": set_by, "section": section.name if section else None}
        if same_pdata is not None:
            end_va = same_pdata.end_va
            detail["range_source"] = "pdata"
        elif containing_pdata is not None:
            next_entry = _next_entry_in_range(
                entries,
                idx,
                section=section,
                limit_end_va=containing_pdata.end_va,
            )
            end_va = next_entry or containing_pdata.end_va
            source = (
                "pdb_public_inside_pdata" if set_by == "pdb" else "label_inside_pdata"
            )
            confidence = 0.58
            if end_va is not None:
                detail["range_source"] = (
                    "symbol_adjacency_inside_pdata"
                    if next_entry is not None
                    else "containing_pdata_end"
                )
                if next_entry is not None:
                    detail["next_symbol_va"] = hex(next_entry)
            detail["containing_pdata_start"] = hex(containing_pdata.entry_va)
            detail["containing_pdata_end"] = (
                hex(containing_pdata.end_va)
                if containing_pdata.end_va is not None
                else None
            )
        else:
            end_va = _next_entry_in_range(entries, idx, section=section)
            if end_va is not None:
                source = (
                    "pdb_symbol_adjacency"
                    if set_by == "pdb"
                    else "function_name_symbol_adjacency"
                )
                confidence = 0.82 if set_by == "pdb" else 0.62
                detail["range_source"] = "symbol_adjacency"
                detail["next_symbol_va"] = hex(end_va)
        yield FunctionBoundaryCandidate(
            entry_va=entry,
            end_va=end_va,
            source=source,
            confidence=confidence,
            name=name,
            detail=detail,
        )


def _call_target_boundaries(
    kb: PersistentKnowledgeBase,
    layout: _PeLayout | None,
) -> Iterable[FunctionBoundaryCandidate]:
    rows = kb._conn.execute(
        "SELECT DISTINCT x.dst_va, fn.canonical FROM xrefs x "
        "LEFT JOIN function_names fn ON fn.binary_id = x.binary_id AND fn.entry_va = x.dst_va "
        "WHERE x.binary_id = ? AND x.kind = 'call' ORDER BY x.dst_va",
        (kb.binary_id,),
    ).fetchall()
    for entry, name in rows:
        entry = int(entry)
        section = layout.section_for_va(entry) if layout is not None else None
        if layout is not None and (section is None or not section.executable):
            continue
        yield FunctionBoundaryCandidate(
            entry_va=entry,
            end_va=None,
            source="call_target",
            confidence=0.64,
            name=str(name) if name is not None else None,
            detail={"section": section.name if section else None},
        )


def _pdata_boundaries(
    data: bytes, layout: _PeLayout
) -> Iterable[FunctionBoundaryCandidate]:
    if not layout.exception_rva or not layout.exception_size:
        return []
    start = layout.rva_to_offset(layout.exception_rva)
    if start is None:
        return []
    end = min(len(data), start + layout.exception_size)
    out: list[FunctionBoundaryCandidate] = []
    for off in range(start, max(start, end - 11), 12):
        begin = int.from_bytes(data[off : off + 4], "little")
        finish = int.from_bytes(data[off + 4 : off + 8], "little")
        if begin == 0 or finish <= begin:
            continue
        entry_va = layout.image_base + begin
        end_va = layout.image_base + finish
        section = layout.section_for_va(entry_va)
        if (
            section is None
            or not section.executable
            or not section.contains_va(end_va - 1)
        ):
            continue
        out.append(
            FunctionBoundaryCandidate(
                entry_va=entry_va,
                end_va=end_va,
                source="pdata",
                confidence=0.90,
                detail={"section": section.name},
            )
        )
    return out


def _dedupe_candidates(
    candidates: Iterable[FunctionBoundaryCandidate],
) -> list[FunctionBoundaryCandidate]:
    best: dict[tuple[int, str], FunctionBoundaryCandidate] = {}
    for item in candidates:
        key = (item.entry_va, item.source)
        prev = best.get(key)
        if prev is None or item.confidence > prev.confidence:
            best[key] = item
    return sorted(
        best.values(), key=lambda item: (item.entry_va, -item.confidence, item.source)
    )


def _containing_boundary(
    candidates: Iterable[FunctionBoundaryCandidate],
    va: int,
) -> FunctionBoundaryCandidate | None:
    return next(
        (
            item
            for item in candidates
            if item.end_va is not None and item.entry_va < va < item.end_va
        ),
        None,
    )


def _next_entry_in_range(
    entries: list[tuple[int, str, str]],
    idx: int,
    *,
    section: _PeSection | None,
    limit_end_va: int | None = None,
) -> int | None:
    for next_entry, _next_name, _next_set_by in entries[idx + 1 :]:
        if section is not None and not section.contains_va(next_entry):
            continue
        if limit_end_va is not None and next_entry >= limit_end_va:
            continue
        return next_entry
    return None


def _parse_pe_layout(data: bytes) -> _PeLayout | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off = _u32(data, 0x3C)
    if (
        pe_off is None
        or pe_off + 0x18 > len(data)
        or data[pe_off : pe_off + 4] != b"PE\0\0"
    ):
        return None
    coff = pe_off + 4
    section_count = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    if section_count is None or optional_size is None:
        return None
    opt = coff + 20
    magic = _u16(data, opt)
    if magic == 0x20B:
        image_base = _u64(data, opt + 0x18)
        data_dir = opt + 0x70
    elif magic == 0x10B:
        image_base = _u32(data, opt + 0x1C)
        data_dir = opt + 0x60
    else:
        return None
    if image_base is None:
        return None
    exception_rva = _u32(data, data_dir + 3 * 8) or 0
    exception_size = _u32(data, data_dir + 3 * 8 + 4) or 0
    section_table = opt + optional_size
    sections: list[_PeSection] = []
    for idx in range(section_count):
        off = section_table + idx * 40
        if off + 40 > len(data):
            break
        raw_name = data[off : off + 8]
        name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = _u32(data, off + 8) or 0
        virtual_address = _u32(data, off + 12) or 0
        raw_size = _u32(data, off + 16) or 0
        raw_start = _u32(data, off + 20) or 0
        characteristics = _u32(data, off + 36) or 0
        size = max(virtual_size, raw_size)
        sections.append(
            _PeSection(
                name=name,
                va_start=image_base + virtual_address,
                va_end=image_base + virtual_address + size,
                raw_start=raw_start,
                raw_end=raw_start + raw_size,
                executable=bool(characteristics & 0x20000000),
            )
        )
    return _PeLayout(
        image_base=image_base,
        sections=sections,
        exception_rva=exception_rva,
        exception_size=exception_size,
    )


def _u16(data: bytes, off: int) -> int | None:
    raw = data[off : off + 2]
    return int.from_bytes(raw, "little") if len(raw) == 2 else None


def _u32(data: bytes, off: int) -> int | None:
    raw = data[off : off + 4]
    return int.from_bytes(raw, "little") if len(raw) == 4 else None


def _u64(data: bytes, off: int) -> int | None:
    raw = data[off : off + 8]
    return int.from_bytes(raw, "little") if len(raw) == 8 else None
