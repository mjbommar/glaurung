"""Windows function chunk, thunk, and tailcall facts.

Function starts alone are not enough for IDA/Ghidra-like analysis. This module
persists a compact project table that describes how discovered ranges and
control-flow transfers should be interpreted: primary bodies, public-symbol
ranges, interior split candidates, jump/import/adjustor thunks, and shared
tail targets.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal

from . import windows_boundaries, xref_db
from .persistent import PersistentKnowledgeBase


FunctionChunkKind = Literal[
    "pdata_body",
    "public_symbol_range",
    "entry_candidate",
    "split_body_candidate",
    "exception_funclet_candidate",
    "chained_unwind_chunk",
    "exception_handler_chunk",
    "tail_jump_target",
    "shared_tail_candidate",
    "jump_thunk",
    "adjustor_thunk",
    "import_thunk",
]

FunctionChunkRelation = Literal[
    "owns",
    "candidate_start",
    "split_candidate",
    "exception_child",
    "unwind_child",
    "exception_handler",
    "tailcall_to",
    "shared_tail_from",
    "thunk_to",
    "import_thunk",
]


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS function_chunk_facts (
    chunk_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    identity_key TEXT NOT NULL,
    owner_entry_va INTEGER,
    chunk_start_va INTEGER NOT NULL,
    chunk_end_va INTEGER,
    chunk_size INTEGER,
    chunk_kind TEXT NOT NULL,
    relation_kind TEXT NOT NULL,
    target_va INTEGER,
    target_name TEXT,
    source TEXT NOT NULL,
    confidence REAL NOT NULL,
    name TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    indexed_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_function_chunk_fact
    ON function_chunk_facts(binary_id, identity_key);
CREATE INDEX IF NOT EXISTS idx_function_chunk_owner
    ON function_chunk_facts(binary_id, owner_entry_va);
CREATE INDEX IF NOT EXISTS idx_function_chunk_start
    ON function_chunk_facts(binary_id, chunk_start_va);
CREATE INDEX IF NOT EXISTS idx_function_chunk_kind
    ON function_chunk_facts(binary_id, chunk_kind);
CREATE INDEX IF NOT EXISTS idx_function_chunk_target
    ON function_chunk_facts(binary_id, target_va);
"""


@dataclass(frozen=True)
class FunctionChunkFact:
    owner_entry_va: int | None
    chunk_start_va: int
    chunk_end_va: int | None
    chunk_kind: str
    relation_kind: str
    source: str
    confidence: float
    target_va: int | None = None
    target_name: str | None = None
    name: str | None = None
    detail: dict[str, Any] | None = None

    @property
    def chunk_size(self) -> int | None:
        if self.chunk_end_va is None or self.chunk_end_va <= self.chunk_start_va:
            return None
        return self.chunk_end_va - self.chunk_start_va


def ensure_schema(kb: PersistentKnowledgeBase) -> None:
    xref_db._ensure_schema(kb._conn)
    windows_boundaries.ensure_schema(kb)
    kb._conn.executescript(_SCHEMA_SQL)
    kb._conn.commit()


def index_function_chunks(
    kb: PersistentKnowledgeBase,
    binary_path: str | Path,
    *,
    force: bool = False,
) -> int:
    """Persist first-class chunk/thunk/tail facts for one Windows project."""

    ensure_schema(kb)
    if force:
        kb._conn.execute(
            "DELETE FROM function_chunk_facts WHERE binary_id = ?",
            (kb.binary_id,),
        )

    path = Path(binary_path)
    data = path.read_bytes() if path.exists() else b""
    layout = windows_boundaries._parse_pe_layout(data)

    if windows_boundaries.row_count(kb) == 0 and path.exists():
        windows_boundaries.index_function_boundaries(kb, path, force=force)
    boundaries = windows_boundaries.list_boundaries(kb, limit=1_000_000)

    facts: list[FunctionChunkFact] = []
    facts.extend(_boundary_chunk_facts(boundaries))
    facts.extend(_jump_xref_chunk_facts(kb, boundaries, data, layout))
    facts.extend(_name_based_thunk_facts(kb, boundaries, data, layout))

    now = int(time.time())
    rows = []
    for item in _dedupe_facts(facts):
        rows.append(
            (
                kb.binary_id,
                _identity_key(item),
                item.owner_entry_va,
                item.chunk_start_va,
                item.chunk_end_va,
                item.chunk_size,
                item.chunk_kind,
                item.relation_kind,
                item.target_va,
                item.target_name,
                item.source,
                item.confidence,
                item.name,
                json.dumps(item.detail or {}, sort_keys=True),
                now,
            )
        )
    kb._conn.executemany(
        "INSERT OR REPLACE INTO function_chunk_facts "
        "(binary_id, identity_key, owner_entry_va, chunk_start_va, chunk_end_va, "
        "chunk_size, chunk_kind, relation_kind, target_va, target_name, source, "
        "confidence, name, detail_json, indexed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    kb._conn.commit()
    return row_count(kb)


def list_function_chunks(
    kb: PersistentKnowledgeBase,
    *,
    va: int | None = None,
    owner_entry_va: int | None = None,
    chunk_kind: str | None = None,
    relation_kind: str | None = None,
    target_va: int | None = None,
    min_confidence: float = 0.0,
    limit: int = 100,
) -> list[FunctionChunkFact]:
    ensure_schema(kb)
    clauses = ["binary_id = ?", "confidence >= ?"]
    params: list[object] = [kb.binary_id, min_confidence]
    if va is not None:
        clauses.append(
            """
            (
                owner_entry_va = ?
                OR chunk_start_va = ?
                OR target_va = ?
                OR (
                    chunk_end_va IS NOT NULL
                    AND chunk_start_va <= ?
                    AND chunk_end_va > ?
                )
            )
            """
        )
        params.extend([va, va, va, va, va])
    if owner_entry_va is not None:
        clauses.append("owner_entry_va = ?")
        params.append(owner_entry_va)
    if chunk_kind:
        clauses.append("chunk_kind = ?")
        params.append(chunk_kind)
    if relation_kind:
        clauses.append("relation_kind = ?")
        params.append(relation_kind)
    if target_va is not None:
        clauses.append("target_va = ?")
        params.append(target_va)
    rows = kb._conn.execute(
        f"""
SELECT owner_entry_va, chunk_start_va, chunk_end_va, chunk_kind, relation_kind,
       target_va, target_name, source, confidence, name, detail_json
FROM function_chunk_facts
WHERE {" AND ".join(clauses)}
ORDER BY chunk_start_va, confidence DESC, chunk_kind
LIMIT ?
""",
        (*params, limit),
    ).fetchall()
    return [_row_to_fact(row) for row in rows]


def row_count(kb: PersistentKnowledgeBase) -> int:
    ensure_schema(kb)
    row = kb._conn.execute(
        "SELECT COUNT(*) FROM function_chunk_facts WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    return int(row[0]) if row else 0


def _row_to_fact(row: tuple) -> FunctionChunkFact:
    detail = json.loads(row[10] or "{}")
    return FunctionChunkFact(
        owner_entry_va=int(row[0]) if row[0] is not None else None,
        chunk_start_va=int(row[1]),
        chunk_end_va=int(row[2]) if row[2] is not None else None,
        chunk_kind=str(row[3]),
        relation_kind=str(row[4]),
        target_va=int(row[5]) if row[5] is not None else None,
        target_name=str(row[6]) if row[6] is not None else None,
        source=str(row[7]),
        confidence=float(row[8]),
        name=str(row[9]) if row[9] is not None else None,
        detail=detail if isinstance(detail, dict) else {},
    )


def _boundary_chunk_facts(
    boundaries: Iterable[windows_boundaries.FunctionBoundaryCandidate],
) -> list[FunctionChunkFact]:
    out: list[FunctionChunkFact] = []
    for item in boundaries:
        detail = dict(item.detail or {})
        if item.source == "pdata" and item.end_va is not None:
            out.append(
                FunctionChunkFact(
                    owner_entry_va=item.entry_va,
                    chunk_start_va=item.entry_va,
                    chunk_end_va=item.end_va,
                    chunk_kind="pdata_body",
                    relation_kind="owns",
                    source="pdata",
                    confidence=item.confidence,
                    name=item.name,
                    detail=detail,
                )
            )
            out.extend(_pdata_unwind_chunk_facts(item, detail))
            continue
        if (
            item.source
            in {
                "pdb",
                "function_name",
                "pdb_symbol_adjacency",
                "function_name_symbol_adjacency",
            }
            and item.end_va is not None
        ):
            out.append(
                FunctionChunkFact(
                    owner_entry_va=item.entry_va,
                    chunk_start_va=item.entry_va,
                    chunk_end_va=item.end_va,
                    chunk_kind="public_symbol_range",
                    relation_kind="owns",
                    source=item.source,
                    confidence=item.confidence,
                    name=item.name,
                    detail=detail,
                )
            )
            continue
        if item.source in {"pdb_public_inside_pdata", "label_inside_pdata"}:
            owner = _hex_value(detail.get("containing_pdata_start"))
            chunk_kind = (
                "exception_funclet_candidate"
                if _looks_exception_funclet_name(item.name)
                else "split_body_candidate"
            )
            relation = (
                "exception_child"
                if chunk_kind == "exception_funclet_candidate"
                else "split_candidate"
            )
            out.append(
                FunctionChunkFact(
                    owner_entry_va=owner,
                    chunk_start_va=item.entry_va,
                    chunk_end_va=item.end_va,
                    chunk_kind=chunk_kind,
                    relation_kind=relation,
                    source=item.source,
                    confidence=item.confidence,
                    name=item.name,
                    detail=detail,
                )
            )
            continue
        if item.source == "call_target":
            out.append(
                FunctionChunkFact(
                    owner_entry_va=None,
                    chunk_start_va=item.entry_va,
                    chunk_end_va=None,
                    chunk_kind="entry_candidate",
                    relation_kind="candidate_start",
                    source="call_target",
                    confidence=item.confidence,
                    name=item.name,
                    detail=detail,
                )
            )
    return out


def _pdata_unwind_chunk_facts(
    item: windows_boundaries.FunctionBoundaryCandidate,
    detail: dict[str, Any],
) -> list[FunctionChunkFact]:
    unwind = detail.get("unwind")
    if not isinstance(unwind, dict):
        return []
    out: list[FunctionChunkFact] = []
    chained_begin = _hex_value(unwind.get("chained_begin_va"))
    if chained_begin is not None:
        out.append(
            FunctionChunkFact(
                owner_entry_va=chained_begin,
                chunk_start_va=item.entry_va,
                chunk_end_va=item.end_va,
                chunk_kind="chained_unwind_chunk",
                relation_kind="unwind_child",
                target_va=chained_begin,
                source="pdata_unwind_chain",
                confidence=0.84,
                name=item.name,
                detail=detail,
            )
        )
    handler_va = _hex_value(unwind.get("handler_va"))
    if handler_va is not None and unwind.get("handler_executable") is not False:
        out.append(
            FunctionChunkFact(
                owner_entry_va=item.entry_va,
                chunk_start_va=handler_va,
                chunk_end_va=None,
                chunk_kind="exception_handler_chunk",
                relation_kind="exception_handler",
                target_va=handler_va,
                source="pdata_unwind_handler",
                confidence=0.76,
                name=item.name,
                detail=detail,
            )
        )
    return out


def _jump_xref_chunk_facts(
    kb: PersistentKnowledgeBase,
    boundaries: list[windows_boundaries.FunctionBoundaryCandidate],
    data: bytes,
    layout: Any | None,
) -> list[FunctionChunkFact]:
    rows = kb._conn.execute(
        """
SELECT x.src_va, x.dst_va, x.src_function_va, dst.canonical, owner.canonical
FROM xrefs x
LEFT JOIN function_names dst
  ON dst.binary_id = x.binary_id AND dst.entry_va = x.dst_va
LEFT JOIN function_names owner
  ON owner.binary_id = x.binary_id AND owner.entry_va = x.src_function_va
WHERE x.binary_id = ? AND x.kind = 'jump'
ORDER BY x.dst_va, x.src_va
""",
        (kb.binary_id,),
    ).fetchall()
    out: list[FunctionChunkFact] = []
    owners_by_target: dict[int, set[int]] = {}
    for src_va, dst_va, src_function_va, _dst_name, _owner_name in rows:
        owner = int(src_function_va) if src_function_va is not None else int(src_va)
        owners_by_target.setdefault(int(dst_va), set()).add(owner)

    containing_by_va = [
        item for item in boundaries if item.end_va is not None and item.entry_va
    ]
    for src_va, dst_va, src_function_va, dst_name, owner_name in rows:
        src = int(src_va)
        dst = int(dst_va)
        owner = int(src_function_va) if src_function_va is not None else src
        head = _head_bytes(data, layout, owner)
        thunk_kind = _thunk_kind_from_head(head)
        detail = {
            "src_va": hex(src),
            "src_function_va": hex(owner),
            "owner_name": owner_name,
            "target_name": dst_name,
            "head_hex": head.hex(" ") if head else None,
        }
        if thunk_kind is not None:
            out.append(
                FunctionChunkFact(
                    owner_entry_va=owner,
                    chunk_start_va=owner,
                    chunk_end_va=None,
                    chunk_kind=thunk_kind,
                    relation_kind="thunk_to",
                    target_va=dst,
                    target_name=str(dst_name) if dst_name is not None else None,
                    source="jump_xref_head",
                    confidence=0.86 if thunk_kind == "adjustor_thunk" else 0.82,
                    name=str(owner_name) if owner_name is not None else None,
                    detail=detail,
                )
            )
        out.append(
            FunctionChunkFact(
                owner_entry_va=owner,
                chunk_start_va=dst,
                chunk_end_va=_containing_end(containing_by_va, dst),
                chunk_kind="tail_jump_target",
                relation_kind="tailcall_to",
                target_va=dst,
                target_name=str(dst_name) if dst_name is not None else None,
                source="jump_xref",
                confidence=0.72,
                name=str(dst_name) if dst_name is not None else None,
                detail=detail,
            )
        )

    for dst, owners in owners_by_target.items():
        if len(owners) < 2:
            continue
        for owner in sorted(owners):
            out.append(
                FunctionChunkFact(
                    owner_entry_va=owner,
                    chunk_start_va=dst,
                    chunk_end_va=_containing_end(containing_by_va, dst),
                    chunk_kind="shared_tail_candidate",
                    relation_kind="shared_tail_from",
                    target_va=dst,
                    source="multi_owner_jump_xref",
                    confidence=0.78,
                    detail={
                        "owner_count": len(owners),
                        "owners": [hex(value) for value in sorted(owners)],
                    },
                )
            )
    return out


def _name_based_thunk_facts(
    kb: PersistentKnowledgeBase,
    boundaries: list[windows_boundaries.FunctionBoundaryCandidate],
    data: bytes,
    layout: Any | None,
) -> list[FunctionChunkFact]:
    rows = kb._conn.execute(
        "SELECT entry_va, canonical, set_by FROM function_names "
        "WHERE binary_id = ? ORDER BY entry_va",
        (kb.binary_id,),
    ).fetchall()
    boundary_by_entry = _best_boundary_by_entry(boundaries)
    out: list[FunctionChunkFact] = []
    for entry_raw, name_raw, set_by_raw in rows:
        entry = int(entry_raw)
        name = str(name_raw)
        set_by = str(set_by_raw or "")
        boundary = boundary_by_entry.get(entry)
        end_va = None if boundary is None else boundary.end_va
        detail = {
            "set_by": set_by,
            "boundary_source": None if boundary is None else boundary.source,
            "head_hex": (_head_bytes(data, layout, entry) or b"").hex(" ") or None,
        }
        target_name = _import_thunk_target_name(name)
        if target_name is not None:
            out.append(
                FunctionChunkFact(
                    owner_entry_va=entry,
                    chunk_start_va=entry,
                    chunk_end_va=end_va,
                    chunk_kind="import_thunk",
                    relation_kind="import_thunk",
                    source="function_name",
                    confidence=0.74,
                    target_name=target_name,
                    name=name,
                    detail=detail,
                )
            )
        if _looks_adjustor_name(name):
            out.append(
                FunctionChunkFact(
                    owner_entry_va=entry,
                    chunk_start_va=entry,
                    chunk_end_va=end_va,
                    chunk_kind="adjustor_thunk",
                    relation_kind="thunk_to",
                    source="function_name",
                    confidence=0.68,
                    name=name,
                    detail=detail,
                )
            )
        if _looks_exception_funclet_name(name):
            owner = None
            if boundary is not None and boundary.detail is not None:
                owner = _hex_value(boundary.detail.get("containing_pdata_start"))
            out.append(
                FunctionChunkFact(
                    owner_entry_va=owner,
                    chunk_start_va=entry,
                    chunk_end_va=end_va,
                    chunk_kind="exception_funclet_candidate",
                    relation_kind="exception_child",
                    source="function_name",
                    confidence=0.64,
                    name=name,
                    detail=detail,
                )
            )
    return out


def _identity_key(item: FunctionChunkFact) -> str:
    parts = [
        item.owner_entry_va,
        item.chunk_start_va,
        item.chunk_kind,
        item.relation_kind,
        item.target_va,
        item.target_name,
        item.source,
    ]
    return json.dumps(parts, separators=(",", ":"), sort_keys=False)


def _dedupe_facts(facts: Iterable[FunctionChunkFact]) -> list[FunctionChunkFact]:
    best: dict[str, FunctionChunkFact] = {}
    for item in facts:
        key = _identity_key(item)
        prev = best.get(key)
        if prev is None or item.confidence > prev.confidence:
            best[key] = item
    return sorted(
        best.values(),
        key=lambda item: (
            item.chunk_start_va,
            item.owner_entry_va if item.owner_entry_va is not None else -1,
            -item.confidence,
            item.chunk_kind,
        ),
    )


def _best_boundary_by_entry(
    boundaries: Iterable[windows_boundaries.FunctionBoundaryCandidate],
) -> dict[int, windows_boundaries.FunctionBoundaryCandidate]:
    out: dict[int, windows_boundaries.FunctionBoundaryCandidate] = {}
    for item in boundaries:
        prev = out.get(item.entry_va)
        if prev is None or item.confidence > prev.confidence:
            out[item.entry_va] = item
    return out


def _containing_end(
    boundaries: Iterable[windows_boundaries.FunctionBoundaryCandidate],
    va: int,
) -> int | None:
    for item in boundaries:
        if item.end_va is not None and item.entry_va <= va < item.end_va:
            return item.end_va
    return None


def _head_bytes(
    data: bytes,
    layout: Any | None,
    va: int,
    size: int = 16,
) -> bytes | None:
    if not data or layout is None:
        return None
    rva = va - getattr(layout, "image_base", 0)
    off = layout.rva_to_offset(rva)
    if off is None or off >= len(data):
        return None
    return data[off : min(len(data), off + size)]


def _thunk_kind_from_head(head: bytes | None) -> str | None:
    if not head:
        return None
    if _looks_adjustor_head(head):
        return "adjustor_thunk"
    if _looks_jump_thunk_head(head):
        return "jump_thunk"
    return None


def _looks_jump_thunk_head(head: bytes) -> bool:
    return (
        head.startswith((b"\xe9", b"\xeb", b"\xff\x25", b"\x48\xff\x25"))
        or len(head) >= 12
        and head.startswith(b"\x48\xb8")
        and head[10:12] == b"\xff\xe0"
    )


def _looks_adjustor_head(head: bytes) -> bool:
    adjust = head.startswith(
        (
            b"\x48\x8d\x49",
            b"\x48\x8d\x89",
            b"\x48\x83\xc1",
            b"\x48\x81\xc1",
        )
    )
    if not adjust:
        return False
    return any(marker in head[3:] for marker in (b"\xe9", b"\xeb", b"\xff\x25"))


def _import_thunk_target_name(name: str | None) -> str | None:
    if not name:
        return None
    short = name.rsplit("!", 1)[-1]
    for prefix in ("__imp__", "__imp_", "_imp_", "imp_", "j_", "thunk_"):
        if short.startswith(prefix) and len(short) > len(prefix):
            return short[len(prefix) :]
    if short.endswith("$thunk") and len(short) > len("$thunk"):
        return short[: -len("$thunk")]
    return None


def _looks_adjustor_name(name: str | None) -> bool:
    text = (name or "").lower()
    return any(token in text for token in ("adjustor", "vtordisp", "this adjust"))


def _looks_exception_funclet_name(name: str | None) -> bool:
    text = (name or "").lower()
    return any(
        token in text
        for token in (
            "$catch",
            "catch$",
            "$finally",
            "finally$",
            "$except",
            "except$",
            "$unwind",
            "unwind$",
            "funclet",
        )
    )


def _hex_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16 if value.lower().startswith("0x") else 10)
    except ValueError:
        return None
