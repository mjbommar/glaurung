"""Persistent cross-reference database (Tier-S #154).

Builds on :mod:`glaurung.llm.kb.persistent`'s SQLite file. Adds two
indexed tables — ``xrefs`` and ``function_names`` — and a small Python
API to populate them once from the analysis pipeline and query them in
O(log n) thereafter.

The existing ``list_xrefs_to`` / ``list_xrefs_from`` tools recompute
the full call graph on every invocation by re-running
``analyze_functions_path``. With the xref database wired up, those
tools become two SQL queries; the analysis runs once per binary and
the answers stay cached forever (until the binary changes).

Schema is additive — existing files without these tables get them
created on demand.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Literal, Optional, Tuple

from .persistent import PersistentKnowledgeBase


XrefKind = Literal[
    "call",          # direct or indirect call control-flow edge
    "jump",          # tail / inter-function jump
    "data_read",     # load that targets dst_va
    "data_write",    # store that targets dst_va
    "struct_field",  # access patterned as base+offset
]


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    src_va INTEGER NOT NULL,
    dst_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    src_function_va INTEGER,
    indexed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_xrefs_dst ON xrefs(binary_id, dst_va);
CREATE INDEX IF NOT EXISTS idx_xrefs_src ON xrefs(binary_id, src_va);
CREATE INDEX IF NOT EXISTS idx_xrefs_func
    ON xrefs(binary_id, src_function_va);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_xref
    ON xrefs(binary_id, src_va, dst_va, kind);

CREATE TABLE IF NOT EXISTS function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, entry_va)
);

CREATE TABLE IF NOT EXISTS comments (
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    body TEXT NOT NULL,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
);

CREATE TABLE IF NOT EXISTS xref_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    function_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class XrefRow:
    """A single xref returned to callers."""
    src_va: int
    dst_va: int
    kind: str
    src_function_va: Optional[int]


@dataclass(frozen=True)
class FunctionName:
    entry_va: int
    canonical: str
    aliases: List[str]
    set_by: Optional[str]


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the xref/function-name/comments tables if they're missing.

    Idempotent — runs on every open. Doesn't bump the schema_version
    (these tables are optional add-ons, present whenever the user
    actually populates them).
    """
    conn.executescript(_SCHEMA_SQL)
    conn.commit()


def is_indexed(kb: PersistentKnowledgeBase) -> bool:
    """Return True when the binary's xref table has been populated.

    Used to skip the (expensive) re-indexing step on every open.
    """
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT 1 FROM xref_index_state WHERE binary_id = ?", (kb.binary_id,),
    )
    return cur.fetchone() is not None


def index_callgraph(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    *,
    force: bool = False,
) -> int:
    """Run ``analyze_functions_path`` once and persist the resulting
    callgraph as ``call`` xrefs. Skips work when the binary is already
    indexed unless ``force`` is True.

    Returns the number of edges written. Idempotent — re-running with
    ``force=True`` deletes the previous rows for this binary first.
    """
    _ensure_schema(kb._conn)
    if is_indexed(kb) and not force:
        return _row_count(kb, "call")

    import glaurung as g

    funcs, cg = g.analysis.analyze_functions_path(binary_path)
    # Build name → entry-VA map; the callgraph emits edges by name.
    va_by_name = {f.name: int(f.entry_point.value) for f in funcs}
    # gcc-emitted callgraph also uses ``sub_<hex>`` for unnamed funcs.
    for f in funcs:
        ev = int(f.entry_point.value)
        va_by_name.setdefault(f"sub_{ev:x}", ev)

    rows: List[Tuple[int, int, int, str, Optional[int]]] = []
    seen: set[Tuple[int, int, str]] = set()
    for e in cg.edges:
        src = va_by_name.get(e.caller)
        dst = va_by_name.get(e.callee)
        if src is None or dst is None:
            continue
        key = (src, dst, "call")
        if key in seen:
            continue
        seen.add(key)
        rows.append((kb.binary_id, src, dst, "call", src))

    cur = kb._conn.cursor()
    cur.execute("BEGIN")
    try:
        if force:
            cur.execute(
                "DELETE FROM xrefs WHERE binary_id = ?", (kb.binary_id,),
            )
        cur.executemany(
            "INSERT OR IGNORE INTO xrefs "
            "(binary_id, src_va, dst_va, kind, src_function_va, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(*r, int(time.time())) for r in rows],
        )
        cur.execute(
            "INSERT OR REPLACE INTO xref_index_state "
            "(binary_id, indexed_at, function_count, edge_count) "
            "VALUES (?, ?, ?, ?)",
            (kb.binary_id, int(time.time()), len(funcs), len(rows)),
        )
        kb._conn.commit()
    except Exception:
        kb._conn.rollback()
        raise

    # Populate function_names with whatever the analyser supplied.
    name_rows = [
        (kb.binary_id, int(f.entry_point.value), f.name, "[]", "analyzer", int(time.time()))
        for f in funcs
    ]
    cur.executemany(
        "INSERT OR IGNORE INTO function_names "
        "(binary_id, entry_va, canonical, aliases_json, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        name_rows,
    )
    kb._conn.commit()
    return len(rows)


def _row_count(kb: PersistentKnowledgeBase, kind: Optional[str] = None) -> int:
    cur = kb._conn.cursor()
    if kind is None:
        cur.execute(
            "SELECT COUNT(*) FROM xrefs WHERE binary_id = ?", (kb.binary_id,),
        )
    else:
        cur.execute(
            "SELECT COUNT(*) FROM xrefs WHERE binary_id = ? AND kind = ?",
            (kb.binary_id, kind),
        )
    return cur.fetchone()[0]


def add_xref(
    kb: PersistentKnowledgeBase,
    src_va: int,
    dst_va: int,
    kind: XrefKind,
    src_function_va: Optional[int] = None,
) -> None:
    """Insert a single xref. Used by callers who discover xrefs
    incrementally — e.g. data-flow analysis, struct-field access pass."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO xrefs "
        "(binary_id, src_va, dst_va, kind, src_function_va, indexed_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (kb.binary_id, src_va, dst_va, kind, src_function_va, int(time.time())),
    )
    kb._conn.commit()


def list_xrefs_to(
    kb: PersistentKnowledgeBase,
    dst_va: int,
    kinds: Optional[Iterable[str]] = None,
    limit: int = 64,
) -> List[XrefRow]:
    """Return every xref whose destination is ``dst_va``."""
    _ensure_schema(kb._conn)
    sql = (
        "SELECT src_va, dst_va, kind, src_function_va FROM xrefs "
        "WHERE binary_id = ? AND dst_va = ?"
    )
    params: List[object] = [kb.binary_id, dst_va]
    if kinds is not None:
        kinds_list = list(kinds)
        sql += " AND kind IN (" + ",".join("?" * len(kinds_list)) + ")"
        params.extend(kinds_list)
    sql += " LIMIT ?"
    params.append(limit)
    cur = kb._conn.cursor()
    cur.execute(sql, params)
    return [XrefRow(*r) for r in cur.fetchall()]


def list_xrefs_from(
    kb: PersistentKnowledgeBase,
    src_va: int,
    kinds: Optional[Iterable[str]] = None,
    limit: int = 64,
) -> List[XrefRow]:
    """Return every xref whose source is ``src_va``."""
    _ensure_schema(kb._conn)
    sql = (
        "SELECT src_va, dst_va, kind, src_function_va FROM xrefs "
        "WHERE binary_id = ? AND src_va = ?"
    )
    params: List[object] = [kb.binary_id, src_va]
    if kinds is not None:
        kinds_list = list(kinds)
        sql += " AND kind IN (" + ",".join("?" * len(kinds_list)) + ")"
        params.extend(kinds_list)
    sql += " LIMIT ?"
    params.append(limit)
    cur = kb._conn.cursor()
    cur.execute(sql, params)
    return [XrefRow(*r) for r in cur.fetchall()]


def list_xrefs_in_function(
    kb: PersistentKnowledgeBase,
    function_va: int,
    kinds: Optional[Iterable[str]] = None,
    limit: int = 256,
) -> List[XrefRow]:
    """Every xref whose source instruction is inside the function whose
    entry is ``function_va``. Useful for "show me everything this
    function calls / reads / writes" without re-running analysis."""
    _ensure_schema(kb._conn)
    sql = (
        "SELECT src_va, dst_va, kind, src_function_va FROM xrefs "
        "WHERE binary_id = ? AND src_function_va = ?"
    )
    params: List[object] = [kb.binary_id, function_va]
    if kinds is not None:
        kinds_list = list(kinds)
        sql += " AND kind IN (" + ",".join("?" * len(kinds_list)) + ")"
        params.extend(kinds_list)
    sql += " LIMIT ?"
    params.append(limit)
    cur = kb._conn.cursor()
    cur.execute(sql, params)
    return [XrefRow(*r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Function names + comments — also persistent, also indexed.
# ---------------------------------------------------------------------------


def set_function_name(
    kb: PersistentKnowledgeBase,
    entry_va: int,
    name: str,
    *,
    set_by: str = "manual",
    aliases: Optional[List[str]] = None,
) -> None:
    """Persist a function name. ``set_by`` distinguishes manual /
    DWARF / FLIRT / LLM sources so later passes can prefer one over
    another."""
    _ensure_schema(kb._conn)
    import json

    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO function_names "
        "(binary_id, entry_va, canonical, aliases_json, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, entry_va, name,
            json.dumps(aliases or []), set_by, int(time.time()),
        ),
    )
    kb._conn.commit()


def get_function_name(
    kb: PersistentKnowledgeBase, entry_va: int
) -> Optional[FunctionName]:
    _ensure_schema(kb._conn)
    import json

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_va, canonical, aliases_json, set_by FROM function_names "
        "WHERE binary_id = ? AND entry_va = ?",
        (kb.binary_id, entry_va),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return FunctionName(
        entry_va=row[0], canonical=row[1],
        aliases=json.loads(row[2] or "[]"), set_by=row[3],
    )


def list_function_names(
    kb: PersistentKnowledgeBase,
) -> List[FunctionName]:
    _ensure_schema(kb._conn)
    import json

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_va, canonical, aliases_json, set_by FROM function_names "
        "WHERE binary_id = ? ORDER BY entry_va",
        (kb.binary_id,),
    )
    return [
        FunctionName(
            entry_va=row[0], canonical=row[1],
            aliases=json.loads(row[2] or "[]"), set_by=row[3],
        )
        for row in cur.fetchall()
    ]


def set_comment(
    kb: PersistentKnowledgeBase, va: int, body: str,
    *, set_by: str = "manual",
) -> None:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO comments "
        "(binary_id, va, body, set_by, set_at) VALUES (?, ?, ?, ?, ?)",
        (kb.binary_id, va, body, set_by, int(time.time())),
    )
    kb._conn.commit()


def get_comment(kb: PersistentKnowledgeBase, va: int) -> Optional[str]:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT body FROM comments WHERE binary_id = ? AND va = ?",
        (kb.binary_id, va),
    )
    row = cur.fetchone()
    return row[0] if row else None


def list_comments(
    kb: PersistentKnowledgeBase,
) -> List[Tuple[int, str]]:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT va, body FROM comments WHERE binary_id = ? ORDER BY va",
        (kb.binary_id,),
    )
    return [(va, body) for va, body in cur.fetchall()]
