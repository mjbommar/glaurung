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
    -- Demangled / pretty-printed form, populated by demangle_pass (#182).
    -- NULL when the canonical name isn't a recognized mangled symbol.
    demangled TEXT,
    flavor TEXT,
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

-- Global data labels (#181). Names + (optional) types for global
-- variables, .data / .rodata / .bss symbols, jump-table targets, etc.
-- Distinct from `function_names` because data isn't called.
CREATE TABLE IF NOT EXISTS data_labels (
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    name TEXT NOT NULL,
    c_type TEXT,                  -- e.g. "int", "char *", "struct stat"
    size INTEGER,                 -- bytes occupied at the VA, optional
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
);
CREATE INDEX IF NOT EXISTS idx_data_labels_binary
    ON data_labels(binary_id);

-- Function prototypes (#172). Keyed by short_name so a stdlib
-- prototype loaded from a bundle can match every binary's `printf`
-- regardless of mangling. Demangled-form lookup runs through the
-- canonical column too (e.g. `Foo::bar` matches a manual entry).
CREATE TABLE IF NOT EXISTS function_prototypes (
    binary_id INTEGER NOT NULL,
    function_name TEXT NOT NULL,
    return_type TEXT,
    params_json TEXT NOT NULL DEFAULT '[]',
    is_variadic INTEGER NOT NULL DEFAULT 0,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, function_name)
);
CREATE INDEX IF NOT EXISTS idx_protos_binary
    ON function_prototypes(binary_id);

-- Evidence log (#200 v0). Every deterministic tool invocation that
-- produces an answer the agent might quote should land here as a row.
-- The cite_id is the stable identifier that propagates into the
-- agent's natural-language output (`...calls recv() at 0x1340 [cite #42]`),
-- and a chat-UI client renders rows here as expandable evidence panes.
--
-- v0 ships the substrate; per-tool migration to populate this is
-- v2 (#200 follow-up). Pre-existing tools keep working unchanged.
CREATE TABLE IF NOT EXISTS evidence_log (
    cite_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    tool TEXT NOT NULL,             -- e.g. "view_hex", "decompile_function"
    args_json TEXT NOT NULL,        -- inputs the tool was called with
    summary TEXT NOT NULL,          -- short human-readable description
    va_start INTEGER,               -- nullable: VA range this evidence covers
    va_end INTEGER,                 -- exclusive end
    file_offset INTEGER,            -- nullable file-offset alternative
    output_json TEXT,               -- structured output (caller-defined schema)
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_binary
    ON evidence_log(binary_id);
CREATE INDEX IF NOT EXISTS idx_evidence_tool
    ON evidence_log(binary_id, tool);
CREATE INDEX IF NOT EXISTS idx_evidence_va
    ON evidence_log(binary_id, va_start);

-- Stack-frame variables (#191). One row per (function, frame offset).
-- Negative offsets are below rbp (locals); positive are above (saved
-- regs / spill area / red-zone). Auto-discovery seeds rows with
-- generic names like `var_8` / `arg_10`; analyst rename overwrites
-- name/c_type and bumps set_by to "manual".
CREATE TABLE IF NOT EXISTS stack_frame_vars (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    name TEXT NOT NULL,
    c_type TEXT,
    use_count INTEGER NOT NULL DEFAULT 0,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, function_va, offset)
);
CREATE INDEX IF NOT EXISTS idx_stack_vars_func
    ON stack_frame_vars(binary_id, function_va);

-- Undo / redo log (#228). Captures the pre- and post-images of any
-- analyst-driven KB write. Auto / dwarf / flirt / propagated writes are
-- excluded — those re-derive on the next pass and don't need reversal.
-- ``undone=0`` means the row is reversible via undo(); ``undone=1``
-- means undo() already reverted it (and redo() can re-apply).
CREATE TABLE IF NOT EXISTS undo_log (
    undo_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    table_name TEXT NOT NULL,    -- function_names | comments | data_labels | stack_frame_vars
    key_json TEXT NOT NULL,      -- JSON-encoded primary key dict
    old_value_json TEXT,          -- prior row state (NULL = row didn't exist)
    new_value_json TEXT,          -- new state (NULL = deletion)
    set_by TEXT NOT NULL,
    ts INTEGER NOT NULL,
    undone INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_undo_active
    ON undo_log(binary_id, undone, ts DESC);

-- Bookmarks (#226). The "I'll come back to this" workflow, distinct
-- from per-VA comments — bookmarks index by id so the analyst can
-- name/sort them, and they carry a free-form note. Multiple bookmarks
-- per VA are allowed (different annotations on the same address).
CREATE TABLE IF NOT EXISTS bookmarks (
    bookmark_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    note TEXT NOT NULL,
    set_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bookmarks_binary
    ON bookmarks(binary_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bookmarks_va
    ON bookmarks(binary_id, va);

-- Analyst journal (#226). Project-level dated free-form notes, not
-- tied to any one VA. Useful for "today I learned X about this
-- binary" entries that are too broad for a per-VA comment.
CREATE TABLE IF NOT EXISTS journal (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    set_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_journal_binary
    ON journal(binary_id, created_at DESC);
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
    demangled: Optional[str] = None
    flavor: Optional[str] = None  # "rust" | "itanium" | "msvc" | None

    @property
    def display(self) -> str:
        """Pretty name for UI: demangled if available, else canonical."""
        return self.demangled or self.canonical


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the xref/function-name/comments tables if they're missing.

    Idempotent — runs on every open. Doesn't bump the schema_version
    (these tables are optional add-ons, present whenever the user
    actually populates them).

    Also runs forward-compatible migrations: when an older DB is opened
    it picks up new columns that recent code expects.
    """
    conn.executescript(_SCHEMA_SQL)
    cur = conn.cursor()
    # Migration: add demangled/flavor columns to function_names if missing.
    cur.execute("PRAGMA table_info(function_names)")
    cols = {row[1] for row in cur.fetchall()}
    if "demangled" not in cols:
        cur.execute("ALTER TABLE function_names ADD COLUMN demangled TEXT")
    if "flavor" not in cols:
        cur.execute("ALTER TABLE function_names ADD COLUMN flavor TEXT")
    conn.commit()


# ---------------------------------------------------------------------------
# Undo / redo (#228) — analyst trust floor.
# ---------------------------------------------------------------------------
#
# Every analyst-driven KB mutation (set_by="manual") records a row in
# undo_log capturing the prior row state. ``undo()`` walks the most
# recent active row, restores its old_value, and marks it undone.
# ``redo()`` walks the most recent undone row and re-applies new_value.
#
# Auto / dwarf / flirt / propagated writes are intentionally NOT
# captured — those re-derive on the next analysis pass and clutter the
# log if logged. The contract is "you can undo what you typed, not
# what the machine inferred."

# Maps table_name → (PK columns, all columns) used to snapshot rows.
_UNDO_TABLES = {
    "function_names": (
        ("entry_va",),
        ("entry_va", "canonical", "aliases_json", "set_by",
         "demangled", "flavor"),
    ),
    "comments": (
        ("va",),
        ("va", "body", "set_by"),
    ),
    "data_labels": (
        ("va",),
        ("va", "name", "c_type", "size", "set_by"),
    ),
    "stack_frame_vars": (
        ("function_va", "offset"),
        ("function_va", "offset", "name", "c_type", "use_count", "set_by"),
    ),
}


def _snapshot_row(
    kb: PersistentKnowledgeBase, table: str, key: dict
) -> Optional[dict]:
    """Read the current row from ``table`` keyed by ``key``. Returns
    None if no such row exists (so an undo of a fresh insert restores
    'no row')."""
    pk_cols, all_cols = _UNDO_TABLES[table]
    where = " AND ".join(f"{c}=?" for c in pk_cols) + " AND binary_id=?"
    sql = f"SELECT {','.join(all_cols)} FROM {table} WHERE {where}"
    cur = kb._conn.cursor()
    params = tuple(key[c] for c in pk_cols) + (kb.binary_id,)
    cur.execute(sql, params)
    row = cur.fetchone()
    if row is None:
        return None
    return dict(zip(all_cols, row))


def _record_undo(
    kb: PersistentKnowledgeBase,
    table: str,
    key: dict,
    old: Optional[dict],
    new: Optional[dict],
    set_by: str,
) -> None:
    """Append an undo_log entry. Only fires for set_by='manual' — other
    sources (auto/dwarf/flirt/propagated) are intentionally ignored."""
    if set_by != "manual":
        return
    if old == new:
        # No-op write, nothing to undo.
        return
    import json
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT INTO undo_log (binary_id, table_name, key_json, "
        "old_value_json, new_value_json, set_by, ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, table, json.dumps(key, sort_keys=True),
            json.dumps(old) if old is not None else None,
            json.dumps(new) if new is not None else None,
            set_by, int(time.time()),
        ),
    )


def _apply_snapshot(
    kb: PersistentKnowledgeBase,
    table: str,
    key: dict,
    snapshot: Optional[dict],
) -> None:
    """Restore ``table[key]`` to ``snapshot``. None means delete the row."""
    pk_cols, all_cols = _UNDO_TABLES[table]
    cur = kb._conn.cursor()
    if snapshot is None:
        where = " AND ".join(f"{c}=?" for c in pk_cols) + " AND binary_id=?"
        cur.execute(
            f"DELETE FROM {table} WHERE {where}",
            tuple(key[c] for c in pk_cols) + (kb.binary_id,),
        )
        return
    cols = ("binary_id",) + all_cols
    placeholders = ",".join("?" * len(cols))
    values = (kb.binary_id,) + tuple(snapshot.get(c) for c in all_cols)
    cur.execute(
        f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) "
        f"VALUES ({placeholders})",
        values,
    )


@dataclass(frozen=True)
class UndoEntry:
    undo_id: int
    table_name: str
    key: dict
    old_value: Optional[dict]
    new_value: Optional[dict]
    set_by: str
    ts: int
    undone: bool


def list_undo_log(
    kb: PersistentKnowledgeBase, *, limit: int = 50, include_undone: bool = True,
) -> List[UndoEntry]:
    """Return recent undo_log entries, newest first."""
    _ensure_schema(kb._conn)
    import json
    cur = kb._conn.cursor()
    where = "binary_id=?"
    params: tuple = (kb.binary_id,)
    if not include_undone:
        where += " AND undone=0"
    cur.execute(
        f"SELECT undo_id, table_name, key_json, old_value_json, "
        f"new_value_json, set_by, ts, undone FROM undo_log "
        f"WHERE {where} ORDER BY undo_id DESC LIMIT ?",
        params + (limit,),
    )
    out: List[UndoEntry] = []
    for row in cur.fetchall():
        out.append(UndoEntry(
            undo_id=row[0], table_name=row[1],
            key=json.loads(row[2]),
            old_value=json.loads(row[3]) if row[3] else None,
            new_value=json.loads(row[4]) if row[4] else None,
            set_by=row[5], ts=row[6], undone=bool(row[7]),
        ))
    return out


def undo(kb: PersistentKnowledgeBase, *, n: int = 1) -> List[UndoEntry]:
    """Revert the most recent N analyst-driven KB writes. Returns the
    list of undo_log entries that were applied."""
    _ensure_schema(kb._conn)
    import json
    applied: List[UndoEntry] = []
    cur = kb._conn.cursor()
    for _ in range(n):
        cur.execute(
            "SELECT undo_id, table_name, key_json, old_value_json, "
            "new_value_json, set_by, ts FROM undo_log "
            "WHERE binary_id=? AND undone=0 ORDER BY undo_id DESC LIMIT 1",
            (kb.binary_id,),
        )
        row = cur.fetchone()
        if row is None:
            break
        undo_id, table, key_json, old_json, new_json, set_by, ts = row
        key = json.loads(key_json)
        old = json.loads(old_json) if old_json else None
        new = json.loads(new_json) if new_json else None
        _apply_snapshot(kb, table, key, old)
        cur.execute(
            "UPDATE undo_log SET undone=1 WHERE undo_id=?", (undo_id,)
        )
        applied.append(UndoEntry(
            undo_id=undo_id, table_name=table, key=key,
            old_value=old, new_value=new, set_by=set_by, ts=ts, undone=True,
        ))
    kb._conn.commit()
    return applied


def redo(kb: PersistentKnowledgeBase, *, n: int = 1) -> List[UndoEntry]:
    """Re-apply the most recent N undone KB writes. Symmetric to undo()."""
    _ensure_schema(kb._conn)
    import json
    applied: List[UndoEntry] = []
    cur = kb._conn.cursor()
    for _ in range(n):
        cur.execute(
            "SELECT undo_id, table_name, key_json, old_value_json, "
            "new_value_json, set_by, ts FROM undo_log "
            "WHERE binary_id=? AND undone=1 ORDER BY undo_id ASC LIMIT 1",
            (kb.binary_id,),
        )
        row = cur.fetchone()
        if row is None:
            break
        undo_id, table, key_json, old_json, new_json, set_by, ts = row
        key = json.loads(key_json)
        old = json.loads(old_json) if old_json else None
        new = json.loads(new_json) if new_json else None
        _apply_snapshot(kb, table, key, new)
        cur.execute(
            "UPDATE undo_log SET undone=0 WHERE undo_id=?", (undo_id,)
        )
        applied.append(UndoEntry(
            undo_id=undo_id, table_name=table, key=key,
            old_value=old, new_value=new, set_by=set_by, ts=ts, undone=False,
        ))
    kb._conn.commit()
    return applied


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

    # Go binaries are stripped of regular symbols but always ship a
    # `.gopclntab` section. Walk it and upgrade every `sub_<hex>` row
    # whose entry VA matches a recovered Go function (#212). Set_by
    # is "gopclntab" so manual renames still take precedence.
    try:
        go_pairs = g.analysis.gopclntab_names_path(binary_path)
        if go_pairs:
            for va, name in go_pairs:
                cur.execute(
                    "SELECT canonical, set_by FROM function_names "
                    "WHERE binary_id = ? AND entry_va = ?",
                    (kb.binary_id, int(va)),
                )
                row = cur.fetchone()
                if row is None:
                    set_function_name(
                        kb, int(va), str(name), set_by="gopclntab",
                    )
                    continue
                # Upgrade rows the analyzer left as sub_<hex>; never
                # clobber manual / dwarf-derived names.
                cur_canon, cur_setby = row
                if cur_setby in ("manual", "dwarf"):
                    continue
                if cur_canon and not cur_canon.startswith("sub_"):
                    continue
                set_function_name(
                    kb, int(va), str(name), set_by="gopclntab",
                )
    except Exception:
        pass

    # Sweep the freshly-populated names through the demangler so the
    # display column lights up immediately. Failures here aren't fatal.
    try:
        demangle_function_names(kb)
    except Exception:
        pass
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

    key = {"entry_va": entry_va}
    old = _snapshot_row(kb, "function_names", key) if set_by == "manual" else None

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
    if set_by == "manual":
        new = _snapshot_row(kb, "function_names", key)
        _record_undo(kb, "function_names", key, old, new, set_by)
    kb._conn.commit()


def get_function_name(
    kb: PersistentKnowledgeBase, entry_va: int
) -> Optional[FunctionName]:
    _ensure_schema(kb._conn)
    import json

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_va, canonical, aliases_json, set_by, demangled, flavor "
        "FROM function_names "
        "WHERE binary_id = ? AND entry_va = ?",
        (kb.binary_id, entry_va),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return FunctionName(
        entry_va=row[0], canonical=row[1],
        aliases=json.loads(row[2] or "[]"), set_by=row[3],
        demangled=row[4], flavor=row[5],
    )


def set_demangled(
    kb: PersistentKnowledgeBase,
    entry_va: int,
    demangled: Optional[str],
    flavor: Optional[str],
) -> None:
    """Update only the demangled/flavor columns on an existing
    function_names row. No-op if the row doesn't exist yet — the
    canonical name must already be set via ``set_function_name``."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "UPDATE function_names SET demangled = ?, flavor = ? "
        "WHERE binary_id = ? AND entry_va = ?",
        (demangled, flavor, kb.binary_id, int(entry_va)),
    )
    kb._conn.commit()


def demangle_function_names(kb: PersistentKnowledgeBase) -> dict:
    """Sweep every persisted function name through the native
    demangler and store the demangled form alongside. Returns a counts
    summary so callers can report the lift.

    Idempotent — re-running just refreshes the demangled column.
    Functions whose canonical name doesn't match any known mangling
    scheme leave the demangled column NULL.
    """
    _ensure_schema(kb._conn)
    try:
        import glaurung as g
        demangle_text = g.strings.demangle_text
    except Exception:
        return {"error": "demangle_bridge_unavailable"}

    counts = {"total": 0, "rust": 0, "itanium": 0, "msvc": 0, "unrecognized": 0}
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_va, canonical FROM function_names WHERE binary_id = ?",
        (kb.binary_id,),
    )
    rows = cur.fetchall()
    for entry_va, canonical in rows:
        counts["total"] += 1
        result = demangle_text(canonical)
        if result is None:
            counts["unrecognized"] += 1
            continue
        demangled, flavor = result
        cur.execute(
            "UPDATE function_names SET demangled = ?, flavor = ? "
            "WHERE binary_id = ? AND entry_va = ?",
            (demangled, flavor, kb.binary_id, int(entry_va)),
        )
        counts[flavor] = counts.get(flavor, 0) + 1
    kb._conn.commit()
    return counts


def list_function_names(
    kb: PersistentKnowledgeBase,
) -> List[FunctionName]:
    _ensure_schema(kb._conn)
    import json

    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_va, canonical, aliases_json, set_by, demangled, flavor "
        "FROM function_names "
        "WHERE binary_id = ? ORDER BY entry_va",
        (kb.binary_id,),
    )
    return [
        FunctionName(
            entry_va=row[0], canonical=row[1],
            aliases=json.loads(row[2] or "[]"), set_by=row[3],
            demangled=row[4], flavor=row[5],
        )
        for row in cur.fetchall()
    ]


def set_comment(
    kb: PersistentKnowledgeBase, va: int, body: str,
    *, set_by: str = "manual",
) -> None:
    _ensure_schema(kb._conn)
    key = {"va": va}
    old = _snapshot_row(kb, "comments", key) if set_by == "manual" else None

    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO comments "
        "(binary_id, va, body, set_by, set_at) VALUES (?, ?, ?, ?, ?)",
        (kb.binary_id, va, body, set_by, int(time.time())),
    )
    if set_by == "manual":
        new = _snapshot_row(kb, "comments", key)
        _record_undo(kb, "comments", key, old, new, set_by)
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


# ---------------------------------------------------------------------------
# Global data labels (#181)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DataLabel:
    """Named global variable / data symbol."""
    va: int
    name: str
    c_type: Optional[str]
    size: Optional[int]
    set_by: Optional[str]


def set_data_label(
    kb: PersistentKnowledgeBase,
    va: int,
    name: str,
    *,
    c_type: Optional[str] = None,
    size: Optional[int] = None,
    set_by: str = "manual",
) -> None:
    """Persist a name for a data address. Manual entries always win
    over later automated guesses (DWARF / symbol table imports)."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by FROM data_labels WHERE binary_id = ? AND va = ?",
        (kb.binary_id, int(va)),
    )
    row = cur.fetchone()
    if row is not None and row[0] == "manual" and set_by != "manual":
        return
    key = {"va": int(va)}
    old = _snapshot_row(kb, "data_labels", key) if set_by == "manual" else None
    cur.execute(
        "INSERT OR REPLACE INTO data_labels "
        "(binary_id, va, name, c_type, size, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, int(va), name, c_type, size,
            set_by, int(time.time()),
        ),
    )
    if set_by == "manual":
        new = _snapshot_row(kb, "data_labels", key)
        _record_undo(kb, "data_labels", key, old, new, set_by)
    kb._conn.commit()


def get_data_label(
    kb: PersistentKnowledgeBase, va: int,
) -> Optional[DataLabel]:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT va, name, c_type, size, set_by FROM data_labels "
        "WHERE binary_id = ? AND va = ?",
        (kb.binary_id, int(va)),
    )
    row = cur.fetchone()
    if not row:
        return None
    return DataLabel(va=row[0], name=row[1], c_type=row[2], size=row[3], set_by=row[4])


def list_data_labels(kb: PersistentKnowledgeBase) -> List[DataLabel]:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT va, name, c_type, size, set_by FROM data_labels "
        "WHERE binary_id = ? ORDER BY va",
        (kb.binary_id,),
    )
    return [
        DataLabel(va=r[0], name=r[1], c_type=r[2], size=r[3], set_by=r[4])
        for r in cur.fetchall()
    ]


def remove_data_label(kb: PersistentKnowledgeBase, va: int) -> None:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "DELETE FROM data_labels WHERE binary_id = ? AND va = ?",
        (kb.binary_id, int(va)),
    )
    kb._conn.commit()


# ---------------------------------------------------------------------------
# Function prototypes (#172 v1)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FunctionParam:
    name: str
    c_type: str


@dataclass(frozen=True)
class FunctionPrototype:
    function_name: str
    return_type: Optional[str]
    params: List[FunctionParam]
    is_variadic: bool
    set_by: Optional[str]

    def render(self) -> str:
        """Render the prototype as a one-line C-ish declaration."""
        ret = self.return_type or "void"
        ps = [f"{p.c_type} {p.name}".strip() for p in self.params]
        if self.is_variadic:
            ps.append("...")
        param_str = ", ".join(ps) if ps else "void"
        return f"{ret} {self.function_name}({param_str})"


def set_function_prototype(
    kb: PersistentKnowledgeBase,
    function_name: str,
    return_type: Optional[str],
    params: List[FunctionParam],
    *,
    is_variadic: bool = False,
    set_by: str = "manual",
) -> None:
    """Persist a function prototype keyed by short name. Manual entries
    always win over later automated guesses (consistent with type_db /
    function_names precedence)."""
    _ensure_schema(kb._conn)
    import json
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (kb.binary_id, function_name),
    )
    row = cur.fetchone()
    if row is not None and row[0] == "manual" and set_by != "manual":
        return
    params_json = json.dumps(
        [{"name": p.name, "c_type": p.c_type} for p in params]
    )
    cur.execute(
        "INSERT OR REPLACE INTO function_prototypes "
        "(binary_id, function_name, return_type, params_json, is_variadic, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, function_name, return_type, params_json,
            1 if is_variadic else 0, set_by, int(time.time()),
        ),
    )
    kb._conn.commit()


def get_function_prototype(
    kb: PersistentKnowledgeBase, function_name: str,
) -> Optional[FunctionPrototype]:
    _ensure_schema(kb._conn)
    import json
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT function_name, return_type, params_json, is_variadic, set_by "
        "FROM function_prototypes "
        "WHERE binary_id = ? AND function_name = ?",
        (kb.binary_id, function_name),
    )
    row = cur.fetchone()
    if not row:
        return None
    raw_params = json.loads(row[2] or "[]")
    return FunctionPrototype(
        function_name=row[0],
        return_type=row[1],
        params=[FunctionParam(name=p["name"], c_type=p["c_type"]) for p in raw_params],
        is_variadic=bool(row[3]),
        set_by=row[4],
    )


def list_function_prototypes(
    kb: PersistentKnowledgeBase,
) -> List[FunctionPrototype]:
    _ensure_schema(kb._conn)
    import json
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT function_name, return_type, params_json, is_variadic, set_by "
        "FROM function_prototypes WHERE binary_id = ? ORDER BY function_name",
        (kb.binary_id,),
    )
    out: List[FunctionPrototype] = []
    for row in cur.fetchall():
        raw_params = json.loads(row[2] or "[]")
        out.append(FunctionPrototype(
            function_name=row[0], return_type=row[1],
            params=[FunctionParam(name=p["name"], c_type=p["c_type"]) for p in raw_params],
            is_variadic=bool(row[3]), set_by=row[4],
        ))
    return out


def import_stdlib_prototypes(
    kb: PersistentKnowledgeBase,
    *,
    bundles: Optional[List[str]] = None,
    bundle_dir=None,
) -> dict:
    """Load function-prototype bundles (libc/POSIX/WinAPI) into
    function_prototypes with `set_by="stdlib"`. Default bundles:
    ["stdlib-libc-protos"]."""
    import json
    from pathlib import Path as _Path
    from . import type_db as _type_db

    if bundles is None:
        bundles = ["stdlib-libc-protos", "stdlib-winapi-protos"]
    if bundle_dir is None:
        bundle_dir = _type_db._stdlib_bundle_dir()

    summary: dict = {}
    for name in bundles:
        path = _Path(bundle_dir) / f"{name}.json"
        if not path.exists():
            summary[name] = {"error": "bundle_missing", "path": str(path)}
            continue
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            summary[name] = {"error": f"parse_failed: {e}"}
            continue
        set_by = data.get("set_by", "stdlib")
        bs = {"prototypes": 0, "skipped": 0}
        for proto in data.get("prototypes", []) or []:
            if not proto.get("name"):
                bs["skipped"] += 1
                continue
            params = [
                FunctionParam(name=str(p["name"]), c_type=str(p["c_type"]))
                for p in proto.get("params", [])
            ]
            set_function_prototype(
                kb,
                function_name=str(proto["name"]),
                return_type=str(proto.get("return_type") or "void"),
                params=params,
                is_variadic=bool(proto.get("is_variadic", False)),
                set_by=set_by,
            )
            bs["prototypes"] += 1
        summary[name] = bs
    return summary


# ---------------------------------------------------------------------------
# Cross-function type propagation v2 (#195)
# ---------------------------------------------------------------------------

# Calling-convention argument-register tables. Each entry is a tuple
# (full, ...aliases) where `full` is the canonical 64-bit name we
# normalize to, and the aliases are narrower-width or alternate
# register names that target the same logical arg slot.
#
# x86_64 SysV (Linux/macOS x86_64): integer args 1-6 → rdi/rsi/rdx/rcx/r8/r9.
_SYSV_ARG_REGS_X64: List[Tuple[str, ...]] = [
    ("rdi", "edi", "di",  "dil"),
    ("rsi", "esi", "si",  "sil"),
    ("rdx", "edx", "dx",  "dl"),
    ("rcx", "ecx", "cx",  "cl"),
    ("r8",  "r8d", "r8w", "r8b"),
    ("r9",  "r9d", "r9w", "r9b"),
]

# Microsoft x64 (Windows x86_64 MSVC): integer args 1-4 → rcx/rdx/r8/r9.
# Different ordering vs SysV — rcx is arg0, not arg3 — so an MSVC binary
# analysed with the SysV table will misattribute every parameter.
_WIN64_ARG_REGS_X64: List[Tuple[str, ...]] = [
    ("rcx", "ecx", "cx",  "cl"),
    ("rdx", "edx", "dx",  "dl"),
    ("r8",  "r8d", "r8w", "r8b"),
    ("r9",  "r9d", "r9w", "r9b"),
]

# AArch64 / ARM64 AAPCS64: integer args 1-8 → x0-x7. Each x-reg has a
# 32-bit alias w-reg sharing the same logical slot.
_AAPCS64_ARG_REGS: List[Tuple[str, ...]] = [
    ("x0", "w0"), ("x1", "w1"), ("x2", "w2"), ("x3", "w3"),
    ("x4", "w4"), ("x5", "w5"), ("x6", "w6"), ("x7", "w7"),
]


def _select_arg_regs(binary_path: str) -> List[Tuple[str, ...]]:
    """Pick the right calling-convention table for `binary_path`.

    Decision tree:
      - PE / EXE on x86_64 → Win64 (rcx/rdx/r8/r9)
      - ELF/Mach-O on AArch64 → AAPCS64 (x0-x7)
      - Otherwise → SysV x86_64 (rdi/rsi/rdx/rcx/r8/r9)

    Falls back to SysV for anything we can't classify; the cost is
    misattribution on Win64/ARM64 binaries that slip past detection,
    not crashes.
    """
    try:
        import glaurung as g
        art = g.triage.analyze_path(str(binary_path), 10_000_000, 100_000_000, 1)
    except Exception:
        return _SYSV_ARG_REGS_X64
    verdicts = getattr(art, "verdicts", None) or []
    if not verdicts:
        return _SYSV_ARG_REGS_X64
    v = verdicts[0]
    fmt = (str(getattr(v, "format", "")) or "").upper()
    arch = (str(getattr(v, "arch", "")) or "").lower()

    if "aarch64" in arch or "arm64" in arch:
        return _AAPCS64_ARG_REGS
    # PE on x86_64 → Microsoft x64 calling convention.
    # Note: MinGW-built PEs use SysV instead, but the bench (and the
    # propagation pass) tolerates wrong tables — they just produce
    # zero matches. The real win is Win64-on-MSVC binaries.
    if "PE" in fmt and ("x86_64" in arch or "amd64" in arch or "x64" in arch):
        return _WIN64_ARG_REGS_X64
    return _SYSV_ARG_REGS_X64


def _operand_destination_register(
    op: str,
    arg_regs: Optional[List[Tuple[str, ...]]] = None,
) -> Optional[str]:
    """For a single operand string, return the canonical (first-element)
    register name if the operand is one of the calling convention's arg
    registers in any width. Returns None for memory operands or
    unrelated registers.

    Defaults to SysV x86_64 when no table is supplied to keep existing
    callers working; the propagation pass passes the binary-specific
    table after running `_select_arg_regs`.
    """
    if arg_regs is None:
        arg_regs = _SYSV_ARG_REGS_X64
    s = op.strip().lower()
    # Reject anything bracketed (memory operand) or with a colon prefix.
    if "[" in s or "]" in s:
        return None
    if ":" in s:
        s = s.split(":", 1)[-1].strip()
    s = s.strip()
    for entry in arg_regs:
        if s in entry:
            return entry[0]
    return None


def _operand_source_frame_offset(op: str) -> Optional[int]:
    """Reuse the stack-frame parser to extract `[rbp-N]` / `[rsp+N]`
    from a source operand."""
    return _parse_frame_offset(op)


def propagate_types_at_callsites(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    function_va: int,
    *,
    max_lookback: int = 32,
    max_instructions: int = 1024,
    window_bytes: int = 8192,
) -> int:
    """Walk every call site inside `function_va` and apply each
    callee's prototype parameter types to the originating stack-frame
    slots.

    Algorithm:
        - Disassemble the function.
        - For each `call` instruction whose target name has a known
          prototype, iterate backward up to `max_lookback` instructions
          looking for `mov <arg_reg_i>, <src>` where `src` is a stack
          slot — for each i ∈ [0, min(6, len(params))).
        - When found, write the prototype param's c_type onto
          stack_frame_vars[function_va, slot_offset]. Auto-discovered
          slots get retyped; manual slots are preserved.

    Returns the number of (slot, param) pairs whose c_type was
    refined. Fast on small functions; degrades gracefully on
    optimized code (just finds fewer matches).

    No SSA / no constant propagation in v1: a write to `rdi` between
    here and the call, or an indirect parameter load via another
    register, defeats the heuristic. v2 adds those refinements.
    """
    _ensure_schema(kb._conn)
    try:
        import glaurung as g
        ins = g.disasm.disassemble_window_at(
            str(binary_path), int(function_va),
            window_bytes=window_bytes, max_instructions=max_instructions,
        )
    except Exception:
        return 0
    if not ins:
        return 0

    # Pre-build name → prototype lookup (single SQL hit).
    protos = {p.function_name: p for p in list_function_prototypes(kb)}
    if not protos:
        return 0

    # Select the calling-convention argument-register table for this
    # binary. Win64 PE / AAPCS64 / SysV are picked from triage output.
    arg_regs = _select_arg_regs(str(binary_path))
    # Branch instruction set: x86 uses `call`, ARM uses `bl`/`blr`.
    is_arm = arg_regs is _AAPCS64_ARG_REGS
    call_mnemonics = ("bl", "blr") if is_arm else ("call",)
    move_mnemonics = ("mov", "lea") if not is_arm else ("mov", "ldr", "ldur", "adrp", "add")

    # Pre-build name → entry-VA map so we can resolve `call <hex>` to a
    # known function name when the operand is a literal address. Also
    # fold in the ELF PLT map: imported libc functions (printf, strlen,
    # ...) are reached via PLT thunks that don't appear as discovered
    # Functions, so we wouldn't otherwise resolve them.
    name_by_va: dict[int, str] = {
        n.entry_va: n.canonical for n in list_function_names(kb)
    }
    try:
        plt_pairs = g.analysis.elf_plt_map_path(
            str(binary_path), 100_000_000, 100_000_000,
        ) or []
        for va, name in plt_pairs:
            # Strip the @plt suffix so 'printf@plt' → 'printf' matches
            # the prototype bundle keys.
            clean = str(name).split("@", 1)[0]
            name_by_va.setdefault(int(va), clean)
    except Exception:
        pass

    refinements = 0
    for idx, inst in enumerate(ins):
        if inst.mnemonic.lower() not in call_mnemonics:
            continue
        # Resolve the call target name.
        target_name = _resolve_call_target_name(inst, name_by_va)
        if target_name is None:
            continue
        # Strip libc PLT decoration (`puts@plt` → `puts`) and demangler
        # noise so the prototype lookup still hits.
        clean = target_name.split("@", 1)[0]
        proto = protos.get(clean) or protos.get(target_name)
        if proto is None:
            continue

        params = proto.params[: len(arg_regs)]
        if not params:
            continue

        # Track which arg registers we've already filled so an inner
        # `mov rdi, ...` doesn't overwrite an outer `mov rdx, ...` in
        # later iterations.
        filled: dict[str, int] = {}
        lookback_end = max(0, idx - max_lookback)
        for back_idx in range(idx - 1, lookback_end - 1, -1):
            prev = ins[back_idx]
            mnem = prev.mnemonic.lower()
            if mnem in call_mnemonics or mnem in ("jmp", "b", "br"):
                # Crossed a basic-block boundary — stop scanning.
                break
            if mnem not in move_mnemonics:
                continue
            if len(prev.operands) < 2:
                continue
            dst_reg = _operand_destination_register(
                str(prev.operands[0]), arg_regs=arg_regs,
            )
            if dst_reg is None:
                continue
            src_off = _operand_source_frame_offset(str(prev.operands[1]))
            if src_off is None:
                continue
            # Match dst_reg to a parameter index.
            param_idx = next(
                (i for i, regs in enumerate(arg_regs) if regs[0] == dst_reg),
                None,
            )
            if param_idx is None or param_idx >= len(params):
                continue
            if dst_reg in filled:
                # Earlier (= closer to call) write already won.
                continue
            filled[dst_reg] = src_off

            # Refine the slot's c_type. Don't touch manual slots.
            existing = get_stack_var(kb, function_va, src_off)
            if existing is not None and existing.set_by == "manual":
                continue
            param = params[param_idx]
            set_stack_var(
                kb, function_va, src_off,
                name=(existing.name if existing else _default_var_name(src_off)),
                c_type=param.c_type,
                use_count=(existing.use_count if existing else 1),
                set_by="propagated",
            )
            refinements += 1
    return refinements


def render_decompile_with_names(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    function_va: int,
    *,
    max_blocks: int = 256,
    max_instructions: int = 10_000,
    timeout_ms: int = 500,
    style: str = "c",
    include_locals_prelude: bool = True,
    include_call_proto_hints: bool = True,
) -> str:
    """Decompile `function_va` and rewrite frame-offset references
    (`(rbp - 0x10)`, `(rbp + 8)`, `*&[rbp - 0x40]`, ...) to named
    stack-frame variables from the persistent KB.

    With `include_locals_prelude=True` (default), prepend a comment
    block listing every typed local with its declared c_type and
    provenance — partial #194 down-payment that gives the analyst /
    agent a single place to read what the function works with before
    reading the body. Each declaration carries a `// <set_by>` tag so
    DWARF-derived types are distinguishable from propagated guesses.

    Cashes in #191 stack-frame discovery + #195 type propagation
    immediately. Falls back gracefully: when no stack vars are
    populated for the function, returns the raw decompile output
    unchanged.
    """
    import glaurung as g
    import re

    raw = g.ir.decompile_at(
        str(binary_path), int(function_va),
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
        style=style,
    )
    slots = list_stack_vars(kb, function_va=function_va)
    name_by_offset: dict[int, str] = {s.offset: s.name for s in slots}

    def _resolve(off_text: str, sign: str) -> Optional[str]:
        try:
            n = int(off_text, 16) if off_text.lower().startswith("0x") else int(off_text)
        except ValueError:
            return None
        offset = -n if sign == "-" else n
        return name_by_offset.get(offset)

    # Match `(rbp - 0x10)`, `(rbp + 0x18)`, `(rbp - 272)`, `(rsp + 8)`.
    paren_re = re.compile(
        r"\((?:%?)(?:rbp|ebp|rsp|esp)\s*([+\-])\s*((?:0x)?[0-9a-fA-F]+)\)"
    )
    # Match `*&[rbp - 0x40]` and bare `[rbp - 0x40]` forms.
    bracket_re = re.compile(
        r"(\*?&?)?\[(?:%?)(?:rbp|ebp|rsp|esp)\s*([+\-])\s*((?:0x)?[0-9a-fA-F]+)\]"
    )

    out = raw

    def _paren_sub(m: "re.Match[str]") -> str:
        sign, off = m.group(1), m.group(2)
        name = _resolve(off, sign)
        if name is None:
            return m.group(0)
        # Mirror C address-of when the original was a parenthesized
        # frame address (it represents `&local`, not the value).
        return f"&{name}"

    def _bracket_sub(m: "re.Match[str]") -> str:
        prefix, sign, off = m.group(1) or "", m.group(2), m.group(3)
        name = _resolve(off, sign)
        if name is None:
            return m.group(0)
        # `[rbp - N]` is the *value* at that slot (i.e. `local`).
        # `&[rbp - N]` is the address (`&local`).
        # `*&[rbp - N]` collapses to `local` again.
        if "*" in prefix and "&" in prefix:
            return name
        if "&" in prefix:
            return f"&{name}"
        return name

    out = paren_re.sub(_paren_sub, out)
    out = bracket_re.sub(_bracket_sub, out)

    # Apply analyst-renamed function names everywhere they appear in the
    # rendered output: `sub_1080(...)` and `0x1080(...)` are common shapes
    # that the native decompiler emits when a callee has no symbol-derived
    # name. Walking the function_names table once and pre-compiling a
    # single regex per binary keeps the cost flat per call (#220).
    fn_names = list_function_names(kb)
    if fn_names:
        # Map sub_<hex> → canonical for every analyst-set entry.
        sub_map: dict[str, str] = {}
        addr_map: dict[str, str] = {}
        for fn in fn_names:
            disp = fn.display
            if not disp:
                continue
            sub_map[f"sub_{fn.entry_va:x}"] = disp
            sub_map[f"sub_{fn.entry_va:X}"] = disp
            addr_map[f"0x{fn.entry_va:x}"] = disp
            addr_map[f"0x{fn.entry_va:X}"] = disp
        if sub_map:
            sub_re = re.compile(
                r"\b(" + "|".join(re.escape(k) for k in sub_map) + r")\b"
            )
            out = sub_re.sub(lambda m: sub_map[m.group(1)], out)
        if addr_map:
            # Only rewrite addresses immediately followed by `(` so we
            # don't accidentally rename loose constants. Restrict the
            # match to call-shaped occurrences.
            addr_re = re.compile(
                r"\b(" + "|".join(re.escape(k) for k in addr_map)
                + r")(?=\s*\()"
            )
            out = addr_re.sub(lambda m: addr_map[m.group(1)], out)

    # Function-prototype hints (#227): for each call-site line, append a
    # trailing `// proto: ...` comment showing the prototype if known.
    # We skip lines that already carry a comment to avoid double-hints
    # on lines the analyst (or earlier passes) already annotated.
    if include_call_proto_hints:
        protos = list_function_prototypes(kb)
        if protos:
            proto_by_name: dict[str, "FunctionPrototype"] = {}
            for p in protos:
                proto_by_name[p.function_name] = p
            # Match `<name>(` or `<name>@plt(` with optional whitespace —
            # we only want to find the *first* call on a given line so
            # we don't hint on every nested call. Greedy match wouldn't
            # help since one rendered line is rarely longer than ~140
            # chars; just take the first hit.
            ident_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)(?:@plt)?\s*\(")
            new_lines = []
            for line in out.splitlines():
                stripped = line.split("//", 1)[0]
                if "//" in line:
                    new_lines.append(line)
                    continue
                m = ident_re.search(stripped)
                if not m:
                    new_lines.append(line)
                    continue
                name = m.group(1)
                proto = proto_by_name.get(name)
                if proto is None:
                    new_lines.append(line)
                    continue
                hint = proto.render()
                new_lines.append(f"{line.rstrip()}  // proto: {hint}")
            out = "\n".join(new_lines)
            # Preserve the original trailing newline if any.
            if raw.endswith("\n") and not out.endswith("\n"):
                out += "\n"

    if include_locals_prelude:
        prelude = _format_locals_prelude(slots)
        if prelude:
            # Inject after the first opening brace so the prelude lives
            # inside the function body. Falls back to prepending if no
            # `{` is found (defensive — the renderer should always emit one).
            brace_idx = out.find("{")
            if brace_idx >= 0:
                out = out[: brace_idx + 1] + "\n" + prelude + out[brace_idx + 1 :]
            else:
                out = prelude + "\n" + out

    return out


def _format_locals_prelude(slots: List["StackVar"]) -> str:
    """Build a `// locals (from KB)` comment block listing every named
    slot with its c_type and provenance. Skips fully-default `var_*`
    rows with no c_type (no information to surface).

    Output style is C-comment-only so the result still parses as C
    syntax for downstream tools that don't tolerate analyst metadata
    inline."""
    interesting = [
        s for s in slots
        if s.c_type or s.set_by in ("manual", "propagated", "dwarf")
    ]
    if not interesting:
        return ""
    lines = ["    // ── locals (from KB) ─────────────────────────────────"]
    for s in sorted(interesting, key=lambda s: s.offset):
        type_str = s.c_type or "(unknown)"
        tag = f"  // {s.set_by}" if s.set_by else ""
        lines.append(f"    // {s.offset:+#06x}  {type_str:<24}  {s.name}{tag}")
    lines.append("    // ─────────────────────────────────────────────────")
    return "\n".join(lines) + "\n"


def _resolve_call_target_name(
    inst, name_by_va: dict
) -> Optional[str]:
    """Try several ways the disassembler might encode a call target.
    Operand strings can be a hex literal (`0x1180`), a register
    indirection (`rax`), or a symbolic label.

    Returns the resolved name (a string), or None if the target can't
    be statically pinned down — which is the common case for indirect
    calls.
    """
    if not inst.operands:
        return None
    op = str(inst.operands[0]).strip()
    # Direct call to a literal VA.
    if op.startswith("0x") or op.startswith("0X"):
        try:
            va = int(op, 16)
        except ValueError:
            return None
        return name_by_va.get(va)
    # Some disassemblers emit a label or symbolic name directly.
    if op and not op.startswith("[") and " " not in op:
        return op
    return None


# ---------------------------------------------------------------------------
# Evidence log (#200 v0)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Evidence:
    """One row in the evidence_log: a cited tool invocation."""
    cite_id: int
    tool: str
    args: dict
    summary: str
    va_start: Optional[int]
    va_end: Optional[int]
    file_offset: Optional[int]
    output: Optional[dict]
    created_at: int


def record_evidence(
    kb: PersistentKnowledgeBase,
    tool: str,
    args: dict,
    summary: str,
    *,
    va_start: Optional[int] = None,
    va_end: Optional[int] = None,
    file_offset: Optional[int] = None,
    output: Optional[dict] = None,
) -> int:
    """Persist an evidence row and return its `cite_id`. The cite_id
    is the stable handle the agent embeds in its natural-language
    output (`[cite #42]`); the chat UI renders rows here as
    expandable evidence panes.

    `args`, `output` are dict — JSON-serialised for storage so any
    pickleable shape is acceptable. Passing complex objects that
    don't round-trip through json.dumps will raise TypeError; callers
    are expected to flatten to primitives.
    """
    import json
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT INTO evidence_log "
        "(binary_id, tool, args_json, summary, va_start, va_end, file_offset, output_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, tool,
            json.dumps(args, default=str, sort_keys=True),
            summary,
            int(va_start) if va_start is not None else None,
            int(va_end) if va_end is not None else None,
            int(file_offset) if file_offset is not None else None,
            json.dumps(output, default=str, sort_keys=True) if output is not None else None,
            int(time.time()),
        ),
    )
    cite_id = cur.lastrowid
    kb._conn.commit()
    return int(cite_id)


def get_evidence(
    kb: PersistentKnowledgeBase, cite_id: int,
) -> Optional[Evidence]:
    import json
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT cite_id, tool, args_json, summary, va_start, va_end, file_offset, output_json, created_at "
        "FROM evidence_log WHERE binary_id = ? AND cite_id = ?",
        (kb.binary_id, int(cite_id)),
    )
    row = cur.fetchone()
    if not row:
        return None
    return Evidence(
        cite_id=int(row[0]),
        tool=row[1],
        args=json.loads(row[2] or "{}"),
        summary=row[3],
        va_start=row[4],
        va_end=row[5],
        file_offset=row[6],
        output=json.loads(row[7]) if row[7] else None,
        created_at=int(row[8]),
    )


def list_evidence(
    kb: PersistentKnowledgeBase,
    *,
    tool: Optional[str] = None,
    va: Optional[int] = None,
    limit: int = 256,
) -> List[Evidence]:
    """Return evidence rows filtered by tool name and/or by VA range
    membership. Sorted newest-first so the agent picks up its most
    recent observations on a re-prompt."""
    import json
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    sql = (
        "SELECT cite_id, tool, args_json, summary, va_start, va_end, "
        "file_offset, output_json, created_at "
        "FROM evidence_log WHERE binary_id = ?"
    )
    params: list = [kb.binary_id]
    if tool is not None:
        sql += " AND tool = ?"
        params.append(tool)
    if va is not None:
        # Match rows where va_start <= va < va_end. Rows with NULL
        # va_start always pass the filter — they're whole-file evidence.
        sql += " AND (va_start IS NULL OR (va_start <= ? AND va_end > ?))"
        params.extend([int(va), int(va)])
    sql += " ORDER BY cite_id DESC LIMIT ?"
    params.append(int(limit))
    cur.execute(sql, params)
    return [
        Evidence(
            cite_id=int(r[0]), tool=r[1],
            args=json.loads(r[2] or "{}"),
            summary=r[3],
            va_start=r[4], va_end=r[5], file_offset=r[6],
            output=json.loads(r[7]) if r[7] else None,
            created_at=int(r[8]),
        )
        for r in cur.fetchall()
    ]


# ---------------------------------------------------------------------------
# Rename consistency verification (#201 v0)
# ---------------------------------------------------------------------------

# Hand-curated keyword families for #201 v0. Each family maps a set of
# *name keywords* (what an analyst might rename a function to) to a
# set of *callee keywords* (function names the rename is consistent
# with). When a rename's name keywords are dominated by callees from
# a different family, the verifier flags the inconsistency.
#
# v0 is heuristic; v1 will replace this with an LLM-driven assessment
# that reads the function's pseudocode + decides naturalistically.
_NAME_FAMILIES: List[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = [
    # (family, name keywords, callee keywords)
    ("memory_free",
     ("free", "release", "destroy", "deinit", "dealloc"),
     ("free", "delete", "release", "destroy")),
    ("memory_alloc",
     ("alloc", "create", "new", "init", "make"),
     ("malloc", "calloc", "realloc", "alloc", "new")),
    ("parse",
     ("parse", "decode", "scan", "read", "unmarshal", "deserialize", "lex"),
     ("strchr", "strrchr", "strtol", "strtoul", "strtod", "atoi", "atol",
      "strtok", "strstr", "memchr", "scanf", "sscanf", "fscanf",
      "parse", "decode")),
    ("format",
     ("format", "encode", "marshal", "serialize", "render", "build", "make"),
     ("snprintf", "sprintf", "fprintf", "printf", "asprintf", "format",
      "encode", "putchar", "fputc")),
    ("crypto",
     ("encrypt", "decrypt", "hash", "sign", "verify", "hmac", "kdf",
      "checksum", "digest"),
     ("CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData",
      "CryptDeriveKey", "EVP_", "AES_", "SHA", "MD5", "RC4")),
    ("network",
     ("send", "recv", "connect", "bind", "listen", "accept", "request",
      "fetch", "download", "upload"),
     ("send", "recv", "connect", "bind", "listen", "accept",
      "WinHttp", "Internet", "socket", "WSA")),
    ("file_io",
     ("open", "close", "load", "save", "read", "write", "import", "export"),
     ("fopen", "fclose", "fread", "fwrite", "fgets", "fputs",
      "open", "close", "read", "write", "stat",
      "CreateFile", "ReadFile", "WriteFile", "DeleteFile")),
    ("string",
     ("copy", "concat", "compare", "duplicate", "trim", "split"),
     ("strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp",
      "strdup", "memcpy", "memmove")),
    ("process",
     ("fork", "exec", "spawn", "kill", "wait", "exit"),
     ("fork", "execve", "execl", "system", "waitpid", "kill",
      "CreateProcess", "OpenProcess", "TerminateProcess")),
]


@dataclass(frozen=True)
class NameVerification:
    """Result of `verify_function_name` — heuristic consistency check
    between a (potentially newly-applied) function name and the
    function's actual callee profile."""
    entry_va: int
    name: str
    score: float                      # 0.0 (very inconsistent) … 1.0 (high consistency)
    matched_family: Optional[str]
    callee_count: int
    matching_callees: List[str]       # callees that supported the matched family
    foreign_callees: List[str]        # callees from a *different* family
    flags: List[str]                  # e.g. ["family-mismatch", "no-callees"]


def _family_for_name(name: str) -> Optional[Tuple[str, Tuple[str, ...], Tuple[str, ...]]]:
    """Map a function name to its predicted family (if any). First
    family whose name-keywords match wins; ordering above puts more
    specific families before less specific ones."""
    n = name.lower()
    for family, name_kws, callee_kws in _NAME_FAMILIES:
        for kw in name_kws:
            if kw in n:
                return (family, name_kws, callee_kws)
    return None


def verify_function_name(
    kb: PersistentKnowledgeBase, entry_va: int,
) -> Optional[NameVerification]:
    """Score whether a function's name is consistent with its callee
    profile. Returns None when the function isn't in the KB.

    Algorithm:
      1. Look up the function's canonical name.
      2. Predict the family from name keywords (memory_free, parse,
         format, crypto, ...).
      3. List the function's callees via list_xrefs_from(call kind);
         resolve dst VAs back to canonical names.
      4. Score = matching_callees / max(1, callee_count).
      5. Flag `family-mismatch` when callees suggest a *different*
         family than the name does.
      6. Flag `no-callees` when the function has zero outgoing call
         edges (in which case the score is uninformative — e.g.
         small leaf functions don't tell us much).

    The agent uses this to retract / soften high-confidence rename
    claims when the score is low.
    """
    _ensure_schema(kb._conn)
    fn = get_function_name(kb, entry_va)
    if fn is None:
        return None
    name = fn.canonical
    predicted = _family_for_name(name)

    # Pull callees (call edges from this function) via xrefs_from.
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT dst_va FROM xrefs WHERE binary_id = ? "
        "AND src_function_va = ? AND kind = ?",
        (kb.binary_id, int(entry_va), "call"),
    )
    callee_vas = [row[0] for row in cur.fetchall()]
    callee_names: List[str] = []
    for dva in callee_vas:
        cur.execute(
            "SELECT canonical, demangled FROM function_names "
            "WHERE binary_id = ? AND entry_va = ?",
            (kb.binary_id, int(dva)),
        )
        r = cur.fetchone()
        if r:
            callee_names.append(r[1] or r[0])
    # Strip @plt suffixes for matching purposes.
    callee_names_clean = [c.split("@", 1)[0] for c in callee_names]

    flags: List[str] = []
    matching: List[str] = []
    foreign: List[str] = []
    matched_family: Optional[str] = predicted[0] if predicted else None

    if predicted:
        _, _, callee_kws = predicted
        for c in callee_names_clean:
            cl = c.lower()
            if any(kw.lower() in cl for kw in callee_kws):
                matching.append(c)
            else:
                # Check if the callee is in a *different* family.
                for fam, _nkws, ckws in _NAME_FAMILIES:
                    if fam == matched_family:
                        continue
                    if any(kw.lower() in cl for kw in ckws):
                        foreign.append(c)
                        break

    score = (len(matching) / len(callee_names_clean)) if callee_names_clean else 0.5
    if not callee_names_clean:
        flags.append("no-callees")
    if predicted and foreign and not matching:
        flags.append("family-mismatch")
    if predicted and matching and foreign and len(foreign) > len(matching) * 2:
        flags.append("majority-foreign-callees")

    return NameVerification(
        entry_va=int(entry_va),
        name=name,
        score=round(score, 3),
        matched_family=matched_family,
        callee_count=len(callee_names_clean),
        matching_callees=matching[:16],
        foreign_callees=foreign[:16],
        flags=flags,
    )


def set_function_name_audited(
    kb: PersistentKnowledgeBase,
    entry_va: int,
    name: str,
    *,
    set_by: str = "manual",
    aliases: Optional[List[str]] = None,
    rationale: Optional[str] = None,
) -> tuple:
    """Rename a function and atomically record the change as evidence.

    Returns (cite_id, FunctionName-after). The evidence row's
    summary captures the before/after names so the chat UI's history
    pane shows analyst annotation chronologically.

    Behaves identically to ``set_function_name`` when the rename
    succeeds; the only difference is the evidence row that gets
    appended to evidence_log. Failures don't write evidence.
    """
    old = get_function_name(kb, entry_va)
    set_function_name(kb, entry_va, name, set_by=set_by, aliases=aliases)
    new = get_function_name(kb, entry_va)

    old_name = old.canonical if old else f"sub_{entry_va:x}"
    summary = f"renamed {old_name} → {name}" + (
        f"  ({rationale})" if rationale else ""
    )
    # Run the consistency verifier so the evidence row carries a
    # score the chat UI can surface ("⚠️ name suggests `parse_*`
    # but callees look like `free`/`destroy`...").
    verification = verify_function_name(kb, entry_va)
    output: dict = {
        "previous_set_by": old.set_by if old else None,
        "demangled": new.demangled if new else None,
    }
    if verification is not None:
        output["verification"] = {
            "score": verification.score,
            "matched_family": verification.matched_family,
            "callee_count": verification.callee_count,
            "matching_callees": verification.matching_callees,
            "foreign_callees": verification.foreign_callees,
            "flags": verification.flags,
        }
        # Attach a concise inline note when the rename looks
        # inconsistent so summaries surface the warning at the
        # cite-table level without needing to expand the row.
        if "family-mismatch" in verification.flags or (
            verification.matched_family and verification.score < 0.25
            and verification.callee_count >= 2
        ):
            summary = f"{summary}  ⚠ name vs. callees suggests inconsistency"

    cite_id = record_evidence(
        kb,
        tool="rename_function",
        args={
            "entry_va": int(entry_va),
            "old_name": old_name,
            "new_name": name,
            "set_by": set_by,
            "aliases": list(aliases or []),
            "rationale": rationale,
        },
        summary=summary,
        va_start=int(entry_va),
        va_end=int(entry_va) + 1,    # representative point; whole fn covered by 0-len range
        output=output,
    )
    return cite_id, new


def set_comment_audited(
    kb: PersistentKnowledgeBase,
    va: int,
    body: str,
    *,
    set_by: str = "manual",
) -> int:
    """Add a comment and record it as evidence. Returns cite_id."""
    set_comment(kb, va, body, set_by=set_by)
    cite_id = record_evidence(
        kb,
        tool="set_comment",
        args={"va": int(va), "body": body, "set_by": set_by},
        summary=f"comment @{va:#x}: {body[:80]}",
        va_start=int(va),
        va_end=int(va) + 1,
    )
    return cite_id


def render_evidence_markdown(evs: List[Evidence], *, max_args_chars: int = 120) -> str:
    """Compact Markdown rendering for the chat UI. Keeps the args
    JSON one-line and truncated so the cite pane stays readable."""
    if not evs:
        return "_no evidence rows_\n"
    import json
    lines = ["| cite | tool | summary | range |", "|---:|---|---|---|"]
    for e in evs:
        rng = ""
        if e.va_start is not None:
            rng = f"`{e.va_start:#x}…{e.va_end:#x}`" if e.va_end else f"`{e.va_start:#x}`"
        elif e.file_offset is not None:
            rng = f"off `{e.file_offset:#x}`"
        lines.append(
            f"| #{e.cite_id} | `{e.tool}` | {e.summary} | {rng} |"
        )
    return "\n".join(lines) + "\n"


def borrow_symbols_from_donor(
    target_kb: PersistentKnowledgeBase,
    target_binary_path: str,
    donor_binary_path: str,
    *,
    prologue_len: int = 32,
) -> dict:
    """Cross-binary symbol borrowing (#170).

    When two binaries share source code but only one ships with
    DWARF / symbols (the **donor**), transfer the donor's named
    functions onto the **target** by prologue-equality match. This is
    the on-the-fly equivalent of building a FLIRT library from one
    specific binary — useful when:
      - Vendor ships a debug build alongside a stripped release.
      - You compiled the same source twice with -g and -O2 -s.
      - You're analysing malware variants that share library code with
        a known-good binary.

    Returns a counts dict: {donor_named, target_subs, matched, applied}.
    Only renames `sub_*` placeholders in the target; never overwrites
    a name that DWARF or the symbol table already provided.
    """
    _ensure_schema(target_kb._conn)
    try:
        import glaurung as g
    except ImportError:
        return {"error": "glaurung native unavailable"}

    # Build the donor → {prologue: name} map. We reuse the same
    # 32-byte exact-equality discipline as FLIRT.
    try:
        donor_funcs, _ = g.analysis.analyze_functions_path(donor_binary_path)
        donor_bytes = open(donor_binary_path, "rb").read()
    except Exception as e:
        return {"error": f"donor_read_failed: {e}"}

    def _read_prologue(binary_path: str, va: int, raw: bytes) -> Optional[bytes]:
        try:
            off = g.analysis.va_to_file_offset_path(
                binary_path, int(va), 100_000_000, 100_000_000,
            )
        except Exception:
            return None
        if off is None:
            return None
        off = int(off)
        if off < 0 or off + prologue_len > len(raw):
            return None
        return raw[off : off + prologue_len]

    donor_named = 0
    by_prologue: dict[bytes, str] = {}
    ambiguous: set[bytes] = set()
    for f in donor_funcs:
        if f.name.startswith("sub_") or not f.basic_blocks:
            continue
        donor_named += 1
        proto = _read_prologue(donor_binary_path, int(f.entry_point.value), donor_bytes)
        if proto is None or all(b == 0 for b in proto):
            continue
        if proto in ambiguous:
            continue
        if proto in by_prologue:
            if by_prologue[proto] != f.name:
                ambiguous.add(proto)
                del by_prologue[proto]
            continue
        by_prologue[proto] = f.name

    # Now match against the target's sub_* functions.
    try:
        target_funcs, _ = g.analysis.analyze_functions_path(target_binary_path)
        target_bytes = open(target_binary_path, "rb").read()
    except Exception as e:
        return {"error": f"target_read_failed: {e}"}

    target_subs = 0
    matched = 0
    applied = 0
    for f in target_funcs:
        if not f.name.startswith("sub_"):
            continue
        target_subs += 1
        proto = _read_prologue(
            target_binary_path, int(f.entry_point.value), target_bytes,
        )
        if proto is None:
            continue
        donor_name = by_prologue.get(proto)
        if donor_name is None:
            continue
        matched += 1
        # Don't clobber non-`sub_*` names that may already be in the
        # target's xref_db (DWARF / FLIRT / manual). We only set if
        # the existing row is `sub_*` or absent.
        existing = get_function_name(target_kb, int(f.entry_point.value))
        if existing is not None and not existing.canonical.startswith("sub_") \
                and existing.set_by != "analyzer":
            continue
        set_function_name(
            target_kb, int(f.entry_point.value), donor_name, set_by="borrowed",
        )
        applied += 1

    return {
        "donor_named": donor_named,
        "donor_unique_prologues": len(by_prologue),
        "donor_ambiguous": len(ambiguous),
        "target_subs": target_subs,
        "matched": matched,
        "applied": applied,
    }


def import_data_symbols_from_binary(
    kb: PersistentKnowledgeBase, binary_path: str,
) -> int:
    """Pull every defined non-text symbol out of the binary and store
    it as a data_label with set_by="analyzer". Picks up most globals,
    .rodata strings, and statically-named arrays. No-op for stripped
    binaries.

    Returns the number of labels imported.
    """
    try:
        import glaurung as g
        pairs = g.symbol_address_map(binary_path)
    except Exception:
        return 0
    # symbol_address_map returns (va, name) tuples — but we don't know
    # which are functions vs data. Filter out names that already have a
    # function_names row at the same VA so we don't shadow them.
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_va FROM function_names WHERE binary_id = ?",
        (kb.binary_id,),
    )
    func_vas = {row[0] for row in cur.fetchall()}
    n = 0
    for va, name in pairs:
        if int(va) in func_vas:
            continue
        set_data_label(
            kb, int(va), str(name), set_by="analyzer",
        )
        n += 1
    return n


# ---------------------------------------------------------------------------
# Stack-frame variables (#191)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StackVar:
    """One stack-frame slot, named and (optionally) typed."""
    function_va: int
    offset: int            # signed: negative = below rbp (local), positive = above
    name: str              # e.g. "var_8", "arg_10", or analyst-renamed
    c_type: Optional[str]  # None until type inference / DWARF / analyst sets it
    use_count: int
    set_by: Optional[str]


def set_stack_var(
    kb: PersistentKnowledgeBase,
    function_va: int,
    offset: int,
    name: str,
    *,
    c_type: Optional[str] = None,
    use_count: int = 0,
    set_by: str = "manual",
) -> None:
    """Persist a stack-frame variable. Manual entries always win over
    later automated guesses (consistent with type_db precedence)."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by, use_count FROM stack_frame_vars "
        "WHERE binary_id = ? AND function_va = ? AND offset = ?",
        (kb.binary_id, int(function_va), int(offset)),
    )
    row = cur.fetchone()
    if row is not None and row[0] == "manual" and set_by != "manual":
        # Don't clobber analyst-renamed entries with auto-discovery;
        # but DO bump use_count if the auto pass saw it referenced.
        new_uses = max(int(row[1] or 0), int(use_count))
        cur.execute(
            "UPDATE stack_frame_vars SET use_count = ? "
            "WHERE binary_id = ? AND function_va = ? AND offset = ?",
            (new_uses, kb.binary_id, int(function_va), int(offset)),
        )
        kb._conn.commit()
        return
    key = {"function_va": int(function_va), "offset": int(offset)}
    old = (
        _snapshot_row(kb, "stack_frame_vars", key) if set_by == "manual"
        else None
    )
    cur.execute(
        "INSERT OR REPLACE INTO stack_frame_vars "
        "(binary_id, function_va, offset, name, c_type, use_count, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, int(function_va), int(offset),
            name, c_type, int(use_count), set_by, int(time.time()),
        ),
    )
    if set_by == "manual":
        new = _snapshot_row(kb, "stack_frame_vars", key)
        _record_undo(kb, "stack_frame_vars", key, old, new, set_by)
    kb._conn.commit()


def get_stack_var(
    kb: PersistentKnowledgeBase, function_va: int, offset: int,
) -> Optional[StackVar]:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT function_va, offset, name, c_type, use_count, set_by "
        "FROM stack_frame_vars "
        "WHERE binary_id = ? AND function_va = ? AND offset = ?",
        (kb.binary_id, int(function_va), int(offset)),
    )
    row = cur.fetchone()
    if not row:
        return None
    return StackVar(
        function_va=row[0], offset=row[1], name=row[2],
        c_type=row[3], use_count=int(row[4] or 0), set_by=row[5],
    )


def list_stack_vars(
    kb: PersistentKnowledgeBase, function_va: Optional[int] = None,
) -> List[StackVar]:
    """Return every stack-frame variable, optionally filtered to one
    function. Sorted by (function_va, offset) so locals (negative
    offsets) come before parameters (positive)."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    if function_va is None:
        cur.execute(
            "SELECT function_va, offset, name, c_type, use_count, set_by "
            "FROM stack_frame_vars "
            "WHERE binary_id = ? ORDER BY function_va, offset",
            (kb.binary_id,),
        )
    else:
        cur.execute(
            "SELECT function_va, offset, name, c_type, use_count, set_by "
            "FROM stack_frame_vars "
            "WHERE binary_id = ? AND function_va = ? ORDER BY offset",
            (kb.binary_id, int(function_va)),
        )
    return [
        StackVar(
            function_va=r[0], offset=r[1], name=r[2],
            c_type=r[3], use_count=int(r[4] or 0), set_by=r[5],
        )
        for r in cur.fetchall()
    ]


def _default_var_name(offset: int) -> str:
    """Conventional placeholder name. IDA-style: `var_<hex>` for negative
    offsets (locals), `arg_<hex>` for positive offsets (parameters)."""
    if offset < 0:
        return f"var_{(-offset):x}"
    return f"arg_{offset:x}"


def discover_stack_vars(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    function_va: int,
    *,
    max_instructions: int = 1024,
    window_bytes: int = 4096,
) -> int:
    """Disassemble a function and populate stack_frame_vars from every
    `[rbp + N]` / `[rsp + N]` reference seen.

    Returns the number of unique slots discovered. Idempotent: re-running
    refreshes use_count without overwriting analyst-renamed entries.

    The pass is intentionally simple — no data-flow tracking, no SSA.
    Just textual operand parsing of the disassembler's `Instruction`
    output. Good enough to seed names; #172 will refine types later.
    """
    import glaurung as g
    try:
        ins = g.disasm.disassemble_window_at(
            str(binary_path), int(function_va),
            window_bytes=window_bytes, max_instructions=max_instructions,
        )
    except Exception:
        return 0

    # Aggregate offset → use count.
    seen: dict[int, int] = {}
    for i in ins:
        for op in i.operands:
            off = _parse_frame_offset(str(op))
            if off is not None:
                seen[off] = seen.get(off, 0) + 1

    for off, count in seen.items():
        set_stack_var(
            kb, function_va, off, _default_var_name(off),
            use_count=count, set_by="auto",
        )
    return len(seen)


def _parse_frame_offset(op: str) -> Optional[int]:
    """Extract a signed integer offset from operand strings shaped like
    ``rbp:[rbp - 0x10]``, ``[rbp+0x18]``, ``rsp:[rsp - 0x40]``. Returns
    None if the operand isn't a frame-relative memory reference.

    We treat rbp and rsp as the only legitimate frame bases. Skipping
    rsp-relative refs entirely would miss frame-pointer-omitted
    functions (very common at -O2); including them costs us occasional
    false positives when rsp moves mid-function, which the bench will
    surface if it becomes a real issue.
    """
    s = op.strip()
    # Look for the bracket part.
    lb = s.find("[")
    rb = s.find("]", lb + 1) if lb >= 0 else -1
    if lb < 0 or rb < 0:
        return None
    inner = s[lb + 1 : rb].strip()
    # Split on +/- preserving sign.
    base, sep, rest = _split_signed(inner)
    if not base or sep is None:
        return None
    base = base.strip().lower()
    if base not in ("rbp", "rsp", "ebp", "esp"):
        return None
    rest = rest.strip()
    try:
        if rest.startswith("0x") or rest.startswith("0X"):
            magnitude = int(rest, 16)
        else:
            magnitude = int(rest, 10)
    except ValueError:
        return None
    return -magnitude if sep == "-" else magnitude


def _split_signed(s: str) -> Tuple[str, Optional[str], str]:
    """Split `'rbp - 0x10'` → ('rbp', '-', '0x10').
    Returns ('', None, '') if no signed split point is found."""
    # Find first + or - that's not at position 0.
    for i in range(1, len(s)):
        c = s[i]
        if c in ("+", "-"):
            return s[:i].strip(), c, s[i + 1 :].strip()
    return "", None, ""


# ---------------------------------------------------------------------------
# Bookmarks + journal (#226).
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Bookmark:
    bookmark_id: int
    va: int
    note: str
    set_by: str
    created_at: int


@dataclass(frozen=True)
class JournalEntry:
    entry_id: int
    body: str
    set_by: str
    created_at: int


def add_bookmark(
    kb: PersistentKnowledgeBase, va: int, note: str,
    *, set_by: str = "manual",
) -> int:
    """Add a bookmark at ``va`` with a free-form note. Returns the
    new bookmark_id so the analyst can reference it later. Multiple
    bookmarks per VA are allowed."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT INTO bookmarks (binary_id, va, note, set_by, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (kb.binary_id, int(va), note, set_by, int(time.time())),
    )
    bookmark_id = int(cur.lastrowid or 0)
    kb._conn.commit()
    return bookmark_id


def list_bookmarks(
    kb: PersistentKnowledgeBase, *, va: Optional[int] = None,
) -> List[Bookmark]:
    """Return all bookmarks for the binary, newest first. If ``va``
    is given, only bookmarks at that exact VA."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    if va is None:
        cur.execute(
            "SELECT bookmark_id, va, note, set_by, created_at "
            "FROM bookmarks WHERE binary_id = ? ORDER BY created_at DESC, bookmark_id DESC",
            (kb.binary_id,),
        )
    else:
        cur.execute(
            "SELECT bookmark_id, va, note, set_by, created_at "
            "FROM bookmarks WHERE binary_id = ? AND va = ? "
            "ORDER BY created_at DESC, bookmark_id DESC",
            (kb.binary_id, int(va)),
        )
    return [
        Bookmark(
            bookmark_id=r[0], va=r[1], note=r[2],
            set_by=r[3], created_at=r[4],
        )
        for r in cur.fetchall()
    ]


def delete_bookmark(kb: PersistentKnowledgeBase, bookmark_id: int) -> bool:
    """Remove a single bookmark by id. Returns True if a row was
    deleted, False if the id wasn't found."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "DELETE FROM bookmarks WHERE binary_id = ? AND bookmark_id = ?",
        (kb.binary_id, int(bookmark_id)),
    )
    deleted = cur.rowcount > 0
    kb._conn.commit()
    return deleted


def add_journal_entry(
    kb: PersistentKnowledgeBase, body: str,
    *, set_by: str = "manual",
) -> int:
    """Append a journal entry. Returns the new entry_id."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT INTO journal (binary_id, body, set_by, created_at) "
        "VALUES (?, ?, ?, ?)",
        (kb.binary_id, body, set_by, int(time.time())),
    )
    entry_id = int(cur.lastrowid or 0)
    kb._conn.commit()
    return entry_id


def list_journal(
    kb: PersistentKnowledgeBase, *, limit: int = 50,
) -> List[JournalEntry]:
    """Return the N most recent journal entries, newest first."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT entry_id, body, set_by, created_at FROM journal "
        "WHERE binary_id = ? ORDER BY created_at DESC, entry_id DESC LIMIT ?",
        (kb.binary_id, limit),
    )
    return [
        JournalEntry(
            entry_id=r[0], body=r[1], set_by=r[2], created_at=r[3],
        )
        for r in cur.fetchall()
    ]


def delete_journal_entry(kb: PersistentKnowledgeBase, entry_id: int) -> bool:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "DELETE FROM journal WHERE binary_id = ? AND entry_id = ?",
        (kb.binary_id, int(entry_id)),
    )
    deleted = cur.rowcount > 0
    kb._conn.commit()
    return deleted
