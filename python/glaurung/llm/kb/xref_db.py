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
    cur.execute(
        "INSERT OR REPLACE INTO data_labels "
        "(binary_id, va, name, c_type, size, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, int(va), name, c_type, size,
            set_by, int(time.time()),
        ),
    )
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
) -> str:
    """Decompile `function_va` and rewrite frame-offset references
    (`(rbp - 0x10)`, `(rbp + 8)`, `*&[rbp - 0x40]`, ...) to named
    stack-frame variables from the persistent KB.

    A user calling this in the REPL sees `argc` instead of `(rbp -
    0x14)`, and `*request_table` instead of `*&[rbp - 0xa0]`. Cashes in
    #191 stack-frame discovery + #195 type propagation immediately.

    Falls back gracefully: when no stack vars are populated for the
    function, returns the raw decompile output unchanged.
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
    if not slots:
        return raw
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
    return out


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
    cur.execute(
        "INSERT OR REPLACE INTO stack_frame_vars "
        "(binary_id, function_va, offset, name, c_type, use_count, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, int(function_va), int(offset),
            name, c_type, int(use_count), set_by, int(time.time()),
        ),
    )
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
