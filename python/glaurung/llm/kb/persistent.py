"""SQLite-backed KnowledgeBase persistence.

Inherits :class:`KnowledgeBase`'s API so every existing tool that
queries or mutates the in-memory KB keeps working unchanged. The
SQLite layer is a write-through cache for reads (the in-memory
indexes are populated on open) and a buffered writer for mutations
(``add_node`` / ``add_edge`` / ``tag_node`` mutate in memory; the
explicit ``save()`` call commits the diff to disk in one transaction).

Schema is documented in ``docs/architecture/PERSISTENT_PROJECT.md``.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .models import Edge, Node, NodeKind
from .store import KnowledgeBase


SCHEMA_VERSION = "1"


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS binaries (
    binary_id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE,
    first_path TEXT,
    format TEXT,
    arch TEXT,
    bits INTEGER,
    size_bytes INTEGER,
    discovered_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id INTEGER PRIMARY KEY,
    binary_id INTEGER REFERENCES binaries(binary_id),
    name TEXT NOT NULL,
    created_at INTEGER,
    UNIQUE (binary_id, name)
);

CREATE TABLE IF NOT EXISTS kb_nodes (
    node_pk INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(session_id),
    node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    label TEXT,
    text TEXT,
    props_json TEXT NOT NULL DEFAULT '{}',
    tags_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (session_id, node_id)
);

CREATE TABLE IF NOT EXISTS kb_edges (
    edge_pk INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(session_id),
    edge_id TEXT NOT NULL,
    src_node_id TEXT NOT NULL,
    dst_node_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    props_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (session_id, edge_id)
);

CREATE TABLE IF NOT EXISTS kb_node_tags (
    node_pk INTEGER REFERENCES kb_nodes(node_pk) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (node_pk, tag)
);

CREATE INDEX IF NOT EXISTS idx_nodes_session_kind
    ON kb_nodes(session_id, kind);
CREATE INDEX IF NOT EXISTS idx_nodes_session_label
    ON kb_nodes(session_id, label);
CREATE INDEX IF NOT EXISTS idx_edges_session_src
    ON kb_edges(session_id, src_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_session_dst
    ON kb_edges(session_id, dst_node_id);
"""


def _file_sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class PersistentKnowledgeBase(KnowledgeBase):
    """KnowledgeBase that loads from / saves to a SQLite file.

    Usage::

        kb = PersistentKnowledgeBase.open("malware.glaurung",
                                         binary_path="malware.elf")
        # ...mutate via the inherited add_node/add_edge/tag_node API...
        kb.save()
        kb.close()

    Or as a context manager (auto-saves on clean exit)::

        with PersistentKnowledgeBase.open(...) as kb:
            ...
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        session_id: int,
        binary_id: int,
        path: Path,
    ) -> None:
        super().__init__()
        self._conn = conn
        self._session_id = session_id
        self._binary_id = binary_id
        self._path = path
        # Track which (session_id, node_id) and edge_id rows we've
        # already persisted so save() only writes the new diff.
        self._persisted_nodes: set[str] = set()
        self._persisted_edges: set[str] = set()

    # ------------------------------------------------------------------
    # Open / create
    # ------------------------------------------------------------------

    @classmethod
    def open(
        cls,
        path: str | Path,
        binary_path: str | Path | None = None,
        session: str = "main",
        *,
        auto_load_stdlib: bool = False,
    ) -> "PersistentKnowledgeBase":
        """Open or create a glaurung database. When the file does not
        exist, a fresh schema is initialised. ``binary_path`` is
        required only for new files (the binary's sha256 anchors the
        ``binaries`` row); existing files locate their binary by
        sha256 already stored.
        """
        path = Path(path)
        first_open = not path.exists()
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(_SCHEMA_SQL)
        # Set the schema version on first creation.
        cur = conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", SCHEMA_VERSION),
        )
        conn.commit()

        # Verify version compatibility.
        cur.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        )
        row = cur.fetchone()
        on_disk = row[0] if row else SCHEMA_VERSION
        if on_disk != SCHEMA_VERSION:
            conn.close()
            raise RuntimeError(
                f"glaurung db at {path} has schema_version={on_disk!r} "
                f"but this build expects {SCHEMA_VERSION!r}; "
                "migrations are not yet implemented"
            )

        # Resolve / create the binary record.
        if binary_path is None and first_open:
            conn.close()
            raise ValueError(
                f"creating a new database at {path} requires binary_path"
            )
        binary_id = cls._resolve_binary(conn, binary_path)
        # Resolve / create session row.
        session_id = cls._resolve_session(conn, binary_id, session)

        kb = cls(conn, session_id, binary_id, path)
        kb._load_from_disk()
        # On first open of a fresh DB, optionally auto-import canonical
        # stdlib type definitions (libc, WinAPI, ...) so the type system
        # has baseline knowledge before any analysis runs. Off by default
        # to keep existing test assertions clean — production callers
        # (REPL, bench harness, recover_source) pass auto_load_stdlib=True.
        if first_open and auto_load_stdlib:
            try:
                from . import type_db as _type_db
                _type_db.import_stdlib_types(kb)
            except Exception:
                # Stdlib bundles are optional — never block KB open.
                pass
            try:
                from . import xref_db as _xref_db
                _xref_db.import_stdlib_prototypes(kb)
            except Exception:
                pass
        return kb

    @staticmethod
    def _resolve_binary(
        conn: sqlite3.Connection,
        binary_path: str | Path | None,
    ) -> int:
        cur = conn.cursor()
        if binary_path is None:
            # Pick the most-recently-discovered binary in the file.
            cur.execute(
                "SELECT binary_id FROM binaries ORDER BY discovered_at DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row is None:
                conn.close()
                raise ValueError(
                    "database has no binaries and no binary_path given"
                )
            return row[0]
        bp = Path(binary_path)
        sha = _file_sha256(bp)
        cur.execute("SELECT binary_id FROM binaries WHERE sha256 = ?", (sha,))
        row = cur.fetchone()
        if row is not None:
            return row[0]
        cur.execute(
            "INSERT INTO binaries "
            "(sha256, first_path, size_bytes, discovered_at) "
            "VALUES (?, ?, ?, ?)",
            (sha, str(bp.resolve()), bp.stat().st_size, int(time.time())),
        )
        conn.commit()
        return cur.lastrowid

    @staticmethod
    def _resolve_session(
        conn: sqlite3.Connection, binary_id: int, name: str
    ) -> int:
        cur = conn.cursor()
        cur.execute(
            "SELECT session_id FROM sessions WHERE binary_id = ? AND name = ?",
            (binary_id, name),
        )
        row = cur.fetchone()
        if row is not None:
            return row[0]
        cur.execute(
            "INSERT INTO sessions (binary_id, name, created_at) VALUES (?, ?, ?)",
            (binary_id, name, int(time.time())),
        )
        conn.commit()
        return cur.lastrowid

    # ------------------------------------------------------------------
    # Load existing rows into the in-memory indexes
    # ------------------------------------------------------------------

    def _load_from_disk(self) -> None:
        """Hydrate the inherited in-memory KB from the session's rows."""
        cur = self._conn.cursor()
        cur.execute(
            "SELECT node_id, kind, label, text, props_json, tags_json "
            "FROM kb_nodes WHERE session_id = ?",
            (self._session_id,),
        )
        for node_id, kind, label, text, props_json, tags_json in cur.fetchall():
            try:
                kind_enum = NodeKind(kind)
            except ValueError:
                continue  # forward-compat: skip unknown kinds
            n = Node(
                id=node_id,
                kind=kind_enum,
                label=label or "",
                text=text,
                props=json.loads(props_json) if props_json else {},
                tags=json.loads(tags_json) if tags_json else [],
            )
            super().add_node(n)
            self._persisted_nodes.add(node_id)
        cur.execute(
            "SELECT edge_id, src_node_id, dst_node_id, kind, props_json "
            "FROM kb_edges WHERE session_id = ?",
            (self._session_id,),
        )
        for edge_id, src, dst, kind, props_json in cur.fetchall():
            e = Edge(
                id=edge_id, src=src, dst=dst, kind=kind,
                props=json.loads(props_json) if props_json else {},
            )
            try:
                super().add_edge(e)
                self._persisted_edges.add(edge_id)
            except ValueError:
                # Endpoint missing — likely a forward-compat skip above.
                continue

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Commit every in-memory mutation since the last save() to
        SQLite in a single transaction. Idempotent — calling twice in
        a row writes nothing the second time."""
        cur = self._conn.cursor()
        cur.execute("BEGIN")
        try:
            for n in self.nodes():
                if n.id in self._persisted_nodes:
                    # Update path: attributes may have changed.
                    cur.execute(
                        "UPDATE kb_nodes SET kind=?, label=?, text=?, "
                        "props_json=?, tags_json=? "
                        "WHERE session_id=? AND node_id=?",
                        (
                            n.kind.value, n.label, n.text,
                            json.dumps(n.props), json.dumps(n.tags),
                            self._session_id, n.id,
                        ),
                    )
                else:
                    cur.execute(
                        "INSERT INTO kb_nodes "
                        "(session_id, node_id, kind, label, text, "
                        "props_json, tags_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            self._session_id, n.id, n.kind.value,
                            n.label, n.text,
                            json.dumps(n.props), json.dumps(n.tags),
                        ),
                    )
                    self._persisted_nodes.add(n.id)
                # Re-write tags index (small set; cheap).
                cur.execute(
                    "DELETE FROM kb_node_tags WHERE node_pk = ("
                    "SELECT node_pk FROM kb_nodes "
                    "WHERE session_id=? AND node_id=?)",
                    (self._session_id, n.id),
                )
                if n.tags:
                    cur.execute(
                        "SELECT node_pk FROM kb_nodes "
                        "WHERE session_id=? AND node_id=?",
                        (self._session_id, n.id),
                    )
                    pk_row = cur.fetchone()
                    if pk_row is not None:
                        pk = pk_row[0]
                        for t in n.tags:
                            cur.execute(
                                "INSERT OR IGNORE INTO kb_node_tags "
                                "(node_pk, tag) VALUES (?, ?)",
                                (pk, t),
                            )
            for e in self.edges():
                if e.id in self._persisted_edges:
                    cur.execute(
                        "UPDATE kb_edges SET src_node_id=?, dst_node_id=?, "
                        "kind=?, props_json=? "
                        "WHERE session_id=? AND edge_id=?",
                        (
                            e.src, e.dst, e.kind, json.dumps(e.props),
                            self._session_id, e.id,
                        ),
                    )
                else:
                    cur.execute(
                        "INSERT INTO kb_edges "
                        "(session_id, edge_id, src_node_id, dst_node_id, "
                        "kind, props_json) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            self._session_id, e.id, e.src, e.dst, e.kind,
                            json.dumps(e.props),
                        ),
                    )
                    self._persisted_edges.add(e.id)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Resource management
    # ------------------------------------------------------------------

    def close(self) -> None:
        try:
            self.save()
        finally:
            self._conn.close()

    def __enter__(self) -> "PersistentKnowledgeBase":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.save()
        self._conn.close()

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def binary_id(self) -> int:
        return self._binary_id

    @property
    def session_id(self) -> int:
        return self._session_id

    def list_binaries(self) -> List[Tuple[int, str, Optional[str]]]:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT binary_id, sha256, first_path FROM binaries "
            "ORDER BY discovered_at"
        )
        return [(bid, sha, path) for bid, sha, path in cur.fetchall()]

    def list_sessions(self) -> List[Tuple[int, str, int]]:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT session_id, name, created_at FROM sessions "
            "WHERE binary_id = ? ORDER BY created_at",
            (self._binary_id,),
        )
        return [(sid, name, created) for sid, name, created in cur.fetchall()]
