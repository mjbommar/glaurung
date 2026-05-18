"""Persistent intra-function CFG facts for PE projects.

The native analyser already recovers basic blocks on demand. This module
persists those blocks into the project SQLite database so later tools can
query CFG coverage without re-running function recovery.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from .persistent import PersistentKnowledgeBase


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS basic_blocks (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    start_va INTEGER NOT NULL,
    end_va INTEGER NOT NULL,
    instruction_count INTEGER NOT NULL,
    is_entry INTEGER NOT NULL DEFAULT 0,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id)
);
CREATE INDEX IF NOT EXISTS idx_basic_blocks_function
    ON basic_blocks(binary_id, function_va);
CREATE INDEX IF NOT EXISTS idx_basic_blocks_range
    ON basic_blocks(binary_id, start_va, end_va);

CREATE TABLE IF NOT EXISTS cfg_edges (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    src_block_id TEXT NOT NULL,
    dst_block_id TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'cfg',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, src_block_id, dst_block_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_cfg_edges_function
    ON cfg_edges(binary_id, function_va);

CREATE TABLE IF NOT EXISTS cfg_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    function_count INTEGER NOT NULL,
    block_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class CfgIndexCounts:
    function_count: int = 0
    block_count: int = 0
    edge_count: int = 0


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
    conn.commit()


def is_indexed(kb: PersistentKnowledgeBase) -> bool:
    """Return True when CFG facts have been indexed for this binary."""
    _ensure_schema(kb._conn)
    row = kb._conn.execute(
        "SELECT 1 FROM cfg_index_state WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    return row is not None


def cfg_counts(kb: PersistentKnowledgeBase) -> CfgIndexCounts:
    """Return persisted CFG counts for the current binary."""
    _ensure_schema(kb._conn)
    row = kb._conn.execute(
        "SELECT function_count, block_count, edge_count FROM cfg_index_state "
        "WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    if row is None:
        return CfgIndexCounts()
    return CfgIndexCounts(
        function_count=int(row[0]),
        block_count=int(row[1]),
        edge_count=int(row[2]),
    )


def index_cfg(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    *,
    force: bool = False,
    max_read_bytes: int = 104_857_600,
    max_file_size: int = 104_857_600,
    max_functions: int = 30_000,
    max_blocks: int = 1_000_000,
    max_instructions: int = 30_000_000,
    timeout_ms: int = 600_000,
) -> int:
    """Persist native basic blocks and CFG edges.

    Returns the number of basic-block rows currently available for this binary.
    The index is idempotent unless ``force`` is true.
    """
    _ensure_schema(kb._conn)
    if is_indexed(kb) and not force:
        return cfg_counts(kb).block_count

    import glaurung as g

    funcs, _cg = g.analysis.analyze_functions_path(
        binary_path,
        max_read_bytes,
        max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    now = int(time.time())
    block_rows: list[tuple[int, int, str, int, int, int, int, int]] = []
    edge_rows: list[tuple[int, int, str, str, str, int]] = []
    function_count = 0

    for func in funcs:
        function_va = int(getattr(getattr(func, "entry_point", 0), "value", 0) or 0)
        blocks = list(getattr(func, "basic_blocks", []) or [])
        if not function_va or not blocks:
            continue
        function_count += 1
        entry_id = _entry_block_id(blocks)
        valid_ids = {str(getattr(block, "id")) for block in blocks}
        for block in blocks:
            block_id = str(getattr(block, "id"))
            block_rows.append(
                (
                    kb.binary_id,
                    function_va,
                    block_id,
                    int(getattr(getattr(block, "start_address"), "value")),
                    int(getattr(getattr(block, "end_address"), "value")),
                    int(getattr(block, "instruction_count", 0) or 0),
                    1 if block_id == entry_id else 0,
                    now,
                )
            )
            for dst in getattr(block, "successor_ids", []) or []:
                dst_id = str(dst)
                if dst_id not in valid_ids:
                    continue
                edge_rows.append(
                    (kb.binary_id, function_va, block_id, dst_id, "cfg", now)
                )

    cur = kb._conn.cursor()
    cur.execute("BEGIN")
    try:
        if force:
            cur.execute(
                "DELETE FROM basic_blocks WHERE binary_id = ?",
                (kb.binary_id,),
            )
            cur.execute(
                "DELETE FROM cfg_edges WHERE binary_id = ?",
                (kb.binary_id,),
            )
            cur.execute(
                "DELETE FROM cfg_index_state WHERE binary_id = ?",
                (kb.binary_id,),
            )
        cur.executemany(
            "INSERT OR REPLACE INTO basic_blocks "
            "(binary_id, function_va, block_id, start_va, end_va, "
            "instruction_count, is_entry, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            block_rows,
        )
        cur.executemany(
            "INSERT OR REPLACE INTO cfg_edges "
            "(binary_id, function_va, src_block_id, dst_block_id, kind, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            edge_rows,
        )
        cur.execute(
            "INSERT OR REPLACE INTO cfg_index_state "
            "(binary_id, indexed_at, function_count, block_count, edge_count) "
            "VALUES (?, ?, ?, ?, ?)",
            (kb.binary_id, now, function_count, len(block_rows), len(edge_rows)),
        )
        kb._conn.commit()
    except Exception:
        kb._conn.rollback()
        raise
    return len(block_rows)


def _entry_block_id(blocks: list[object]) -> str | None:
    no_preds = [
        block for block in blocks if not (getattr(block, "predecessor_ids", []) or [])
    ]
    candidates = no_preds or blocks
    if not candidates:
        return None
    block = min(
        candidates,
        key=lambda item: int(getattr(getattr(item, "start_address"), "value")),
    )
    return str(getattr(block, "id"))
