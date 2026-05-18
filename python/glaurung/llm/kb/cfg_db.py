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

CREATE TABLE IF NOT EXISTS cfg_dominance (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    immediate_dominator_id TEXT,
    immediate_post_dominator_id TEXT,
    reachable_from_entry INTEGER NOT NULL,
    can_reach_exit INTEGER NOT NULL,
    dominator_count INTEGER NOT NULL,
    post_dominator_count INTEGER NOT NULL,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id)
);
CREATE INDEX IF NOT EXISTS idx_cfg_dominance_function
    ON cfg_dominance(binary_id, function_va);

CREATE TABLE IF NOT EXISTS cfg_dominance_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    function_count INTEGER NOT NULL,
    block_count INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class CfgIndexCounts:
    function_count: int = 0
    block_count: int = 0
    edge_count: int = 0


@dataclass(frozen=True)
class CfgDominanceCounts:
    function_count: int = 0
    block_count: int = 0


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


def is_dominance_indexed(kb: PersistentKnowledgeBase) -> bool:
    """Return True when CFG dominance summaries exist for this binary."""
    _ensure_schema(kb._conn)
    row = kb._conn.execute(
        "SELECT 1 FROM cfg_dominance_index_state WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    return row is not None


def cfg_dominance_counts(kb: PersistentKnowledgeBase) -> CfgDominanceCounts:
    """Return persisted CFG dominance-summary counts for the current binary."""
    _ensure_schema(kb._conn)
    row = kb._conn.execute(
        "SELECT function_count, block_count FROM cfg_dominance_index_state "
        "WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    if row is None:
        return CfgDominanceCounts()
    return CfgDominanceCounts(function_count=int(row[0]), block_count=int(row[1]))


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
            cur.execute(
                "DELETE FROM cfg_dominance WHERE binary_id = ?",
                (kb.binary_id,),
            )
            cur.execute(
                "DELETE FROM cfg_dominance_index_state WHERE binary_id = ?",
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


def index_cfg_dominance(
    kb: PersistentKnowledgeBase,
    *,
    force: bool = False,
) -> int:
    """Precompute dominator and post-dominator summaries for persisted CFGs.

    Returns the number of block-summary rows currently available. This requires
    ``index_cfg`` to have already populated ``basic_blocks`` and ``cfg_edges``.
    """
    _ensure_schema(kb._conn)
    if is_dominance_indexed(kb) and not force:
        return cfg_dominance_counts(kb).block_count

    functions = [
        int(row[0])
        for row in kb._conn.execute(
            "SELECT DISTINCT function_va FROM basic_blocks "
            "WHERE binary_id = ? ORDER BY function_va",
            (kb.binary_id,),
        ).fetchall()
    ]
    now = int(time.time())
    rows: list[tuple[int, int, str, str | None, str | None, int, int, int, int, int]] = []
    covered_functions = 0
    for function_va in functions:
        summaries = _dominance_rows_for_function(kb._conn, kb.binary_id, function_va)
        if not summaries:
            continue
        covered_functions += 1
        for summary in summaries:
            rows.append((kb.binary_id, function_va, *summary, now))

    cur = kb._conn.cursor()
    cur.execute("BEGIN")
    try:
        if force:
            cur.execute(
                "DELETE FROM cfg_dominance WHERE binary_id = ?",
                (kb.binary_id,),
            )
            cur.execute(
                "DELETE FROM cfg_dominance_index_state WHERE binary_id = ?",
                (kb.binary_id,),
            )
        cur.executemany(
            "INSERT OR REPLACE INTO cfg_dominance "
            "(binary_id, function_va, block_id, immediate_dominator_id, "
            "immediate_post_dominator_id, reachable_from_entry, can_reach_exit, "
            "dominator_count, post_dominator_count, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        cur.execute(
            "INSERT OR REPLACE INTO cfg_dominance_index_state "
            "(binary_id, indexed_at, function_count, block_count) "
            "VALUES (?, ?, ?, ?)",
            (kb.binary_id, now, covered_functions, len(rows)),
        )
        kb._conn.commit()
    except Exception:
        kb._conn.rollback()
        raise
    return len(rows)


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


def _dominance_rows_for_function(
    conn: sqlite3.Connection,
    binary_id: int,
    function_va: int,
) -> list[tuple[str, str | None, str | None, int, int, int, int]]:
    block_rows = conn.execute(
        "SELECT block_id, is_entry FROM basic_blocks "
        "WHERE binary_id = ? AND function_va = ? ORDER BY start_va",
        (binary_id, function_va),
    ).fetchall()
    if not block_rows:
        return []
    ids = [str(row[0]) for row in block_rows]
    id_set = set(ids)
    entry_rows = [str(row[0]) for row in block_rows if int(row[1]) == 1]
    entry_id = entry_rows[0] if entry_rows else ids[0]

    successors = {block_id: set[str]() for block_id in ids}
    predecessors = {block_id: set[str]() for block_id in ids}
    for src, dst in conn.execute(
        "SELECT src_block_id, dst_block_id FROM cfg_edges "
        "WHERE binary_id = ? AND function_va = ?",
        (binary_id, function_va),
    ).fetchall():
        src_id = str(src)
        dst_id = str(dst)
        if src_id not in id_set or dst_id not in id_set:
            continue
        successors[src_id].add(dst_id)
        predecessors[dst_id].add(src_id)

    reachable = _reachable({entry_id}, successors)
    exits = {block_id for block_id, succs in successors.items() if not succs}
    can_reach_exit = _reachable(exits, predecessors) if exits else set()

    dominators = _fixed_point_dominators(ids, entry_id, predecessors, reachable)
    post_dominators = _fixed_point_post_dominators(
        ids,
        exits,
        successors,
        can_reach_exit,
    )

    rows = []
    for block_id in ids:
        doms = dominators.get(block_id, {block_id})
        post_doms = post_dominators.get(block_id, {block_id})
        rows.append(
            (
                block_id,
                _immediate_parent(block_id, doms, dominators),
                _immediate_parent(block_id, post_doms, post_dominators),
                1 if block_id in reachable else 0,
                1 if block_id in can_reach_exit else 0,
                max(0, len(doms) - 1),
                max(0, len(post_doms) - 1),
            )
        )
    return rows


def _reachable(starts: set[str], edges: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(starts)
    while stack:
        block_id = stack.pop()
        if block_id in seen:
            continue
        seen.add(block_id)
        stack.extend(sorted(edges.get(block_id, set()) - seen))
    return seen


def _fixed_point_dominators(
    ids: list[str],
    entry_id: str,
    predecessors: dict[str, set[str]],
    reachable: set[str],
) -> dict[str, set[str]]:
    all_ids = set(ids)
    dom = {
        block_id: ({block_id} if block_id not in reachable else set(all_ids))
        for block_id in ids
    }
    dom[entry_id] = {entry_id}
    changed = True
    while changed:
        changed = False
        for block_id in sorted(reachable - {entry_id}):
            preds = predecessors.get(block_id, set()) & reachable
            if preds:
                new = set.intersection(*(dom[pred] for pred in preds)) | {block_id}
            else:
                new = {block_id}
            if new != dom[block_id]:
                dom[block_id] = new
                changed = True
    return dom


def _fixed_point_post_dominators(
    ids: list[str],
    exits: set[str],
    successors: dict[str, set[str]],
    can_reach_exit: set[str],
) -> dict[str, set[str]]:
    all_ids = set(ids)
    post_dom = {
        block_id: ({block_id} if block_id not in can_reach_exit else set(all_ids))
        for block_id in ids
    }
    for exit_id in exits:
        post_dom[exit_id] = {exit_id}
    changed = True
    while changed:
        changed = False
        for block_id in sorted(can_reach_exit - exits):
            succs = successors.get(block_id, set()) & can_reach_exit
            if succs:
                new = set.intersection(*(post_dom[succ] for succ in succs)) | {block_id}
            else:
                new = {block_id}
            if new != post_dom[block_id]:
                post_dom[block_id] = new
                changed = True
    return post_dom


def _immediate_parent(
    block_id: str,
    parents: set[str],
    parent_sets: dict[str, set[str]],
) -> str | None:
    strict = parents - {block_id}
    for candidate in sorted(strict):
        if all(other in parent_sets.get(candidate, set()) for other in strict - {candidate}):
            return candidate
    return None
