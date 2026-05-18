"""Persistent intra-function CFG facts for PE projects.

The native analyser already recovers basic blocks on demand. This module
persists those blocks into the project SQLite database so later tools can
query CFG coverage without re-running function recovery.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

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

CREATE TABLE IF NOT EXISTS cfg_branch_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    branch_va INTEGER NOT NULL,
    branch_mnemonic TEXT NOT NULL,
    branch_operands_json TEXT NOT NULL DEFAULT '[]',
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT NOT NULL DEFAULT '[]',
    condition_kind TEXT NOT NULL,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id, branch_va)
);
CREATE INDEX IF NOT EXISTS idx_cfg_branch_facts_function
    ON cfg_branch_facts(binary_id, function_va);
CREATE INDEX IF NOT EXISTS idx_cfg_branch_facts_block
    ON cfg_branch_facts(binary_id, function_va, block_id);

CREATE TABLE IF NOT EXISTS cfg_branch_index_state (
    binary_id INTEGER PRIMARY KEY,
    indexed_at INTEGER NOT NULL,
    function_count INTEGER NOT NULL,
    branch_count INTEGER NOT NULL
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


@dataclass(frozen=True)
class CfgBranchCounts:
    function_count: int = 0
    branch_count: int = 0


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


def is_branch_facts_indexed(kb: PersistentKnowledgeBase) -> bool:
    """Return True when branch-condition facts exist for this binary."""
    _ensure_schema(kb._conn)
    row = kb._conn.execute(
        "SELECT 1 FROM cfg_branch_index_state WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    return row is not None


def cfg_branch_counts(kb: PersistentKnowledgeBase) -> CfgBranchCounts:
    """Return persisted branch-condition fact counts for the current binary."""
    _ensure_schema(kb._conn)
    row = kb._conn.execute(
        "SELECT function_count, branch_count FROM cfg_branch_index_state "
        "WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    if row is None:
        return CfgBranchCounts()
    return CfgBranchCounts(function_count=int(row[0]), branch_count=int(row[1]))


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
            cur.execute(
                "DELETE FROM cfg_branch_facts WHERE binary_id = ?",
                (kb.binary_id,),
            )
            cur.execute(
                "DELETE FROM cfg_branch_index_state WHERE binary_id = ?",
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


def index_cfg_branch_facts(
    kb: PersistentKnowledgeBase,
    binary_path: str,
    *,
    force: bool = False,
    max_instructions_per_block: int = 64,
    timeout_ms: int = 500,
) -> int:
    """Persist simple branch-condition facts for CFG blocks.

    The first version records conditional x86/x64 branch terminators and the
    closest preceding ``cmp``/``test`` instruction in the same block when one is
    visible through the native disassembler.
    """
    _ensure_schema(kb._conn)
    if is_branch_facts_indexed(kb) and not force:
        return cfg_branch_counts(kb).branch_count

    import glaurung as g

    data = Path(binary_path).read_bytes()
    pe_mapper = _PeVaMapper.from_bytes(data)
    disassembler = None
    if pe_mapper is not None:
        try:
            disassembler = g.disasm.disassembler_for_path(binary_path)
        except Exception:
            disassembler = None

    block_rows = kb._conn.execute(
        "SELECT function_va, block_id, start_va, end_va FROM basic_blocks "
        "WHERE binary_id = ? ORDER BY function_va, start_va",
        (kb.binary_id,),
    ).fetchall()
    successors = _successors_by_block(kb._conn, kb.binary_id)
    now = int(time.time())
    rows: list[
        tuple[
            int,
            int,
            str,
            int,
            str,
            str,
            int | None,
            str | None,
            str,
            str,
            str | None,
            str | None,
            int,
        ]
    ] = []
    functions_with_facts: set[int] = set()
    for function_va, block_id, start_va, end_va in block_rows:
        try:
            window_bytes = max(1, int(end_va) - int(start_va))
            if disassembler is not None and pe_mapper is not None:
                block_bytes = pe_mapper.read_va(int(start_va), window_bytes)
                if not block_bytes:
                    continue
                instructions = disassembler.disassemble_bytes(
                    g.Address(g.AddressKind.VA, int(start_va), bits=64),
                    block_bytes,
                    max_instructions_per_block,
                    timeout_ms,
                )
            else:
                instructions = g.disasm.disassemble_window_at(
                    binary_path,
                    int(start_va),
                    window_bytes=window_bytes,
                    max_instructions=max_instructions_per_block,
                    max_time_ms=timeout_ms,
                )
        except Exception:
            continue
        fact = _branch_fact_from_instructions(
            str(block_id),
            list(instructions),
            successors.get((int(function_va), str(block_id)), []),
        )
        if fact is None:
            continue
        rows.append((kb.binary_id, int(function_va), str(block_id), *fact, now))
        functions_with_facts.add(int(function_va))

    cur = kb._conn.cursor()
    cur.execute("BEGIN")
    try:
        if force:
            cur.execute(
                "DELETE FROM cfg_branch_facts WHERE binary_id = ?",
                (kb.binary_id,),
            )
            cur.execute(
                "DELETE FROM cfg_branch_index_state WHERE binary_id = ?",
                (kb.binary_id,),
            )
        cur.executemany(
            "INSERT OR REPLACE INTO cfg_branch_facts "
            "(binary_id, function_va, block_id, branch_va, branch_mnemonic, "
            "branch_operands_json, compare_va, compare_mnemonic, "
            "compare_operands_json, condition_kind, target_block_id, "
            "fallthrough_block_id, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        cur.execute(
            "INSERT OR REPLACE INTO cfg_branch_index_state "
            "(binary_id, indexed_at, function_count, branch_count) "
            "VALUES (?, ?, ?, ?)",
            (kb.binary_id, now, len(functions_with_facts), len(rows)),
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


def _successors_by_block(
    conn: sqlite3.Connection,
    binary_id: int,
) -> dict[tuple[int, str], list[str]]:
    out: dict[tuple[int, str], list[str]] = {}
    rows = conn.execute(
        "SELECT function_va, src_block_id, dst_block_id FROM cfg_edges "
        "WHERE binary_id = ? ORDER BY function_va, src_block_id, dst_block_id",
        (binary_id,),
    ).fetchall()
    for function_va, src, dst in rows:
        out.setdefault((int(function_va), str(src)), []).append(str(dst))
    return out


def _branch_fact_from_instructions(
    block_id: str,
    instructions: list[object],
    successors: list[str],
) -> tuple[int, str, str, int | None, str | None, str, str, str | None, str | None] | None:
    branch_index = None
    for index in range(len(instructions) - 1, -1, -1):
        mnemonic = str(getattr(instructions[index], "mnemonic", "")).lower()
        if _is_conditional_branch(mnemonic):
            branch_index = index
            break
    if branch_index is None:
        return None
    branch = instructions[branch_index]
    compare = None
    for candidate in reversed(instructions[:branch_index]):
        mnemonic = str(getattr(candidate, "mnemonic", "")).lower()
        if mnemonic in {"cmp", "test"}:
            compare = candidate
            break
    target_block_id = _target_successor(successors)
    fallthrough_block_id = _fallthrough_successor(block_id, successors, target_block_id)
    return (
        int(getattr(getattr(branch, "address"), "value")),
        str(getattr(branch, "mnemonic")).lower(),
        json.dumps(_operand_texts(branch)),
        int(getattr(getattr(compare, "address"), "value")) if compare is not None else None,
        str(getattr(compare, "mnemonic")).lower() if compare is not None else None,
        json.dumps(_operand_texts(compare)) if compare is not None else "[]",
        _condition_kind(str(getattr(branch, "mnemonic")).lower()),
        target_block_id,
        fallthrough_block_id,
    )


def _is_conditional_branch(mnemonic: str) -> bool:
    return mnemonic.startswith("j") and mnemonic not in {"jmp", "jmpe", "jmpl"}


def _operand_texts(instruction: object) -> list[str]:
    return [str(operand) for operand in getattr(instruction, "operands", []) or []]


def _condition_kind(mnemonic: str) -> str:
    mapping = {
        "je": "equal",
        "jz": "equal",
        "jne": "not_equal",
        "jnz": "not_equal",
        "ja": "unsigned_greater",
        "jnbe": "unsigned_greater",
        "jae": "unsigned_greater_equal",
        "jnb": "unsigned_greater_equal",
        "jb": "unsigned_less",
        "jnae": "unsigned_less",
        "jbe": "unsigned_less_equal",
        "jna": "unsigned_less_equal",
        "jg": "signed_greater",
        "jnle": "signed_greater",
        "jge": "signed_greater_equal",
        "jnl": "signed_greater_equal",
        "jl": "signed_less",
        "jnge": "signed_less",
        "jle": "signed_less_equal",
        "jng": "signed_less_equal",
        "jo": "overflow",
        "jno": "not_overflow",
        "js": "signed",
        "jns": "not_signed",
        "jp": "parity",
        "jpe": "parity",
        "jnp": "not_parity",
        "jpo": "not_parity",
    }
    return mapping.get(mnemonic, "conditional")


def _target_successor(successors: list[str]) -> str | None:
    # Native CFG edges are currently not typed true/false. Preserve a stable
    # candidate target when present and keep fallthrough distinct below.
    return successors[0] if successors else None


def _fallthrough_successor(
    block_id: str,
    successors: list[str],
    target_block_id: str | None,
) -> str | None:
    for successor in successors:
        if successor != target_block_id:
            return successor
    return None


@dataclass(frozen=True)
class _PeSection:
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int


@dataclass(frozen=True)
class _PeVaMapper:
    data: bytes
    image_base: int
    sections: list[_PeSection]

    @classmethod
    def from_bytes(cls, data: bytes) -> "_PeVaMapper | None":
        if len(data) < 0x100 or data[:2] != b"MZ":
            return None
        pe_offset = _u32(data, 0x3C)
        if pe_offset is None or pe_offset + 0x18 >= len(data):
            return None
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return None
        number_of_sections = _u16(data, pe_offset + 6)
        optional_header_size = _u16(data, pe_offset + 20)
        if number_of_sections is None or optional_header_size is None:
            return None
        optional_header = pe_offset + 24
        magic = _u16(data, optional_header)
        if magic == 0x20B:
            image_base = _u64(data, optional_header + 24)
        elif magic == 0x10B:
            image_base = _u32(data, optional_header + 28)
        else:
            image_base = None
        if image_base is None:
            return None
        section_table = optional_header + optional_header_size
        sections: list[_PeSection] = []
        for index in range(number_of_sections):
            off = section_table + index * 40
            if off + 40 > len(data):
                break
            virtual_size = _u32(data, off + 8) or 0
            virtual_address = _u32(data, off + 12) or 0
            raw_size = _u32(data, off + 16) or 0
            raw_pointer = _u32(data, off + 20) or 0
            if raw_pointer >= len(data):
                continue
            sections.append(
                _PeSection(
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_pointer=raw_pointer,
                    raw_size=raw_size,
                )
            )
        return cls(data=data, image_base=int(image_base), sections=sections)

    def read_va(self, va: int, size: int) -> bytes:
        rva = va - self.image_base
        if rva < 0:
            return b""
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                offset = section.raw_pointer + (rva - section.virtual_address)
                if offset < 0 or offset >= len(self.data):
                    return b""
                end = min(len(self.data), offset + size)
                return self.data[offset:end]
        return b""


def _u16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 8 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 8], "little")


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
