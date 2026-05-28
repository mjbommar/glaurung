"""Persisted Windows callsite argument and path-condition facts."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Iterable

from . import xref_db
from .persistent import PersistentKnowledgeBase


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS callsite_argument_facts (
    binary_id INTEGER NOT NULL,
    callsite_va INTEGER NOT NULL,
    argument_index INTEGER NOT NULL,
    location TEXT NOT NULL,
    register_name TEXT NOT NULL,
    role TEXT NOT NULL,
    expression TEXT,
    value_role TEXT,
    value_role_reason TEXT,
    stack_offset INTEGER,
    source_va INTEGER,
    source_text TEXT,
    data_target_va INTEGER,
    data_target_kind TEXT,
    data_target_name TEXT,
    data_target_type TEXT,
    data_target_size INTEGER,
    alias_depth INTEGER NOT NULL DEFAULT 0,
    alias_kind TEXT,
    confidence REAL NOT NULL,
    set_by TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, callsite_va, argument_index, location)
);
CREATE INDEX IF NOT EXISTS idx_callsite_argument_facts_callsite
    ON callsite_argument_facts(binary_id, callsite_va);

CREATE TABLE IF NOT EXISTS callsite_path_conditions (
    binary_id INTEGER NOT NULL,
    callsite_va INTEGER NOT NULL,
    caller_va INTEGER,
    block_id TEXT NOT NULL,
    branch_va INTEGER NOT NULL,
    branch_mnemonic TEXT NOT NULL,
    branch_operands_json TEXT NOT NULL DEFAULT '[]',
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT NOT NULL DEFAULT '[]',
    condition_kind TEXT NOT NULL,
    condition_role TEXT NOT NULL,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    distance_bytes INTEGER,
    confidence REAL NOT NULL,
    provenance_json TEXT NOT NULL DEFAULT '[]',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, callsite_va, branch_va)
);
CREATE INDEX IF NOT EXISTS idx_callsite_path_conditions_callsite
    ON callsite_path_conditions(binary_id, callsite_va);
CREATE INDEX IF NOT EXISTS idx_callsite_path_conditions_role
    ON callsite_path_conditions(binary_id, condition_role);
"""


@dataclass(frozen=True)
class CallsiteArgumentFactRow:
    callsite_va: int
    argument_index: int
    location: str
    register_name: str
    role: str
    expression: str | None
    value_role: str | None
    confidence: float


@dataclass(frozen=True)
class CallsitePathConditionRow:
    callsite_va: int
    caller_va: int | None
    block_id: str
    branch_va: int
    branch_mnemonic: str
    branch_operands: list[str]
    compare_va: int | None
    compare_mnemonic: str | None
    compare_operands: list[str]
    condition_kind: str
    condition_role: str
    target_block_id: str | None
    fallthrough_block_id: str | None
    distance_bytes: int | None
    confidence: float
    provenance: list[str]


def ensure_schema(kb: PersistentKnowledgeBase) -> None:
    xref_db._ensure_schema(kb._conn)
    kb._conn.executescript(_SCHEMA_SQL)
    kb._conn.commit()


def persist_callsite_argument_facts(
    kb: PersistentKnowledgeBase,
    *,
    binary_id: int | None,
    callsite_va: int,
    arguments: Iterable[Any],
    set_by: str = "windows_project_call_argument_snapshot",
) -> int:
    """Persist argument rows from a call-argument snapshot result."""

    ensure_schema(kb)
    effective_binary_id = int(binary_id or kb.binary_id)
    now = int(time.time())
    rows = []
    for argument in arguments:
        argument_index = _required_int(_argument_value(argument, "index"))
        rows.append(
            (
                effective_binary_id,
                int(callsite_va),
                argument_index,
                str(_argument_value(argument, "location") or "register"),
                str(_argument_value(argument, "register_name") or ""),
                str(_argument_value(argument, "role") or ""),
                _optional_str(_argument_value(argument, "expression")),
                _optional_str(_argument_value(argument, "value_role")),
                _optional_str(_argument_value(argument, "value_role_reason")),
                _optional_int(_argument_value(argument, "stack_offset")),
                _optional_int(_argument_value(argument, "source_va")),
                _optional_str(_argument_value(argument, "source_text")),
                _optional_int(_argument_value(argument, "data_target_va")),
                _optional_str(_argument_value(argument, "data_target_kind")),
                _optional_str(_argument_value(argument, "data_target_name")),
                _optional_str(_argument_value(argument, "data_target_type")),
                _optional_int(_argument_value(argument, "data_target_size")),
                int(_argument_value(argument, "alias_depth") or 0),
                _optional_str(_argument_value(argument, "alias_kind")),
                float(_argument_value(argument, "confidence") or 0.0),
                set_by,
                now,
            )
        )
    if not rows:
        return row_count(kb, "callsite_argument_facts")
    kb._conn.executemany(
        """
INSERT OR REPLACE INTO callsite_argument_facts
(binary_id, callsite_va, argument_index, location, register_name, role,
 expression, value_role, value_role_reason, stack_offset, source_va,
 source_text, data_target_va, data_target_kind, data_target_name,
 data_target_type, data_target_size, alias_depth, alias_kind,
 confidence, set_by, set_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
        rows,
    )
    kb._conn.commit()
    return row_count(kb, "callsite_argument_facts")


def list_callsite_argument_facts(
    kb: PersistentKnowledgeBase,
    *,
    callsite_va: int | None = None,
    limit: int = 64,
) -> list[CallsiteArgumentFactRow]:
    ensure_schema(kb)
    clauses = ["binary_id = ?"]
    params: list[object] = [kb.binary_id]
    if callsite_va is not None:
        clauses.append("callsite_va = ?")
        params.append(int(callsite_va))
    params.append(int(limit))
    rows = kb._conn.execute(
        f"""
SELECT callsite_va, argument_index, location, register_name, role,
       expression, value_role, confidence
FROM callsite_argument_facts
WHERE {" AND ".join(clauses)}
ORDER BY callsite_va, argument_index, location
LIMIT ?
""",
        params,
    ).fetchall()
    return [
        CallsiteArgumentFactRow(
            callsite_va=int(row[0]),
            argument_index=int(row[1]),
            location=str(row[2]),
            register_name=str(row[3]),
            role=str(row[4]),
            expression=str(row[5]) if row[5] is not None else None,
            value_role=str(row[6]) if row[6] is not None else None,
            confidence=float(row[7]),
        )
        for row in rows
    ]


def index_callsite_path_conditions(
    kb: PersistentKnowledgeBase,
    *,
    max_distance_bytes: int = 0x200,
    force: bool = False,
) -> int:
    """Attach nearby persisted branch facts to callsites in the same function."""

    ensure_schema(kb)
    present = _present_tables(kb._conn)
    if "cfg_branch_facts" not in present:
        return row_count(kb, "callsite_path_conditions")
    cur = kb._conn.cursor()
    if force:
        cur.execute(
            "DELETE FROM callsite_path_conditions WHERE binary_id = ?",
            (kb.binary_id,),
        )
    callsites = cur.execute(
        """
SELECT src_va, src_function_va
FROM xrefs
WHERE binary_id = ? AND kind = 'call' AND src_function_va IS NOT NULL
ORDER BY src_va
""",
        (kb.binary_id,),
    ).fetchall()
    now = int(time.time())
    rows = []
    for callsite_va, caller_va in callsites:
        branch_rows = cur.execute(
            """
SELECT block_id, branch_va, branch_mnemonic, branch_operands_json,
       compare_va, compare_mnemonic, compare_operands_json, condition_kind,
       target_block_id, fallthrough_block_id
FROM cfg_branch_facts
WHERE binary_id = ? AND function_va = ? AND branch_va < ?
  AND (? - branch_va) <= ?
ORDER BY branch_va
""",
            (
                kb.binary_id,
                int(caller_va),
                int(callsite_va),
                int(callsite_va),
                int(max_distance_bytes),
            ),
        ).fetchall()
        for row in branch_rows:
            compare_operands = _json_list(row[6])
            branch_operands = _json_list(row[3])
            role, confidence = _condition_role(
                compare_operands,
                str(row[7]),
            )
            distance = int(callsite_va) - int(row[1])
            rows.append(
                (
                    kb.binary_id,
                    int(callsite_va),
                    int(caller_va),
                    str(row[0]),
                    int(row[1]),
                    str(row[2]),
                    json.dumps(branch_operands),
                    int(row[4]) if row[4] is not None else None,
                    str(row[5]) if row[5] is not None else None,
                    json.dumps(compare_operands),
                    str(row[7]),
                    role,
                    str(row[8]) if row[8] is not None else None,
                    str(row[9]) if row[9] is not None else None,
                    distance,
                    confidence,
                    json.dumps(
                        [
                            "cfg_branch_facts",
                            "project_call_xref",
                            "nearby_preceding_branch",
                        ]
                    ),
                    now,
                )
            )
    if rows:
        cur.executemany(
            """
INSERT OR REPLACE INTO callsite_path_conditions
(binary_id, callsite_va, caller_va, block_id, branch_va, branch_mnemonic,
 branch_operands_json, compare_va, compare_mnemonic, compare_operands_json,
 condition_kind, condition_role, target_block_id, fallthrough_block_id,
 distance_bytes, confidence, provenance_json, indexed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
            rows,
        )
    kb._conn.commit()
    return row_count(kb, "callsite_path_conditions")


def list_callsite_path_conditions(
    kb: PersistentKnowledgeBase,
    *,
    callsite_va: int | None = None,
    condition_role: str | None = None,
    limit: int = 64,
) -> list[CallsitePathConditionRow]:
    ensure_schema(kb)
    clauses = ["binary_id = ?"]
    params: list[object] = [kb.binary_id]
    if callsite_va is not None:
        clauses.append("callsite_va = ?")
        params.append(int(callsite_va))
    if condition_role is not None:
        clauses.append("condition_role = ?")
        params.append(str(condition_role))
    params.append(int(limit))
    rows = kb._conn.execute(
        f"""
SELECT callsite_va, caller_va, block_id, branch_va, branch_mnemonic,
       branch_operands_json, compare_va, compare_mnemonic,
       compare_operands_json, condition_kind, condition_role,
       target_block_id, fallthrough_block_id, distance_bytes, confidence,
       provenance_json
FROM callsite_path_conditions
WHERE {" AND ".join(clauses)}
ORDER BY callsite_va, branch_va
LIMIT ?
""",
        params,
    ).fetchall()
    return [_path_condition_from_row(row) for row in rows]


def row_count(kb: PersistentKnowledgeBase, table: str) -> int:
    ensure_schema(kb)
    row = kb._conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE binary_id = ?",
        (kb.binary_id,),
    ).fetchone()
    return int(row[0]) if row else 0


def _condition_role(
    compare_operands: list[str],
    condition_kind: str,
) -> tuple[str, float]:
    normalized = " ".join(compare_operands).lower()
    if re_search(r"\b(?:222|0xde)\b", normalized) or re_search(
        r"\b(?:253|0xfd)\b",
        normalized,
    ):
        return "sysinfo_class_gate", 0.78
    if re_search(r"\b0\b", normalized):
        return "zero_length_or_null_gate", 0.76
    if re_search(r"\b(?:len|length|size|cb|bytes|r8|r8d|r9|r9d)\b", normalized):
        return "length_gate", 0.66
    if condition_kind in {"unsigned_less", "unsigned_less_equal"}:
        return "range_gate", 0.62
    return "compare_gate", 0.54


def _path_condition_from_row(row: tuple) -> CallsitePathConditionRow:
    return CallsitePathConditionRow(
        callsite_va=int(row[0]),
        caller_va=int(row[1]) if row[1] is not None else None,
        block_id=str(row[2]),
        branch_va=int(row[3]),
        branch_mnemonic=str(row[4]),
        branch_operands=_json_list(row[5]),
        compare_va=int(row[6]) if row[6] is not None else None,
        compare_mnemonic=str(row[7]) if row[7] is not None else None,
        compare_operands=_json_list(row[8]),
        condition_kind=str(row[9]),
        condition_role=str(row[10]),
        target_block_id=str(row[11]) if row[11] is not None else None,
        fallthrough_block_id=str(row[12]) if row[12] is not None else None,
        distance_bytes=int(row[13]) if row[13] is not None else None,
        confidence=float(row[14]),
        provenance=_json_list(row[15]),
    )


def _present_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _json_list(raw: object) -> list[str]:
    try:
        value = json.loads(str(raw or "[]"))
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _required_int(value: Any) -> int:
    if value is None:
        raise ValueError("argument fact is missing required integer field")
    return int(value)


def _argument_value(argument: Any, key: str) -> Any:
    if isinstance(argument, dict):
        return argument.get(key)
    return getattr(argument, key, None)


def re_search(pattern: str, value: str) -> bool:
    import re

    return bool(re.search(pattern, value))
