"""Persisted Windows memory operand facts."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Iterable


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS memory_operand_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    function_name TEXT,
    instruction_va INTEGER NOT NULL,
    instruction_text TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operand_index INTEGER NOT NULL,
    operand_text TEXT NOT NULL,
    access_kind TEXT NOT NULL,
    width_bytes INTEGER,
    address_expression TEXT NOT NULL,
    base_register TEXT,
    index_register TEXT,
    scale INTEGER,
    displacement INTEGER NOT NULL DEFAULT 0,
    role_hint TEXT NOT NULL,
    base_object TEXT,
    base_object_kind TEXT,
    base_object_type TEXT,
    base_object_role TEXT,
    field_offset INTEGER NOT NULL DEFAULT 0,
    likely_field_name TEXT,
    likely_type_name TEXT,
    data_target_va INTEGER,
    data_target_kind TEXT,
    data_target_name TEXT,
    data_target_type TEXT,
    data_target_size INTEGER,
    confidence REAL NOT NULL,
    set_by TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, instruction_va, operand_index)
);
CREATE INDEX IF NOT EXISTS idx_memory_operand_facts_function
    ON memory_operand_facts(binary_id, function_va);
CREATE INDEX IF NOT EXISTS idx_memory_operand_facts_instruction
    ON memory_operand_facts(binary_id, instruction_va);
CREATE INDEX IF NOT EXISTS idx_memory_operand_facts_base_kind
    ON memory_operand_facts(binary_id, base_object_kind);
CREATE INDEX IF NOT EXISTS idx_memory_operand_facts_access
    ON memory_operand_facts(binary_id, access_kind);
CREATE INDEX IF NOT EXISTS idx_memory_operand_facts_field
    ON memory_operand_facts(binary_id, likely_type_name, likely_field_name);
"""


@dataclass(frozen=True)
class MemoryOperandFactRow:
    function_va: int
    instruction_va: int
    operand_index: int
    access_kind: str
    width_bytes: int | None
    address_expression: str
    role_hint: str
    base_object_kind: str | None
    likely_field_name: str | None
    confidence: float


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
    conn.commit()


def persist_memory_operand_facts(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    facts: Iterable[Any],
    set_by: str = "windows_project_memory_operand_facts",
) -> int:
    ensure_schema(conn)
    now = int(time.time())
    rows = []
    for fact in facts:
        rows.append(
            (
                int(binary_id),
                _required_int(_fact_value(fact, "function_va")),
                _optional_str(_fact_value(fact, "function_name")),
                _required_int(_fact_value(fact, "instruction_va")),
                str(_fact_value(fact, "instruction_text") or ""),
                str(_fact_value(fact, "mnemonic") or ""),
                _required_int(_fact_value(fact, "operand_index")),
                str(_fact_value(fact, "operand_text") or ""),
                str(_fact_value(fact, "access_kind") or ""),
                _optional_int(_fact_value(fact, "width_bytes")),
                str(_fact_value(fact, "address_expression") or ""),
                _optional_str(_fact_value(fact, "base_register")),
                _optional_str(_fact_value(fact, "index_register")),
                _optional_int(_fact_value(fact, "scale")),
                int(_fact_value(fact, "displacement") or 0),
                str(_fact_value(fact, "role_hint") or "memory"),
                _optional_str(_fact_value(fact, "base_object")),
                _optional_str(_fact_value(fact, "base_object_kind")),
                _optional_str(_fact_value(fact, "base_object_type")),
                _optional_str(_fact_value(fact, "base_object_role")),
                int(_fact_value(fact, "field_offset") or 0),
                _optional_str(_fact_value(fact, "likely_field_name")),
                _optional_str(_fact_value(fact, "likely_type_name")),
                _optional_int(_fact_value(fact, "data_target_va")),
                _optional_str(_fact_value(fact, "data_target_kind")),
                _optional_str(_fact_value(fact, "data_target_name")),
                _optional_str(_fact_value(fact, "data_target_type")),
                _optional_int(_fact_value(fact, "data_target_size")),
                float(_fact_value(fact, "confidence") or 0.0),
                set_by,
                now,
            )
        )
    if rows:
        conn.executemany(
            """
INSERT OR REPLACE INTO memory_operand_facts
(binary_id, function_va, function_name, instruction_va, instruction_text,
 mnemonic, operand_index, operand_text, access_kind, width_bytes,
 address_expression, base_register, index_register, scale, displacement,
 role_hint, base_object, base_object_kind, base_object_type, base_object_role,
 field_offset, likely_field_name, likely_type_name, data_target_va,
 data_target_kind, data_target_name, data_target_type, data_target_size,
 confidence, set_by, set_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?)
""",
            rows,
        )
        conn.commit()
    return row_count(conn, binary_id=binary_id)


def list_memory_operand_facts(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    function_va: int | None = None,
    access_kind: str | None = None,
    base_object_kind: str | None = None,
    likely_field_name: str | None = None,
    limit: int = 128,
) -> list[MemoryOperandFactRow]:
    ensure_schema(conn)
    clauses = ["binary_id = ?"]
    params: list[object] = [int(binary_id)]
    if function_va is not None:
        clauses.append("function_va = ?")
        params.append(int(function_va))
    if access_kind:
        clauses.append("access_kind = ?")
        params.append(access_kind)
    if base_object_kind:
        clauses.append("base_object_kind = ?")
        params.append(base_object_kind)
    if likely_field_name:
        clauses.append("likely_field_name = ?")
        params.append(likely_field_name)
    params.append(int(limit))
    rows = conn.execute(
        f"""
SELECT function_va, instruction_va, operand_index, access_kind, width_bytes,
       address_expression, role_hint, base_object_kind, likely_field_name,
       confidence
FROM memory_operand_facts
WHERE {" AND ".join(clauses)}
ORDER BY function_va, instruction_va, operand_index
LIMIT ?
""",
        params,
    ).fetchall()
    return [
        MemoryOperandFactRow(
            function_va=int(row[0]),
            instruction_va=int(row[1]),
            operand_index=int(row[2]),
            access_kind=str(row[3]),
            width_bytes=int(row[4]) if row[4] is not None else None,
            address_expression=str(row[5]),
            role_hint=str(row[6]),
            base_object_kind=str(row[7]) if row[7] is not None else None,
            likely_field_name=str(row[8]) if row[8] is not None else None,
            confidence=float(row[9]),
        )
        for row in rows
    ]


def row_count(conn: sqlite3.Connection, *, binary_id: int | None = None) -> int:
    ensure_schema(conn)
    if binary_id is None:
        row = conn.execute("SELECT COUNT(*) FROM memory_operand_facts").fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) FROM memory_operand_facts WHERE binary_id = ?",
            (int(binary_id),),
        ).fetchone()
    return int(row[0]) if row else 0


def delete_memory_operand_facts(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    function_va: int | None = None,
) -> None:
    ensure_schema(conn)
    if function_va is None:
        conn.execute(
            "DELETE FROM memory_operand_facts WHERE binary_id = ?",
            (int(binary_id),),
        )
    else:
        conn.execute(
            "DELETE FROM memory_operand_facts WHERE binary_id = ? AND function_va = ?",
            (int(binary_id), int(function_va)),
        )
    conn.commit()


def _fact_value(fact: Any, name: str) -> Any:
    if isinstance(fact, dict):
        return fact.get(name)
    return getattr(fact, name, None)


def _required_int(value: Any) -> int:
    if value is None:
        raise ValueError("required integer field is missing")
    return int(value)


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)
