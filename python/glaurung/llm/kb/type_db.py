"""Persistent type system (Tier-S #153).

Stores user-defined / recovered types in the .glaurung database so
struct/enum/typedef definitions survive process exit. Wires into
two real consumers:

  1. The decompiler's render pass: when a function's pseudocode shows
     ``[base + 0x10]`` and the type system knows ``base`` is a
     ``struct request *`` whose 0x10 field is ``len: int``, the
     rendered code shows ``base->len`` instead. Today's tools have
     no equivalent — Bug J's ``_augment_canonical_types`` sketched
     this but did it on the fly per emission.

  2. The :mod:`glaurung.llm.tools.recover_struct_layout` LLM tool
     writes its output into this store rather than returning a
     one-shot result. Subsequent passes consume it.

Schema is additive on top of the persistent KB — new tables
``types`` and ``type_field_uses`` are created on demand.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from typing import List, Literal, Optional

from .persistent import PersistentKnowledgeBase


TypeKind = Literal["struct", "union", "enum", "typedef", "function_proto"]


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS types (
    type_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    body_json TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    set_by TEXT,
    set_at INTEGER,
    UNIQUE (binary_id, name)
);

CREATE INDEX IF NOT EXISTS idx_types_binary
    ON types(binary_id, kind);

CREATE TABLE IF NOT EXISTS type_field_uses (
    binary_id INTEGER NOT NULL,
    type_name TEXT NOT NULL,
    field_name TEXT NOT NULL,
    use_va INTEGER NOT NULL,
    function_va INTEGER,
    PRIMARY KEY (binary_id, use_va, type_name, field_name)
);
CREATE INDEX IF NOT EXISTS idx_type_field_uses_va
    ON type_field_uses(binary_id, use_va);
CREATE INDEX IF NOT EXISTS idx_type_field_uses_func
    ON type_field_uses(binary_id, function_va);
CREATE INDEX IF NOT EXISTS idx_type_field_uses_type
    ON type_field_uses(binary_id, type_name);
"""


# ---------------------------------------------------------------------------
# Body shapes — stored as JSON in `types.body_json`.
# ---------------------------------------------------------------------------


@dataclass
class StructField:
    offset: int
    name: str
    c_type: str
    size: int = 0
    rationale: str = ""


@dataclass
class StructBody:
    fields: List[StructField] = field(default_factory=list)
    total_size: int = 0


@dataclass
class EnumVariant:
    name: str
    value: int
    doc: str = ""


@dataclass
class EnumBody:
    variants: List[EnumVariant] = field(default_factory=list)
    underlying_type: str = "int"


@dataclass
class TypedefBody:
    aliased: str = ""


@dataclass
class FunctionProtoBody:
    return_type: str = "void"
    parameters: List[dict] = field(default_factory=list)
    c_prototype: str = ""


@dataclass
class TypeRecord:
    name: str
    kind: TypeKind
    body: dict
    confidence: float = 0.5
    set_by: Optional[str] = None
    set_at: Optional[int] = None


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
    conn.commit()


# ---------------------------------------------------------------------------
# Add / get / list
# ---------------------------------------------------------------------------


def add_struct(
    kb: PersistentKnowledgeBase,
    name: str,
    fields: List[StructField],
    *,
    total_size: int = 0,
    confidence: float = 0.5,
    set_by: str = "manual",
) -> None:
    """Persist a struct definition. Idempotent — re-adding the same
    name overwrites the previous body unless a manual entry already
    exists (analyst input wins over later automated guesses)."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT set_by FROM types WHERE binary_id = ? AND name = ?",
        (kb.binary_id, name),
    )
    existing = cur.fetchone()
    if existing is not None and existing[0] == "manual" and set_by != "manual":
        # Refuse to overwrite manual entries with automated ones.
        return
    body = {
        "kind": "struct",
        "fields": [
            {
                "offset": f.offset, "name": f.name,
                "c_type": f.c_type, "size": f.size,
                "rationale": f.rationale,
            } for f in fields
        ],
        "total_size": total_size or (
            max((f.offset + f.size for f in fields), default=0)
        ),
    }
    cur.execute(
        "INSERT OR REPLACE INTO types "
        "(binary_id, name, kind, body_json, confidence, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, name, "struct", json.dumps(body),
            confidence, set_by, int(time.time()),
        ),
    )
    kb._conn.commit()


def add_enum(
    kb: PersistentKnowledgeBase,
    name: str,
    variants: List[EnumVariant],
    *,
    underlying_type: str = "int",
    confidence: float = 0.5,
    set_by: str = "manual",
) -> None:
    _ensure_schema(kb._conn)
    body = {
        "kind": "enum",
        "underlying_type": underlying_type,
        "variants": [
            {"name": v.name, "value": v.value, "doc": v.doc}
            for v in variants
        ],
    }
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO types "
        "(binary_id, name, kind, body_json, confidence, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, name, "enum", json.dumps(body),
            confidence, set_by, int(time.time()),
        ),
    )
    kb._conn.commit()


def add_typedef(
    kb: PersistentKnowledgeBase,
    name: str,
    aliased: str,
    *,
    confidence: float = 0.7,
    set_by: str = "manual",
) -> None:
    _ensure_schema(kb._conn)
    body = {"kind": "typedef", "aliased": aliased}
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO types "
        "(binary_id, name, kind, body_json, confidence, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id, name, "typedef", json.dumps(body),
            confidence, set_by, int(time.time()),
        ),
    )
    kb._conn.commit()


def get_type(
    kb: PersistentKnowledgeBase, name: str
) -> Optional[TypeRecord]:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT name, kind, body_json, confidence, set_by, set_at "
        "FROM types WHERE binary_id = ? AND name = ?",
        (kb.binary_id, name),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return TypeRecord(
        name=row[0], kind=row[1],
        body=json.loads(row[2]),
        confidence=row[3] or 0.5,
        set_by=row[4], set_at=row[5],
    )


def list_types(
    kb: PersistentKnowledgeBase,
    kind: Optional[TypeKind] = None,
) -> List[TypeRecord]:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    if kind is None:
        cur.execute(
            "SELECT name, kind, body_json, confidence, set_by, set_at "
            "FROM types WHERE binary_id = ? ORDER BY name",
            (kb.binary_id,),
        )
    else:
        cur.execute(
            "SELECT name, kind, body_json, confidence, set_by, set_at "
            "FROM types WHERE binary_id = ? AND kind = ? ORDER BY name",
            (kb.binary_id, kind),
        )
    return [
        TypeRecord(
            name=r[0], kind=r[1], body=json.loads(r[2]),
            confidence=r[3] or 0.5, set_by=r[4], set_at=r[5],
        )
        for r in cur.fetchall()
    ]


def remove_type(kb: PersistentKnowledgeBase, name: str) -> None:
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "DELETE FROM types WHERE binary_id = ? AND name = ?",
        (kb.binary_id, name),
    )
    kb._conn.commit()


# ---------------------------------------------------------------------------
# Field-use tracking
# ---------------------------------------------------------------------------


def record_field_use(
    kb: PersistentKnowledgeBase,
    type_name: str,
    field_name: str,
    use_va: int,
    function_va: Optional[int] = None,
) -> None:
    """Record an instruction that accesses a struct field. Lets the
    decompiler / analyst answer "where is foo.bar referenced?"."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO type_field_uses "
        "(binary_id, type_name, field_name, use_va, function_va) "
        "VALUES (?, ?, ?, ?, ?)",
        (kb.binary_id, type_name, field_name, use_va, function_va),
    )
    kb._conn.commit()


def list_field_uses(
    kb: PersistentKnowledgeBase,
    type_name: str,
    field_name: Optional[str] = None,
) -> List[tuple[str, int, Optional[int]]]:
    """Return ``(field_name, use_va, function_va)`` for every recorded
    access of ``type_name`` (or only ``field_name`` when supplied)."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    if field_name is None:
        cur.execute(
            "SELECT field_name, use_va, function_va FROM type_field_uses "
            "WHERE binary_id = ? AND type_name = ? ORDER BY use_va",
            (kb.binary_id, type_name),
        )
    else:
        cur.execute(
            "SELECT field_name, use_va, function_va FROM type_field_uses "
            "WHERE binary_id = ? AND type_name = ? AND field_name = ? "
            "ORDER BY use_va",
            (kb.binary_id, type_name, field_name),
        )
    return [(r[0], r[1], r[2]) for r in cur.fetchall()]


def lookup_field_at(
    kb: PersistentKnowledgeBase,
    use_va: int,
) -> Optional[tuple[str, str]]:
    """Inverse of record_field_use — given an instruction VA, return
    (type_name, field_name) when known. Used by the decompiler render
    pass to retroactively render ``[reg+0x10]`` as ``req->len``."""
    _ensure_schema(kb._conn)
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT type_name, field_name FROM type_field_uses "
        "WHERE binary_id = ? AND use_va = ? LIMIT 1",
        (kb.binary_id, use_va),
    )
    row = cur.fetchone()
    return (row[0], row[1]) if row else None


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------


def render_c_definition(rec: TypeRecord) -> str:
    """Pretty-print a type record as the C declaration the user would
    paste into a header. Lossy but useful for export."""
    body = rec.body
    if rec.kind == "struct":
        lines = [f"struct {rec.name} {{"]
        for f in body.get("fields", []):
            lines.append(
                f"    {f['c_type']} {f['name']};  /* +0x{f['offset']:x} */"
            )
        lines.append("};")
        return "\n".join(lines)
    if rec.kind == "enum":
        lines = [f"enum {rec.name} {{"]
        for v in body.get("variants", []):
            doc = f"  /* {v['doc']} */" if v.get("doc") else ""
            lines.append(f"    {v['name']} = {v['value']},{doc}")
        lines.append("};")
        return "\n".join(lines)
    if rec.kind == "typedef":
        return f"typedef {body.get('aliased', 'void')} {rec.name};"
    if rec.kind == "function_proto":
        return body.get("c_prototype", f"void {rec.name}(void);")
    return f"/* unknown kind: {rec.kind} */"


def render_all_as_header(kb: PersistentKnowledgeBase) -> str:
    """Emit every persisted type as a single C header. Used by the
    standard-format exporters (#165)."""
    parts = [
        "/* Auto-generated by glaurung from persistent type database. */",
        "#pragma once",
        "",
    ]
    # Order: typedefs, structs, enums, function_proto.
    for kind in ("typedef", "struct", "enum", "function_proto"):
        for rec in list_types(kb, kind):  # type: ignore[arg-type]
            parts.append(render_c_definition(rec))
            parts.append("")
    return "\n".join(parts)
