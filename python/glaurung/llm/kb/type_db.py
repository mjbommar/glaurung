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
from pathlib import Path
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


def _stdlib_bundle_dir() -> Path:
    """Locate the bundled stdlib type JSON files. Search:
       1. ``GLAURUNG_TYPES_DIR`` env var (single dir).
       2. ``data/types/`` under the current working directory.
       3. ``data/types/`` under the package install root.
    Returns the *first* directory that exists; the caller filters by
    file existence.
    """
    import os
    env = os.environ.get("GLAURUNG_TYPES_DIR")
    if env and Path(env).is_dir():
        return Path(env)
    cwd_local = Path.cwd() / "data" / "types"
    if cwd_local.is_dir():
        return cwd_local
    pkg_local = Path(__file__).resolve().parent.parent.parent.parent.parent / "data" / "types"
    if pkg_local.is_dir():
        return pkg_local
    return cwd_local  # canonical default — caller will get FileNotFoundError


def import_stdlib_types(
    kb: PersistentKnowledgeBase,
    *,
    bundles: Optional[List[str]] = None,
    bundle_dir: Optional[Path] = None,
) -> dict:
    """Load canonical libc / Windows API type definitions from JSON
    bundles into the persistent type DB. Each bundle's entries land
    with `set_by="stdlib"` and `confidence=0.99` — manual overrides
    still win, but DWARF imports won't clobber a stdlib type because
    the existing-row check only protects ``manual``.

    Returns a counts dict per bundle: structs / typedefs / enums imported.

    Default bundles when none specified: ``stdlib-libc`` and
    ``stdlib-winapi``. Pick explicitly to load only what's relevant
    (e.g. analysing a Linux ELF doesn't need WinAPI types).
    """
    if bundles is None:
        bundles = ["stdlib-libc", "stdlib-winapi"]
    if bundle_dir is None:
        bundle_dir = _stdlib_bundle_dir()
    summary: dict = {}
    for name in bundles:
        path = bundle_dir / f"{name}.json"
        if not path.exists():
            summary[name] = {"error": "bundle_missing", "path": str(path)}
            continue
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            summary[name] = {"error": f"parse_failed: {e}"}
            continue
        bs = {"structs": 0, "typedefs": 0, "enums": 0, "skipped": 0}
        set_by = data.get("set_by", "stdlib")
        confidence = float(data.get("confidence", 0.95))

        for s in data.get("structs", []) or []:
            if not s.get("name") or not s.get("fields"):
                bs["skipped"] += 1
                continue
            sf = [
                StructField(
                    offset=int(f["offset"]),
                    name=str(f["name"]),
                    c_type=str(f["c_type"]),
                    size=int(f.get("size", 0)),
                ) for f in s["fields"]
            ]
            add_struct(
                kb, str(s["name"]), sf,
                total_size=int(s.get("byte_size") or 0),
                confidence=confidence, set_by=set_by,
            )
            bs["structs"] += 1
        for t in data.get("typedefs", []) or []:
            if not t.get("name") or not t.get("target"):
                bs["skipped"] += 1
                continue
            add_typedef(
                kb, str(t["name"]), str(t["target"]),
                confidence=confidence, set_by=set_by,
            )
            bs["typedefs"] += 1
        for e in data.get("enums", []) or []:
            if not e.get("name") or not e.get("variants"):
                bs["skipped"] += 1
                continue
            ev = [
                EnumVariant(
                    name=str(v["name"]),
                    value=int(v["value"]),
                    doc=v.get("doc"),
                ) for v in e["variants"]
            ]
            add_enum(
                kb, str(e["name"]), ev,
                underlying_type=str(e.get("underlying_type") or "int"),
                confidence=confidence, set_by=set_by,
            )
            bs["enums"] += 1
        summary[name] = bs
    return summary


def import_dwarf_types(
    kb: PersistentKnowledgeBase, binary_path: str, *, max_types: int = 1000,
) -> dict:
    """Pull every struct / enum / typedef out of `binary_path`'s DWARF
    info and persist them with `set_by="dwarf"` provenance.

    Returns a small summary dict so callers can report stats. Idempotent —
    relies on `add_struct` / `add_enum` / `add_typedef`'s manual-wins
    rule, so analyst overrides are preserved across re-imports.

    Skips entries with empty bodies (declaration-only types DWARF emits
    for incomplete forward references): an empty struct teaches the type
    db nothing and would just clutter the namespace.
    """
    import glaurung as g
    try:
        types = g.debug.extract_dwarf_types_path(binary_path)
    except Exception:
        return {"imported_struct": 0, "imported_enum": 0, "imported_typedef": 0,
                "skipped_empty": 0, "error": "extract_failed"}

    counts = {"imported_struct": 0, "imported_enum": 0, "imported_typedef": 0,
              "skipped_empty": 0}
    for t in types[:max_types]:
        kind = t.get("kind")
        name = t.get("name")
        if not name:
            continue
        if kind == "struct":
            fields = t.get("fields") or []
            if not fields:
                counts["skipped_empty"] += 1
                continue
            sf = [
                StructField(
                    offset=int(f["offset"]),
                    name=str(f["name"]),
                    c_type=str(f["c_type"]),
                    size=int(f.get("size", 0)),
                ) for f in fields
            ]
            add_struct(
                kb, name, sf,
                total_size=int(t.get("byte_size") or 0),
                confidence=0.95, set_by="dwarf",
            )
            counts["imported_struct"] += 1
        elif kind == "enum":
            variants = t.get("variants") or []
            if not variants:
                counts["skipped_empty"] += 1
                continue
            ev = [EnumVariant(name=str(v["name"]), value=int(v["value"]))
                  for v in variants]
            add_enum(kb, name, ev, confidence=0.95, set_by="dwarf")
            counts["imported_enum"] += 1
        elif kind == "typedef":
            target = t.get("typedef_target")
            if not target:
                counts["skipped_empty"] += 1
                continue
            add_typedef(kb, name, str(target), confidence=0.95, set_by="dwarf")
            counts["imported_typedef"] += 1
        # union not yet supported by add_struct (different kind in schema);
        # skip silently. v2 adds union support to type_db.
    return counts


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
