"""Tests for function prototype bundles + propagation seed (#172 v1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_set_get_round_trip(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_function_prototype(
        kb,
        "my_helper",
        "int",
        [
            xref_db.FunctionParam("argc", "int"),
            xref_db.FunctionParam("argv", "char **"),
        ],
        is_variadic=False,
        set_by="manual",
    )
    p = xref_db.get_function_prototype(kb, "my_helper")
    assert p is not None
    assert p.return_type == "int"
    assert [pp.name for pp in p.params] == ["argc", "argv"]
    assert p.is_variadic is False
    assert p.set_by == "manual"
    rendered = p.render()
    assert "int my_helper" in rendered
    assert "char ** argv" in rendered or "char **argv" in rendered
    kb.close()


def test_render_handles_void_and_variadic(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_function_prototype(
        kb,
        "noargs",
        "void",
        [],
        set_by="manual",
    )
    xref_db.set_function_prototype(
        kb,
        "logf",
        "int",
        [xref_db.FunctionParam("fmt", "const char *")],
        is_variadic=True,
        set_by="manual",
    )
    a = xref_db.get_function_prototype(kb, "noargs")
    b = xref_db.get_function_prototype(kb, "logf")
    assert a is not None and "(void)" in a.render()
    assert b is not None and b.render().endswith("...)")
    kb.close()


def test_import_stdlib_prototypes_lands_canonical_libc(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    summary = xref_db.import_stdlib_prototypes(kb)
    bs = summary.get("stdlib-libc-protos", {})
    assert bs.get("prototypes", 0) >= 50, f"expected ≥50 prototypes; got {bs}"

    # Spot-check canonical prototypes.
    printf = xref_db.get_function_prototype(kb, "printf")
    assert printf is not None
    assert printf.return_type == "int"
    assert printf.is_variadic is True
    assert printf.params[0].c_type == "const char *"

    strlen = xref_db.get_function_prototype(kb, "strlen")
    assert strlen is not None
    assert strlen.return_type == "size_t"
    assert strlen.params[0].c_type == "const char *"

    # malloc / free signatures are how the type-propagation pass will
    # tag heap-allocation sites in v2.
    malloc = xref_db.get_function_prototype(kb, "malloc")
    assert malloc is not None
    assert malloc.return_type == "void *"
    assert malloc.params[0].c_type == "size_t"
    kb.close()


def test_manual_entries_survive_stdlib_import(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_function_prototype(
        kb,
        "printf",
        "void",  # deliberately wrong override
        [xref_db.FunctionParam("custom", "int")],
        set_by="manual",
    )
    xref_db.import_stdlib_prototypes(kb)
    after = xref_db.get_function_prototype(kb, "printf")
    assert after is not None
    assert after.return_type == "void"
    assert after.params[0].name == "custom"
    assert after.set_by == "manual"
    kb.close()


def test_auto_load_stdlib_imports_prototypes_too(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "p.glaurung"
    kb = PersistentKnowledgeBase.open(
        db,
        binary_path=binary,
        auto_load_stdlib=True,
    )
    # ELF projects load libc prototypes, not the much larger Windows bundle.
    assert xref_db.get_function_prototype(kb, "printf") is not None
    assert xref_db.get_function_prototype(kb, "strlen") is not None
    assert xref_db.get_function_prototype(kb, "fopen") is not None
    assert xref_db.get_function_prototype(kb, "CreateFileA") is None
    loaded = {
        (row["bundle_kind"], row["bundle_name"])
        for row in PersistentKnowledgeBase.list_stdlib_bundle_loads(kb)
    }
    assert ("prototype", "stdlib-libc-protos") in loaded
    assert ("prototype", "stdlib-winapi-protos") not in loaded
    kb.close()


def test_old_prototype_schema_migrates_forward(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "old-proto-schema.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    cur = kb._conn.cursor()
    cur.execute(
        """
        CREATE TABLE function_prototypes (
            binary_id INTEGER NOT NULL,
            function_name TEXT NOT NULL,
            return_type TEXT,
            params_json TEXT NOT NULL DEFAULT '[]',
            is_variadic INTEGER NOT NULL DEFAULT 0,
            set_by TEXT,
            set_at INTEGER,
            PRIMARY KEY (binary_id, function_name)
        )
        """
    )
    cur.execute(
        "INSERT INTO function_prototypes "
        "(binary_id, function_name, return_type, params_json, is_variadic, set_by, set_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            kb.binary_id,
            "legacy_api",
            "int",
            '[{"name": "value", "c_type": "int"}]',
            0,
            "stdlib",
            1,
        ),
    )
    kb._conn.commit()

    proto = xref_db.get_function_prototype(kb, "legacy_api")
    assert proto is not None
    assert proto.render() == "int legacy_api(int value)"
    assert proto.module is None
    assert proto.provenance == {}

    cur.execute("PRAGMA table_info(function_prototypes)")
    cols = {row[1] for row in cur.fetchall()}
    assert {
        "module",
        "calling_convention",
        "source",
        "source_kind",
        "confidence",
        "provenance_json",
        "semantics_json",
    } <= cols
    kb.close()
