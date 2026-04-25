"""Tests for DWARF type ingestion (#178)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import type_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def test_extract_dwarf_types_returns_dict_records() -> None:
    binary = _need(_HELLO_DEBUG)
    types = g.debug.extract_dwarf_types_path(str(binary))
    assert isinstance(types, list)
    assert types, "DWARF type extraction returned an empty list"
    # Must surface at least one struct with fields.
    structs_with_fields = [t for t in types if t["kind"] == "struct" and t["fields"]]
    assert structs_with_fields, "expected at least one struct with fields"
    sample = structs_with_fields[0]
    f = sample["fields"][0]
    assert "offset" in f and "name" in f and "c_type" in f


def test_import_dwarf_types_into_type_db(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "types.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    summary = type_db.import_dwarf_types(kb, str(binary))
    assert summary["imported_struct"] >= 1, (
        f"no structs imported; summary={summary}"
    )
    # Round-trip: read one struct back from the DB and verify shape.
    structs = type_db.list_types(kb, kind="struct")
    assert structs, "no structs landed in the persistent type DB"
    rec = type_db.get_type(kb, structs[0].name)
    assert rec is not None
    assert rec.kind == "struct"
    assert rec.set_by == "dwarf"
    assert rec.confidence >= 0.9
    kb.close()


def test_import_does_not_overwrite_manual_entries(tmp_path: Path) -> None:
    """A manual analyst entry must survive a later DWARF import — the
    standard `set_by` precedence rule from #153."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "types.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Hand-author a fake `_Vector_impl_data` with one field.
    type_db.add_struct(
        kb, "_Vector_impl_data",
        [type_db.StructField(0, "manually_named", "void *", 8)],
        set_by="manual",
    )

    type_db.import_dwarf_types(kb, str(binary))

    rec = type_db.get_type(kb, "_Vector_impl_data")
    assert rec is not None
    assert rec.set_by == "manual"
    assert rec.body["fields"][0]["name"] == "manually_named"
    kb.close()
