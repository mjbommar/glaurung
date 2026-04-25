"""Tests for the persistent type system (#153)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.kb import type_db
from glaurung.llm.kb.type_db import (
    EnumVariant, StructField, render_all_as_header, render_c_definition,
)


def _hello_path() -> Path:
    p = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
    )
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_struct_round_trip(tmp_path: Path) -> None:
    db = tmp_path / "types.glaurung"
    binary = _hello_path()
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    type_db.add_struct(
        kb, "request",
        fields=[
            StructField(offset=0x00, name="method", c_type="const char *", size=8),
            StructField(offset=0x08, name="path", c_type="const char *", size=8),
            StructField(offset=0x10, name="length", c_type="size_t", size=8),
        ],
        confidence=0.85, set_by="llm",
    )
    kb.close()

    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary)
    rec = type_db.get_type(kb2, "request")
    assert rec is not None
    assert rec.kind == "struct"
    assert len(rec.body["fields"]) == 3
    assert rec.body["fields"][2]["name"] == "length"
    assert rec.body["fields"][2]["c_type"] == "size_t"
    assert rec.confidence == 0.85
    kb2.close()


def test_manual_overrides_llm(tmp_path: Path) -> None:
    db = tmp_path / "types.glaurung"
    binary = _hello_path()
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Manual entry wins over later LLM guesses.
    type_db.add_struct(
        kb, "frame", [StructField(0x0, "ptr", "void *", 8)],
        set_by="manual",
    )
    type_db.add_struct(
        kb, "frame", [StructField(0x0, "data", "int", 4)],
        set_by="llm",
    )
    rec = type_db.get_type(kb, "frame")
    assert rec is not None
    assert rec.body["fields"][0]["name"] == "ptr"  # manual entry preserved
    kb.close()


def test_enum_round_trip(tmp_path: Path) -> None:
    db = tmp_path / "types.glaurung"
    binary = _hello_path()
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    type_db.add_enum(
        kb, "conn_state",
        variants=[
            EnumVariant("CS_CONNECTING", 0, "client connecting"),
            EnumVariant("CS_AUTHENTICATING", 1),
            EnumVariant("CS_ESTABLISHED", 2),
        ],
    )
    kb.close()

    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary)
    rec = type_db.get_type(kb2, "conn_state")
    assert rec is not None
    assert rec.kind == "enum"
    assert len(rec.body["variants"]) == 3
    assert rec.body["variants"][0]["doc"] == "client connecting"
    kb2.close()


def test_typedef_and_render(tmp_path: Path) -> None:
    db = tmp_path / "types.glaurung"
    binary = _hello_path()
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    type_db.add_typedef(kb, "u32", "uint32_t")
    type_db.add_struct(kb, "tiny", [StructField(0, "a", "int", 4)])
    type_db.add_enum(kb, "colour",
                     [EnumVariant("RED", 0), EnumVariant("BLUE", 1)])

    header = render_all_as_header(kb)
    assert "typedef uint32_t u32;" in header
    assert "struct tiny {" in header
    assert "enum colour {" in header
    kb.close()


def test_field_use_tracking(tmp_path: Path) -> None:
    db = tmp_path / "types.glaurung"
    binary = _hello_path()
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    type_db.add_struct(
        kb, "request",
        [StructField(0x10, "length", "size_t", 8)],
    )
    type_db.record_field_use(kb, "request", "length",
                             use_va=0x10c0 + 0x42, function_va=0x10c0)
    type_db.record_field_use(kb, "request", "length",
                             use_va=0x10c0 + 0x60, function_va=0x10c0)

    uses = type_db.list_field_uses(kb, "request", "length")
    assert len(uses) == 2

    # Inverse query — given a VA, what type+field is referenced there?
    rev = type_db.lookup_field_at(kb, 0x10c0 + 0x42)
    assert rev == ("request", "length")
    kb.close()


def test_list_types_filtered_by_kind(tmp_path: Path) -> None:
    db = tmp_path / "types.glaurung"
    binary = _hello_path()
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    type_db.add_struct(kb, "a", [StructField(0, "x", "int", 4)])
    type_db.add_struct(kb, "b", [StructField(0, "y", "int", 4)])
    type_db.add_typedef(kb, "size_t", "unsigned long")

    structs = type_db.list_types(kb, kind="struct")
    typedefs = type_db.list_types(kb, kind="typedef")
    assert sorted(s.name for s in structs) == ["a", "b"]
    assert [t.name for t in typedefs] == ["size_t"]
    kb.close()
