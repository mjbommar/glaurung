"""Tests for stdlib type-library bundles (#180)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaurung.llm.kb import type_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
_DATA_DIR = Path("data/types")


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_libc_bundle_file_is_well_formed() -> None:
    p = _need(_DATA_DIR / "stdlib-libc.json")
    data = json.loads(p.read_text())
    assert data["schema_version"] == "1"
    assert data["set_by"] == "stdlib"
    # Sanity: every struct field has the four required keys.
    for s in data["structs"]:
        assert s["name"]
        assert isinstance(s["fields"], list) and s["fields"]
        for f in s["fields"]:
            for k in ("offset", "name", "c_type", "size"):
                assert k in f, f"missing key {k} in {s['name']}.{f.get('name')}"
    # Spot-check a canonical type.
    by_name = {s["name"]: s for s in data["structs"]}
    assert "timeval" in by_name
    assert by_name["timeval"]["byte_size"] == 16


def test_winapi_bundle_file_is_well_formed() -> None:
    p = _need(_DATA_DIR / "stdlib-winapi.json")
    data = json.loads(p.read_text())
    assert data["set_by"] == "stdlib"
    by_name = {t["name"]: t for t in data["typedefs"]}
    assert "HANDLE" in by_name
    assert by_name["HANDLE"]["target"] == "void *"


def test_import_stdlib_types_lands_structs_and_typedefs(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "types.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    summary = type_db.import_stdlib_types(kb)
    libc = summary.get("stdlib-libc", {})
    win = summary.get("stdlib-winapi", {})
    assert libc.get("structs", 0) >= 5, f"expected >=5 libc structs, got {libc}"
    assert libc.get("typedefs", 0) >= 10
    assert libc.get("enums", 0) >= 1
    assert win.get("typedefs", 0) >= 10  # HANDLE, DWORD, etc.

    # Round-trip: timeval should now be readable from the DB.
    rec = type_db.get_type(kb, "timeval")
    assert rec is not None
    assert rec.kind == "struct"
    assert rec.set_by == "stdlib"
    assert rec.body["fields"][0]["name"] == "tv_sec"
    kb.close()


def test_manual_entries_survive_stdlib_import(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "types.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Analyst pre-defines `timeval` differently.
    type_db.add_struct(
        kb, "timeval",
        [type_db.StructField(0, "manual_field", "void *", 8)],
        set_by="manual",
    )
    type_db.import_stdlib_types(kb, bundles=["stdlib-libc"])

    rec = type_db.get_type(kb, "timeval")
    assert rec is not None
    assert rec.set_by == "manual"
    assert rec.body["fields"][0]["name"] == "manual_field"
    kb.close()


def test_selective_bundle_loading(tmp_path: Path) -> None:
    """Loading only `stdlib-libc` does not pull in WinAPI types."""
    binary = _need(_HELLO)
    db = tmp_path / "types.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    type_db.import_stdlib_types(kb, bundles=["stdlib-libc"])
    assert type_db.get_type(kb, "size_t") is not None
    assert type_db.get_type(kb, "HANDLE") is None  # winapi not loaded
    kb.close()


def test_auto_load_flag_imports_stdlib_on_fresh_kb(tmp_path: Path) -> None:
    """When `auto_load_stdlib=True` is passed at KB creation, stdlib
    types are automatically present without an explicit import call."""
    binary = _need(_HELLO)
    db = tmp_path / "auto.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )
    # Sample one type from each bundle.
    assert type_db.get_type(kb, "size_t") is not None
    assert type_db.get_type(kb, "HANDLE") is not None
    kb.close()


def test_auto_load_flag_default_is_off(tmp_path: Path) -> None:
    """Existing tests rely on PersistentKnowledgeBase.open() returning
    an empty type DB. Verify the default keeps that contract."""
    binary = _need(_HELLO)
    db = tmp_path / "noauto.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    assert type_db.get_type(kb, "size_t") is None
    assert type_db.get_type(kb, "HANDLE") is None
    kb.close()


def test_missing_bundle_reports_cleanly(tmp_path: Path) -> None:
    binary = _need(_HELLO)
    db = tmp_path / "types.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    summary = type_db.import_stdlib_types(
        kb, bundles=["definitely-not-a-real-bundle"],
    )
    assert "definitely-not-a-real-bundle" in summary
    assert summary["definitely-not-a-real-bundle"].get("error") == "bundle_missing"
    kb.close()
