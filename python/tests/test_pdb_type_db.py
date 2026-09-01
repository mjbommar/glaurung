"""Tests for importing PE/PDB layouts into the persistent type DB."""

from __future__ import annotations

import pathlib
from pathlib import Path

import pytest

from glaurung.llm.kb import type_db, xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

# Anchored from this file, not from the working directory. Every reference to
# these fixtures used to be `Path("tests/fixtures/msvc-pdb/...")`, which only
# resolves when pytest happens to be run from the repository root -- from
# anywhere else the skipif silently reported the fixture missing and the test
# never ran. That is the same defect that left three test files permanently
# dead until 95249c54; this is the same shape, spread across twelve files.
_MSVC_PDB = (
    pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "msvc-pdb"
)


_FIXTURES = _MSVC_PDB


def _need_fixture(name: str) -> Path:
    path = _FIXTURES / name
    if not path.exists():
        pytest.skip(f"missing PDB fixture {path}")
    return path


def test_import_pe_pdb_types_into_persistent_type_db(tmp_path: Path) -> None:
    pe_path = _need_fixture("ntoskrnl.exe")
    _need_fixture("ntkrnlmp.pdb")
    db_path = tmp_path / "ntoskrnl.glaurung"
    kb = PersistentKnowledgeBase.open(db_path, binary_path=pe_path)

    summary = type_db.import_pe_pdb_types(
        kb,
        str(pe_path),
        str(_FIXTURES),
        ["_EPROCESS", "_LARGE_INTEGER", "_KSPIN_LOCK"],
    )

    assert summary["imported_struct"] >= 1
    assert summary["imported_union"] >= 1
    assert summary["imported_function_proto"] > 100
    assert summary["imported_function_name"] > 1000
    assert summary["missing_layouts"] == ["_KSPIN_LOCK"]

    eprocess = type_db.get_type(kb, "_EPROCESS")
    assert eprocess is not None
    assert eprocess.kind == "struct"
    assert eprocess.set_by == "pdb"
    assert eprocess.body["total_size"] == 2944
    assert eprocess.body["provenance"]["pdb_guid_age"] == (
        "CF32DE2E4A334C7C06FB63FCB6FAFB5C1"
    )
    assert any(field["name"] == "UniqueProcessId" for field in eprocess.body["fields"])

    large_integer = type_db.get_type(kb, "_LARGE_INTEGER")
    assert large_integer is not None
    assert large_integer.kind == "union"
    assert {field["name"] for field in large_integer.body["fields"]} >= {
        "LowPart",
        "HighPart",
        "QuadPart",
    }

    prototypes = type_db.list_types(kb, kind="function_proto")
    assert prototypes
    assert prototypes[0].set_by == "pdb"
    assert "provenance" in prototypes[0].body

    release_spin_lock = xref_db.get_function_name(kb, 0x140323480)
    assert release_spin_lock is not None
    assert release_spin_lock.canonical == "KeReleaseSpinLock"
    assert release_spin_lock.set_by == "pdb"
    kb.close()

    reopened = PersistentKnowledgeBase.open(db_path, binary_path=pe_path)
    assert type_db.get_type(reopened, "_EPROCESS") is not None
    assert type_db.get_type(reopened, "_KSPIN_LOCK") is None
    reopened.close()
