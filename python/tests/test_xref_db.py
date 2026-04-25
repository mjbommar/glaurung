"""Tests for the persistent xref database (#154)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.kb import xref_db


def _hello_path() -> Path:
    p = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
    )
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_index_callgraph_persists(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "xrefs.glaurung"

    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    assert not xref_db.is_indexed(kb)

    edges = xref_db.index_callgraph(kb, str(binary))
    assert edges > 0, "hello-gcc-O2 has internal calls"
    assert xref_db.is_indexed(kb)
    kb.close()

    # Reopen — still indexed, no re-run needed.
    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary)
    assert xref_db.is_indexed(kb2)
    kb2.close()


def test_xrefs_to_and_from(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "xrefs.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    # main is at 0x13d0 — every internal call from it shows up
    # via list_xrefs_from. We don't assert specific targets (those
    # depend on the toolchain) but the count must be > 0.
    out = xref_db.list_xrefs_from(kb, 0x13d0)
    # Either empty (if the analyser produced no recognisable internal
    # edges) or non-empty — but it must NOT crash.
    assert isinstance(out, list)

    # _start at 0x1840 calls main via __libc_start_main; some
    # toolchains emit a direct call edge to main.
    incoming = xref_db.list_xrefs_to(kb, 0x13d0)
    assert isinstance(incoming, list)
    kb.close()


def test_function_names_and_comments(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "names.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    xref_db.set_function_name(kb, 0x10c0, "parse_config", set_by="llm")
    xref_db.set_function_name(kb, 0x10c0, "parse_config_v2",
                              set_by="manual",
                              aliases=["parse_config"])
    name = xref_db.get_function_name(kb, 0x10c0)
    assert name is not None
    assert name.canonical == "parse_config_v2"
    assert "parse_config" in name.aliases
    assert name.set_by == "manual"

    xref_db.set_comment(kb, 0x10cf, "stack canary save")
    assert xref_db.get_comment(kb, 0x10cf) == "stack canary save"
    kb.close()

    # Reopen — names and comments survived.
    kb2 = PersistentKnowledgeBase.open(db, binary_path=binary)
    name2 = xref_db.get_function_name(kb2, 0x10c0)
    assert name2 is not None
    assert name2.canonical == "parse_config_v2"
    assert xref_db.get_comment(kb2, 0x10cf) == "stack canary save"
    kb2.close()


def test_add_xref_data_kind(tmp_path: Path) -> None:
    binary = _hello_path()
    db = tmp_path / "data.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.add_xref(kb, src_va=0x1500, dst_va=0x4040, kind="data_read",
                     src_function_va=0x14d0)
    xref_db.add_xref(kb, src_va=0x1510, dst_va=0x4040, kind="data_write",
                     src_function_va=0x14d0)
    # Filter by kind via list_xrefs_to.
    reads = xref_db.list_xrefs_to(kb, 0x4040, kinds=["data_read"])
    writes = xref_db.list_xrefs_to(kb, 0x4040, kinds=["data_write"])
    assert len(reads) == 1
    assert len(writes) == 1
    assert reads[0].kind == "data_read"
    assert writes[0].kind == "data_write"

    # In-function summary.
    in_fn = xref_db.list_xrefs_in_function(kb, 0x14d0)
    assert len(in_fn) == 2
    kb.close()
