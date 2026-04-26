"""Tests for .NET CIL metadata walker integration (#210)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO_MONO = Path(
    "samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe"
)
_HELLO_C_PE = Path(
    "samples/binaries/platforms/linux/amd64/cross/windows-x86_64/hello-c-x86_64-mingw.exe"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def test_cil_recovers_main_and_ctor() -> None:
    binary = _need(_HELLO_MONO)
    methods = g.analysis.cil_methods_path(str(binary))
    assert methods, "expected methods"
    names = [n for _, n in methods]
    assert any(n.endswith("::Main") for n in names)
    assert any(".ctor" in n for n in names)


def test_cil_returns_empty_on_native_pe() -> None:
    """Plain mingw PE has no CLR descriptor — must return empty
    rather than crashing."""
    binary = _need(_HELLO_C_PE)
    methods = g.analysis.cil_methods_path(str(binary))
    assert methods == []


def test_index_callgraph_imports_cil_names_with_image_base(tmp_path: Path) -> None:
    """End-to-end: open the .glaurung KB on Hello-mono.exe, index
    callgraph, and confirm Hello::Main appears with set_by='cil' at
    the absolute VA (image_base + RVA)."""
    binary = _need(_HELLO_MONO)
    db = tmp_path / "cil.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    names = xref_db.list_function_names(kb)
    cil_named = [n for n in names if n.set_by == "cil"]
    # We seeded 2 methods (.ctor + Main); expect at least one.
    assert cil_named
    canonicals = {n.canonical for n in cil_named}
    assert any(c.endswith("::Main") for c in canonicals)
    # VAs should be image_base + rva. For Hello-mono the image base
    # defaults to 0x400000.
    main_row = next(n for n in cil_named if n.canonical.endswith("::Main"))
    assert main_row.entry_va > 0x400000
    kb.close()


def test_manual_rename_wins_over_cil(tmp_path: Path) -> None:
    """A manual rename of a CIL method must survive a re-index."""
    binary = _need(_HELLO_MONO)
    db = tmp_path / "cil-manual.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    names = xref_db.list_function_names(kb)
    main_va = next(n.entry_va for n in names if n.canonical.endswith("::Main"))
    xref_db.set_function_name(kb, main_va, "user_main", set_by="manual")

    xref_db.index_callgraph(kb, str(binary), force=True)
    name = xref_db.get_function_name(kb, main_va)
    assert name.canonical == "user_main"
    assert name.set_by == "manual"
    kb.close()
