"""Tests for Go gopclntab walker integration (#212)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO_GO = Path(
    "samples/binaries/platforms/linux/amd64/export/go/hello-go"
)
_HELLO_GO_STATIC = Path(
    "samples/binaries/platforms/linux/amd64/export/go/hello-go-static"
)
_HELLO_C = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


# --- Direct binding tests ---------------------------------------------------

def test_gopclntab_recovers_main_main(tmp_path: Path) -> None:
    binary = _need(_HELLO_GO)
    pairs = g.analysis.gopclntab_names_path(str(binary))
    assert len(pairs) > 100
    names = {n for _, n in pairs}
    assert "main.main" in names


def test_gopclntab_recovers_runtime_namespace() -> None:
    binary = _need(_HELLO_GO)
    pairs = g.analysis.gopclntab_names_path(str(binary))
    runtime_count = sum(1 for _, n in pairs if n.startswith("runtime."))
    assert runtime_count >= 50


def test_gopclntab_returns_empty_on_non_go_binary() -> None:
    """The C/C++ samples are not Go — must not crash, must return empty."""
    binary = _need(_HELLO_C)
    pairs = g.analysis.gopclntab_names_path(str(binary))
    assert pairs == []


def test_gopclntab_recovers_static_binary() -> None:
    """The fully-static Go build embeds the entire stdlib; pclntab
    should still be parseable."""
    binary = _need(_HELLO_GO_STATIC)
    pairs = g.analysis.gopclntab_names_path(str(binary))
    assert len(pairs) >= 100
    assert any(n == "main.main" for _, n in pairs)


# --- KB integration tests --------------------------------------------------

def test_index_xrefs_upgrades_go_function_names(tmp_path: Path) -> None:
    """Running the standard xref/name population on a stripped Go
    binary must end with KB function_names containing main.main and
    runtime.* entries with set_by='gopclntab'."""
    binary = _need(_HELLO_GO)
    db = tmp_path / "go.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    names = xref_db.list_function_names(kb)
    assert names

    by_canonical = {n.canonical: n for n in names}
    assert "main.main" in by_canonical
    main_row = by_canonical["main.main"]
    assert main_row.set_by == "gopclntab"

    # At least 20 runtime.* entries should now be in the KB.
    runtime_named = [n for n in names if n.canonical.startswith("runtime.")]
    assert len(runtime_named) >= 20
    assert all(n.set_by == "gopclntab" for n in runtime_named)
    kb.close()


def test_manual_rename_wins_over_gopclntab(tmp_path: Path) -> None:
    """An analyst rename of a Go function with set_by='manual' must
    survive a re-run of index_xrefs (which would otherwise re-import
    the gopclntab name)."""
    binary = _need(_HELLO_GO)
    db = tmp_path / "go-manual.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    main_va = next(
        n.entry_va for n in xref_db.list_function_names(kb)
        if n.canonical == "main.main"
    )
    xref_db.set_function_name(
        kb, main_va, "user_renamed_main", set_by="manual",
    )

    # Re-run index — the gopclntab pass must respect the manual entry.
    xref_db.index_callgraph(kb, str(binary), force=True)
    name = xref_db.get_function_name(kb, main_va)
    assert name.canonical == "user_renamed_main"
    assert name.set_by == "manual"
    kb.close()
