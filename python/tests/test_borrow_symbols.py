"""Tests for cross-binary symbol borrowing (#170)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_POLY_NAMED = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual"
)
_POLY_STRIPPED = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual-stripped"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_borrow_lifts_stripped_target_naming(tmp_path: Path) -> None:
    """Same source, two builds: one with symbols (donor), one stripped
    (target). Borrowing should rename most/all of the target's `sub_*`
    placeholders to the donor's mangled names."""
    donor = _need(_POLY_NAMED)
    target = _need(_POLY_STRIPPED)

    db = tmp_path / "borrow.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=target)
    # Index target first so function_names exists.
    xref_db.index_callgraph(kb, str(target))

    summary = xref_db.borrow_symbols_from_donor(
        kb,
        target_binary_path=str(target),
        donor_binary_path=str(donor),
    )
    assert summary.get("error") is None, summary
    assert summary["donor_named"] >= 8, (
        f"poly donor should have ≥8 named functions; got {summary}"
    )
    assert summary["matched"] >= 1, (
        f"borrow should match at least one virtual method; got {summary}"
    )
    assert summary["applied"] >= summary["matched"] - 0  # >=, modulo precedence skips

    # Check that at least one virtual method now has a real name in the target.
    names = xref_db.list_function_names(kb)
    borrowed = [n for n in names if n.set_by == "borrowed"]
    assert borrowed, f"no rows ended up with set_by='borrowed'; got {[n.set_by for n in names]}"
    # Names must look like real C++ symbols, not `sub_*`.
    assert all(not n.canonical.startswith("sub_") for n in borrowed)
    kb.close()


def test_borrow_does_not_overwrite_dwarf_or_manual(tmp_path: Path) -> None:
    donor = _need(_POLY_NAMED)
    target = _need(_POLY_STRIPPED)

    db = tmp_path / "borrow.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=target)
    xref_db.index_callgraph(kb, str(target))

    # Pretend an analyst already named one VA.
    names = xref_db.list_function_names(kb)
    if not names:
        pytest.skip("target has no functions")
    pinned_va = names[0].entry_va
    xref_db.set_function_name(
        kb, pinned_va, "do_not_clobber_me", set_by="manual",
    )

    xref_db.borrow_symbols_from_donor(
        kb,
        target_binary_path=str(target),
        donor_binary_path=str(donor),
    )
    after = xref_db.get_function_name(kb, pinned_va)
    assert after is not None
    assert after.canonical == "do_not_clobber_me"
    assert after.set_by == "manual"
    kb.close()


def test_borrow_returns_clean_error_on_bad_donor(tmp_path: Path) -> None:
    target = _need(_POLY_STRIPPED)
    db = tmp_path / "borrow.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=target)
    xref_db.index_callgraph(kb, str(target))

    summary = xref_db.borrow_symbols_from_donor(
        kb,
        target_binary_path=str(target),
        donor_binary_path="/dev/null/definitely-not-a-binary",
    )
    assert "error" in summary
    kb.close()
