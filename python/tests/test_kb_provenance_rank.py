"""Provenance is a ranked ladder, not a `manual`-or-not flag.

`CLAUDE.md` and `docs/architecture/persistent-project.md` both describe a
`set_by` ladder -- manual/dwarf/stdlib/flirt/propagated/auto/borrowed, manual
always wins. Only the top rung was ever implemented. The guard repeated across
five setters was::

    if row is not None and row[0] == "manual" and set_by != "manual":
        return

so `manual` was protected and nothing else was. Measured against the shipped
code before the fix, every one of these silently overwrote the stronger fact:

    dwarf  -> auto          a heuristic replacing real debug information
    dwarf  -> propagated    a derived guess replacing real debug information
    stdlib -> auto          a heuristic replacing a curated prototype
    flirt  -> borrowed      a fact from ANOTHER binary replacing a library match

Ghidra shipped the same value-equality comparison for years and had to retrofit
priority comparison (commit GP-6008). These tests are that retrofit, pinned.
"""

from __future__ import annotations

import pytest

from glaurung.llm.kb import type_db, xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.kb.provenance import (
    AUTO_PRIORITY,
    SET_BY_PRIORITY,
    outranks,
    set_by_priority,
)

VA = 0x1140


@pytest.fixture
def kb(tmp_path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    handle = PersistentKnowledgeBase.open(
        str(tmp_path / "p.glaurung"), binary_path=str(binary)
    )
    yield handle
    handle.close()


# --------------------------------------------------------------------------
# The ladder itself
# --------------------------------------------------------------------------


def test_manual_outranks_every_other_source():
    for other in SET_BY_PRIORITY:
        if other == "manual":
            continue
        assert outranks("manual", other)
        assert not outranks(other, "manual"), other


def test_real_debug_information_outranks_every_inference():
    """The defect this file exists for, stated as a rule."""
    for authoritative in ("dwarf", "pdb", "gopclntab"):
        for guess in ("stdlib", "flirt", "propagated", "auto", "analyzer", "borrowed"):
            assert not outranks(guess, authoritative), (
                f"{guess} overwrote {authoritative}"
            )


def test_a_fact_from_another_binary_cannot_beat_a_fact_about_this_one():
    """`borrowed` sits at PARITY with the heuristics, not below them.

    Below them it cannot write at all, because what it overwrites is the
    synthesised `sub_1234` an `analyzer` pass wrote -- and a real name
    transferred from a matched function beats a placeholder. Ranking it lower
    silently disabled `borrow_symbols` entirely. What it must never do is
    outrank a fact derived from THIS binary's own library matches, debug
    information, or the analyst.
    """
    for stronger in ("flirt", "stdlib", "dwarf", "pdb", "gopclntab", "manual"):
        assert not outranks("borrowed", stronger), stronger
    assert outranks("borrowed", "auto")
    assert outranks("borrowed", "analyzer")


def test_the_three_authoritative_debug_sources_are_deliberately_equal():
    """Nothing in the tree can order DWARF against PDB against gopclntab."""
    ranks = {set_by_priority(s) for s in ("dwarf", "pdb", "gopclntab")}
    assert len(ranks) == 1


def test_an_unknown_source_ranks_as_a_heuristic():
    """Not zero (a typo would be permanently outranked) and not the top (a typo
    would clobber DWARF). Ghidra reverted a below-analysis rung and shipped its
    new source at parity; parity is the defensible default."""
    for unknown in ("", None, "llm", "typo", "some_new_pass"):
        assert set_by_priority(unknown) == AUTO_PRIORITY
    assert outranks("llm", "auto") and outranks("auto", "llm")
    assert not outranks("llm", "dwarf")


def test_equal_rank_replaces():
    """Deliberate, and pre-existing: a later pass must be able to improve on an
    earlier one, and an analyst must be able to correct their own edit."""
    assert outranks("auto", "auto")
    assert outranks("manual", "manual")
    assert outranks("dwarf", "pdb")


# --------------------------------------------------------------------------
# The ladder as the setters actually enforce it
# --------------------------------------------------------------------------

LADDER_CASES = [
    ("dwarf", "auto"),
    ("dwarf", "propagated"),
    ("dwarf", "borrowed"),
    ("pdb", "auto"),
    ("stdlib", "auto"),
    ("flirt", "borrowed"),
    ("propagated", "borrowed"),
]


@pytest.mark.parametrize("strong,weak", LADDER_CASES)
def test_a_weaker_source_cannot_overwrite_a_function_name(kb, strong, weak):
    xref_db.set_function_name(kb, VA, "from_strong", set_by=strong)
    xref_db.set_function_name(kb, VA, "from_weak", set_by=weak)
    row = next(r for r in xref_db.list_function_names(kb) if r.entry_va == VA)
    assert row.canonical == "from_strong", f"{weak} overwrote {strong}"
    assert row.set_by == strong


@pytest.mark.parametrize("strong,weak", LADDER_CASES)
def test_a_weaker_source_cannot_overwrite_a_comment(kb, strong, weak):
    xref_db.set_comment(kb, VA, "from strong", set_by=strong)
    xref_db.set_comment(kb, VA, "from weak", set_by=weak)
    assert "strong" in str(xref_db.get_comment(kb, VA))


@pytest.mark.parametrize("strong,weak", LADDER_CASES)
def test_a_weaker_source_cannot_overwrite_a_stack_variable(kb, strong, weak):
    xref_db.set_stack_var(kb, function_va=VA, offset=-24, name="strong", set_by=strong)
    xref_db.set_stack_var(kb, function_va=VA, offset=-24, name="weak", set_by=weak)
    assert xref_db.get_stack_var(kb, VA, -24).name == "strong"


@pytest.mark.parametrize("strong,weak", LADDER_CASES)
def test_a_weaker_source_cannot_overwrite_a_type(kb, strong, weak):
    strong_field = type_db.StructField(
        offset=0, name="from_strong", c_type="int", size=4
    )
    weak_field = type_db.StructField(offset=0, name="from_weak", c_type="char", size=1)
    type_db.add_struct(kb, "s", [strong_field], set_by=strong)
    type_db.add_struct(kb, "s", [weak_field], set_by=weak)
    body = str(type_db.get_type(kb, "s"))
    assert "from_strong" in body, f"{weak} overwrote a {strong} struct"
    assert "from_weak" not in body


def test_an_upgrade_still_works(kb):
    """The ladder must not become a freeze: a better source may still improve."""
    xref_db.set_function_name(kb, VA, "guess", set_by="auto")
    xref_db.set_function_name(kb, VA, "real", set_by="dwarf")
    xref_db.set_function_name(kb, VA, "analyst", set_by="manual")
    row = next(r for r in xref_db.list_function_names(kb) if r.entry_va == VA)
    assert row.canonical == "analyst"
