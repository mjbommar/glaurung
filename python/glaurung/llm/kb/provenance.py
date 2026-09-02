"""Ranked provenance for every writable fact in a ``.glaurung`` project.

Every annotation table carries a ``set_by`` column naming where the fact came
from. Until this module existed, the rule enforced against it was a single
string comparison repeated in six places::

    if row is not None and row[0] == "manual" and set_by != "manual":
        return

That is a two-level rule -- ``manual`` and everything else -- wearing the
vocabulary of a seven-level one. The documented ladder
(``manual/dwarf/stdlib/flirt/propagated/auto/borrowed``) was not implemented at
all below the top rung, so a ``dwarf`` name read out of real debug information
was silently replaced by an ``auto`` heuristic, and a ``flirt`` library match
was replaced by a name ``borrowed`` from a different binary. Verified against
the shipped code before this module was written: all four of
``dwarf``->``auto``, ``dwarf``->``propagated``, ``stdlib``->``auto`` and
``flirt``->``borrowed`` overwrote the stronger fact.

Ghidra hit exactly this and had to retrofit out of it -- commit GP-6008,
"Changed SourceType examination to base upon priority instead of specific value
equality when appropriate". This module is that comparison, done once.

# The numbers are frozen

Ranks are persisted only indirectly (the *string* is what a project file
stores), but they are compared across versions of this code against rows
written by older ones, so a renumbering silently re-decides old precedence
questions. Gaps are left between rungs so a new source can slot in without
moving an existing one. Ghidra freezes its `SourceType` storage ids for the
same reason.

# An unknown source ranks as a heuristic

A ``set_by`` string this table does not know is ranked at ``auto``, not at zero
and not at the top. Ranking it lowest would let any typo be permanently
outranked by everything; ranking it highest would let a typo clobber DWARF.
Ghidra faced the same question when adding AI-sourced markup, briefly added a
``Speculative`` rung *below* analysis, reverted it, and shipped ``AI`` at
parity with ``ANALYSIS`` instead. Parity is the defensible default.

# Rank is not a lock

This answers "which fact wins", not "may the analysis re-derive this at all".
Ghidra needs both ``SourceType`` *and* separate ``namelock``/``typelock`` bits
because they are different questions. We currently only have the first; see
``docs/history/architecture-reviews/ida-ghidra-parity-2026-08.md``.
"""

from __future__ import annotations

from typing import Final

#: The rank of an automatic, heuristic source -- and the rank given to any
#: ``set_by`` string not in the table below.
AUTO_PRIORITY: Final[int] = 20

#: Frozen. See the module docstring: do not renumber, only insert into gaps.
SET_BY_PRIORITY: Final[dict[str, int]] = {
    # The analyst. Outranks everything, which is the one rule that was
    # actually implemented before this module.
    "manual": 100,
    # Ground truth the toolchain emitted about its own output. These three are
    # the same class of evidence on three platforms and are deliberately equal:
    # nothing in the tree can order them, and inventing an order would be a
    # decision with no basis.
    "dwarf": 80,
    "pdb": 80,
    "gopclntab": 80,
    # A curated bundle matched on an exact identifier. Strong, but it is our
    # data about a library rather than the binary's own statement.
    "stdlib": 60,
    # Signature matching. Genuinely useful and genuinely capable of a false
    # positive on a short function, so below an exact-name match.
    "flirt": 50,
    "cil": 50,
    "ported": 40,
    # Derived by our own analysis FROM another recorded fact. Ranked above a
    # bare heuristic because it has a cited antecedent, below real debug info
    # because the antecedent may itself have been a guess.
    "propagated": 30,
    # Heuristics.
    "auto": AUTO_PRIORITY,
    "analyzer": AUTO_PRIORITY,
    # Copied from a *different* binary judged similar -- the only source whose
    # subject is not this binary at all, and on the face of it the weakest
    # thing we record. It is nonetheless at PARITY with the heuristics rather
    # than below them, for a reason worth stating: what borrowing overwrites is
    # a synthesised `sub_1234` placeholder written by the `analyzer` pass, and
    # a real name transferred from a matched function carries strictly more
    # information than a placeholder. Ranked below, `borrow_symbols` cannot
    # write at all and the feature silently does nothing --
    # `test_borrow_symbols.py::test_borrow_lifts_stripped_target_naming` caught
    # exactly that. Ghidra hit the identical question adding AI-sourced markup,
    # added a `Speculative` rung below analysis on 2025-09-18, reverted it the
    # next day, and shipped the new source at parity instead. Parity is the
    # defensible answer; a rung nothing can ever climb out of is not.
    #
    # It still cannot touch `flirt`, `stdlib`, real debug info, or the analyst,
    # which is what the ladder was actually needed for.
    "borrowed": AUTO_PRIORITY,
}


def set_by_priority(set_by: str | None) -> int:
    """Rank of a ``set_by`` string. Unknown and empty rank as ``auto``."""
    if not set_by:
        return AUTO_PRIORITY
    return SET_BY_PRIORITY.get(set_by, AUTO_PRIORITY)


def outranks(new_set_by: str | None, existing_set_by: str | None) -> bool:
    """Whether a write by ``new_set_by`` may replace a fact from ``existing_set_by``.

    Equal rank replaces. That is deliberate and is the pre-existing behaviour:
    a later ``auto`` pass must be able to improve on an earlier one, and an
    analyst must be able to correct their own earlier edit -- a guard that
    froze a row once written would lock the analyst out of it. The rule is
    about provenance rank, not immutability.
    """
    return set_by_priority(new_set_by) >= set_by_priority(existing_set_by)
