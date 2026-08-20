"""`manual` outranks every automatic source, for every annotation an analyst can set.

CLAUDE.md states the KB rule as "manual always wins", and
`docs/architecture/IDA_GHIDRA_PARITY.md` advertises the precedence rule as a
differentiator over IDA and Ghidra. Three setters enforced it and two did not,
so an analyst could name a function, re-run analysis, and lose the name with no
error and no undo entry naming the culprit.

The gap survived because both unguarded setters *do* contain `== "manual"`
comparisons — a default argument and an undo-snapshot condition — so grepping
for the guard found hits and looked satisfied. Neither consulted the existing
row. These tests assert the behaviour instead of the spelling.

The parametrisation is deliberate: every annotation type an analyst can write
gets the same four checks, so a setter added later that forgets the guard fails
here rather than shipping.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

VA = 0x1000


@pytest.fixture
def kb(tmp_path: Path):
    """A throwaway KB. `tmp_path` keeps this out of the shared /tmp litter."""
    db = tmp_path / "precedence.glaurung"
    return PersistentKnowledgeBase.open(str(db), binary_path=os.sys.executable)


def _set_name(kb, value: str, set_by: str) -> None:
    xref_db.set_function_name(kb, VA, value, set_by=set_by)


def _get_name(kb) -> str | None:
    row = xref_db.get_function_name(kb, VA)
    return getattr(row, "canonical", row)


def _set_comment(kb, value: str, set_by: str) -> None:
    xref_db.set_comment(kb, VA, value, set_by=set_by)


def _get_comment(kb) -> str | None:
    return xref_db.get_comment(kb, VA)


def _set_label(kb, value: str, set_by: str) -> None:
    xref_db.set_data_label(kb, VA, value, set_by=set_by)


def _get_label(kb) -> str | None:
    row = xref_db.get_data_label(kb, VA)
    return getattr(row, "name", row)


#: (human name, setter, getter). Every annotation an analyst can write by hand.
ANNOTATIONS = [
    pytest.param(_set_name, _get_name, id="function_name"),
    pytest.param(_set_comment, _get_comment, id="comment"),
    pytest.param(_set_label, _get_label, id="data_label"),
]


@pytest.mark.parametrize("setter,getter", ANNOTATIONS)
def test_an_automatic_source_cannot_overwrite_an_analyst_edit(kb, setter, getter):
    """The invariant itself: analyst first, robot second, analyst wins."""
    setter(kb, "analyst_chose_this", "manual")
    setter(kb, "robot_chose_this", "auto")
    assert "analyst" in str(getter(kb)), (
        "an automatic writer overwrote a manual annotation — this is silent "
        "analyst data loss, and the KB's documented rule is that manual wins"
    )


@pytest.mark.parametrize("setter,getter", ANNOTATIONS)
def test_the_guard_does_not_freeze_a_value_against_the_analyst(kb, setter, getter):
    """Manual must still be able to correct manual.

    The failure mode of a naive fix: refuse every write once the row is manual,
    which locks an analyst out of their own annotation. The guard is about
    *provenance rank*, not immutability.
    """
    setter(kb, "first_choice", "manual")
    setter(kb, "second_choice", "manual")
    assert "second" in str(getter(kb)), (
        "a manual write was rejected — the guard is meant to outrank automatic "
        "sources, not to make an annotation permanent"
    )


@pytest.mark.parametrize("setter,getter", ANNOTATIONS)
def test_an_analyst_can_always_override_an_automatic_value(kb, setter, getter):
    """The ordinary upgrade path stays open."""
    setter(kb, "robot_chose_this", "auto")
    setter(kb, "analyst_chose_this", "manual")
    assert "analyst" in str(getter(kb))


@pytest.mark.parametrize("setter,getter", ANNOTATIONS)
def test_one_automatic_source_may_still_replace_another(kb, setter, getter):
    """Nothing here should stop a later pass improving on an earlier one."""
    setter(kb, "first_guess", "auto")
    setter(kb, "better_guess", "dwarf")
    assert "better" in str(getter(kb))
