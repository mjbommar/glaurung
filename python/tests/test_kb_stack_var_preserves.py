"""Renaming a stack slot must not destroy the rest of the slot.

`stack_frame_vars` is written with `INSERT OR REPLACE`, which writes the WHOLE
row. So a caller that supplies only a name silently nulls the slot's `c_type`
and resets its `use_count`. That was the caller's problem to solve and only one
of the two callers solved it: `frame.py` read the row back and passed the old
values through, while the REPL's `locals rename` did not. Measured against the
shipped code before the fix::

    before: name=local_18 c_type='struct packet *' use_count=7
    after : name=hdr      c_type=None             use_count=0

Renaming a variable is the single most common thing an analyst does (14 of 16
professional reverse engineers in Votipka et al., USENIX Security 2020). Losing
the type they set a moment earlier, with no message, is the worst possible
response to it.

The fix is in the setter rather than in each caller, because "every caller must
remember to read the row back first" is the property that already failed.
"""

from __future__ import annotations

import subprocess

import pytest

from glaurung.llm.kb import xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase

VA = 0x1140
OFF = -24


def slot(kb, va: int = VA, off: int = OFF):
    """The stack var, asserted to exist.

    A missing row is a real failure here, and `AttributeError: 'NoneType'` is a
    worse way to learn it than an assertion that names the slot.
    """
    var = xref_db.get_stack_var(kb, va, off)
    assert var is not None, f"no stack var at fn 0x{va:x} offset {off}"
    return var


@pytest.fixture
def kb(tmp_path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    handle = PersistentKnowledgeBase.open(
        str(tmp_path / "p.glaurung"), binary_path=str(binary)
    )
    xref_db.set_stack_var(
        handle,
        function_va=VA,
        offset=OFF,
        name="local_18",
        c_type="struct packet *",
        use_count=7,
        set_by="manual",
    )
    yield handle
    handle.close()


def test_a_rename_keeps_the_type_and_the_use_count(kb):
    """Exactly what the REPL's `locals rename` does."""
    xref_db.set_stack_var(kb, function_va=VA, offset=OFF, name="hdr", set_by="manual")
    var = slot(kb)
    assert var.name == "hdr", "the rename must still happen"
    assert var.c_type == "struct packet *", "the analyst's type was destroyed"
    assert var.use_count == 7, "the use count was reset"


def test_a_retype_keeps_the_name(kb):
    """The other direction, which was already correct and must stay so."""
    xref_db.set_stack_var(
        kb, function_va=VA, offset=OFF, name="local_18", c_type="int", set_by="manual"
    )
    var = slot(kb)
    assert var.c_type == "int"
    assert var.name == "local_18"


def test_a_type_can_still_be_cleared_deliberately(kb):
    """`None` means "I am not saying"; `""` means "there is no type".

    Without a way to say the second, making `None` preserve would make a wrong
    type permanent.
    """
    xref_db.set_stack_var(
        kb, function_va=VA, offset=OFF, name="local_18", c_type="", set_by="manual"
    )
    assert not slot(kb).c_type


def test_the_use_count_is_a_floor_not_a_truncation(kb):
    """An auto pass that counted fewer uses must not lower the recorded count,
    and one that counted more must raise it."""
    xref_db.set_stack_var(
        kb, function_va=VA, offset=OFF, name="local_18", use_count=2, set_by="manual"
    )
    assert slot(kb).use_count == 7
    xref_db.set_stack_var(
        kb, function_va=VA, offset=OFF, name="local_18", use_count=9, set_by="manual"
    )
    assert slot(kb).use_count == 9


def test_a_first_write_is_unaffected(kb):
    """There is no row to preserve from, so nothing is invented."""
    xref_db.set_stack_var(kb, function_va=VA, offset=-64, name="fresh", set_by="auto")
    var = slot(kb, off=-64)
    assert var.name == "fresh"
    assert not var.c_type
    assert var.use_count == 0


def test_the_real_frame_cli_preserves_the_type(tmp_path):
    """Drive the shipped `glaurung frame ... rename` end to end.

    The in-process tests above call `set_stack_var` directly, which is where
    the fix lives. This one goes through argument parsing, its own
    `PersistentKnowledgeBase.open`, and its own commit, so a regression in the
    command rather than in the setter still fails.
    """
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    db = tmp_path / "p.glaurung"
    handle = PersistentKnowledgeBase.open(str(db), binary_path=str(binary))
    xref_db.set_stack_var(
        handle,
        function_va=VA,
        offset=OFF,
        name="local_18",
        c_type="struct packet *",
        use_count=7,
        set_by="manual",
    )
    handle.close()

    result = subprocess.run(
        ["glaurung", "frame", str(db), hex(VA), "rename", str(OFF), "hdr"],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    assert "hdr" in result.stdout, result.stdout

    handle = PersistentKnowledgeBase.open(str(db), binary_path=str(binary))
    try:
        var = slot(handle)
    finally:
        handle.close()
    assert var.name == "hdr"
    assert var.c_type == "struct packet *", "the CLI destroyed the analyst's type"
    assert var.use_count == 7, "the CLI reset the use count"
