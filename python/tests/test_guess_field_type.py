"""Tests for the _guess_field_type heuristic in scripts/recover_source.py (Bug O).

The heuristic votes on whether a struct field accessed as `self->FIELD`
or `this->FIELD` is best typed as `int` or `void *`. The original bug:
the access expression itself (which contains `->`) leaked into the
pointer-signal regex, so every read voted ptr. Bug O is the residual
case: even after substituting the access with FIELD_REF, the *numeric*
regex still matched unrelated arithmetic on the same line — bias toward
int that defeats clearly-pointer-shaped uses (e.g. FIELD_REF[i] in a
loop with ++).
"""

from __future__ import annotations

import importlib.util


def _load() -> object:
    spec = importlib.util.spec_from_file_location(
        "recover_source", "scripts/recover_source.py",
    )
    rs = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(rs)
    return rs


def test_guess_returns_pointer_for_indexed_access() -> None:
    rs = _load()
    bodies = ["self->ptr[0] = 0;"]
    assert rs._guess_field_type(bodies, "self", "ptr") == "void *"


def test_guess_returns_pointer_for_strlen_argument() -> None:
    rs = _load()
    bodies = ["int n = strlen(self->name);"]
    assert rs._guess_field_type(bodies, "self", "name") == "void *"


def test_guess_returns_int_for_increment_only() -> None:
    rs = _load()
    bodies = ["self->count++;"]
    assert rs._guess_field_type(bodies, "self", "count") == "int"


def test_guess_returns_int_for_compare_with_literal() -> None:
    rs = _load()
    bodies = ["if (self->flag == 0) { return; }"]
    assert rs._guess_field_type(bodies, "self", "flag") == "int"


def test_guess_handles_loop_index_pollution() -> None:
    """Bug O: a line with FIELD_REF[i] and an unrelated `i++`/`i=0` in
    the same statement shouldn't tie. The pointer signal lives on the
    field; the increment lives on the loop counter."""
    rs = _load()
    bodies = ["for (int i = 0; i < n; i++) { self->buf[i] = 0; }"]
    assert rs._guess_field_type(bodies, "self", "buf") == "void *"


def test_guess_handles_pointer_deref_with_unrelated_arithmetic() -> None:
    """Same shape: unrelated `+= 8` on another variable on the same
    line as a clear `*FIELD_REF` deref."""
    rs = _load()
    bodies = ["offset += 8; total = *self->head;"]
    assert rs._guess_field_type(bodies, "self", "head") == "void *"


def test_guess_handles_no_match() -> None:
    """If no body references the field, we should default to int with
    no votes from either side."""
    rs = _load()
    bodies = ["self->other = 0;"]
    assert rs._guess_field_type(bodies, "self", "missing") == "int"


def test_guess_aggregates_across_bodies() -> None:
    """A field used as a pointer in one body and as an int in another
    should resolve to whichever signal dominates."""
    rs = _load()
    bodies_ptr = [
        "self->data[0] = 0;",
        "self->data[1] = 0;",
        "self->data[2] = 0;",
        "self->data = 0;",  # one int-ish use
    ]
    assert rs._guess_field_type(bodies_ptr, "self", "data") == "void *"
