"""Tests for the Task Q runtime-extern injection pass in
``scripts/recover_source.py``.

The pass scans every emitted module body for references to libgfortran
runtime symbols (``_gfortran_*``), the gfortran-emitted process-startup
helpers (``_gfortran_set_args``, ``_gfortran_set_options``, ``options``),
and the Fortran ``MAIN__`` mangled name, and injects extern prototypes
for any symbol that's referenced but not already declared/defined in
this module.

Why this pass exists: the Bug L verification audit flagged that
``main.c`` in the Fortran-recovered tree calls four undefined symbols,
which makes the recovered project fail ``-Wall -Werror`` and lose the
build-and-verify (#171) gate.

These tests exercise the helper directly — no LLM, no I/O — so they
run in milliseconds and don't depend on a working sample binary.
"""

import sys
from pathlib import Path

import pytest

# scripts/ isn't a package; add it to sys.path the same way the
# orchestrator does.
_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(_SCRIPTS))

from recover_source import (  # noqa: E402  (sys.path mutation above)
    _FORTRAN_RUNTIME_PROTOTYPES,
    _emit_runtime_externs,
)


def test_main_c_with_no_externs_gets_all_four():
    """The canonical gfortran-emitted main() body references four
    undeclared symbols — the pass should emit all four canonical
    extern declarations."""
    body = """\
int main(int argc, char **argv)
{
    _gfortran_set_args(argc, argv);
    _gfortran_set_options(7, options);
    MAIN__();
    return 0;
}
"""
    externs = _emit_runtime_externs([body])
    assert externs == [
        _FORTRAN_RUNTIME_PROTOTYPES["_gfortran_set_args"],
        _FORTRAN_RUNTIME_PROTOTYPES["_gfortran_set_options"],
        _FORTRAN_RUNTIME_PROTOTYPES["options"],
        _FORTRAN_RUNTIME_PROTOTYPES["MAIN__"],
    ]


def test_existing_extern_is_not_duplicated():
    """If the body already declares ``extern void _gfortran_st_write(…)``
    we don't emit a second copy. Bodies sometimes declare just one or
    two manually; the pass should only fill the gaps."""
    body = """\
extern void _gfortran_st_write(void *dt);
extern int  _gfortran_iargc(void);

void caller(void) {
    _gfortran_st_write(&dt);
    int n = _gfortran_iargc();
    _gfortran_transfer_character_write(&dt, "x", 1);
}
"""
    externs = _emit_runtime_externs([body])
    # st_write + iargc are already declared; only the third call needs
    # an extern.
    assert externs == [
        _FORTRAN_RUNTIME_PROTOTYPES["_gfortran_transfer_character_write"],
    ]


def test_locally_defined_main_is_not_extern_declared():
    """If ``MAIN__`` is *defined* (function body) in the same module, we
    must not emit ``extern void MAIN__(void);`` alongside it — that
    would not be wrong but is noisy. Skip when defined."""
    body = """\
void MAIN__(void) {
    _gfortran_st_write(&dt);
}
"""
    externs = _emit_runtime_externs([body])
    # MAIN__ is defined here; only the runtime call needs an extern.
    assert "extern void MAIN__(void);" not in externs
    assert _FORTRAN_RUNTIME_PROTOTYPES["_gfortran_st_write"] in externs


def test_no_fortran_calls_means_no_externs():
    """The pass is silent for non-Fortran modules — no false positives."""
    body = """\
int main(int argc, char **argv) {
    printf("hello\\n");
    return 0;
}
"""
    assert _emit_runtime_externs([body]) == []


def test_empty_input_returns_empty_list():
    assert _emit_runtime_externs([]) == []
    assert _emit_runtime_externs([""]) == []


def test_multiple_bodies_are_unioned_for_detection():
    """Detection scans the concatenation of every body in the module
    — a symbol referenced from one and declared in another is
    considered already declared."""
    body_a = "void f(void) { _gfortran_iargc(); }"
    body_b = "extern int _gfortran_iargc(void);"
    externs = _emit_runtime_externs([body_a, body_b])
    assert externs == []  # iargc is declared in body_b


def test_token_boundaries_avoid_substring_false_positives():
    """``_gfortran_iargc_extended`` (hypothetical superset name)
    should not trigger an ``_gfortran_iargc`` extern."""
    body = """\
extern int _gfortran_iargc_extended(void);
void f(void) {
    int n = _gfortran_iargc_extended();
}
"""
    externs = _emit_runtime_externs([body])
    # The pass shouldn't see iargc as referenced — only iargc_extended is.
    assert _FORTRAN_RUNTIME_PROTOTYPES["_gfortran_iargc"] not in externs


def test_options_global_is_treated_as_extern_int_array():
    """``options`` is the gfortran-emitted runtime-options static array;
    the canonical extern is ``extern int options[];`` (not a function
    prototype)."""
    body = "void f(int *o) { _gfortran_set_options(7, options); }"
    externs = _emit_runtime_externs([body])
    assert "extern int options[];" in externs


def test_extern_decl_lines_are_not_duplicated_across_runs():
    """Calling the helper twice on the same input gives the same output
    — the helper has no internal state."""
    body = "int main(int argc, char **argv) { MAIN__(); return 0; }"
    first = _emit_runtime_externs([body])
    second = _emit_runtime_externs([body])
    assert first == second
    assert "extern void MAIN__(void);" in first
