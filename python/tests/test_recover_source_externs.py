"""Tests for the Task Q + Task P Fortran-runtime emission passes in
``scripts/recover_source.py``.

Two passes are exercised here:

* **Task Q** — ``_emit_runtime_externs`` scans every emitted module body
  for references to libgfortran runtime symbols (``_gfortran_*``), the
  gfortran-emitted process-startup helpers (``_gfortran_set_args``,
  ``_gfortran_set_options``, ``options``), and the Fortran ``MAIN__``
  mangled name, and emits extern prototypes for any symbol that's
  referenced but not already declared/defined in this module.

* **Task P** — ``_module_uses_gfortran_dt`` /
  ``_strip_local_gfortran_dt_decls`` / ``_GFORTRAN_RUNTIME_HEADER``
  detect modules that touch the libgfortran I/O descriptor, strip the
  rewriter's per-body stub declarations, and provide a canonical
  ``st_parameter_dt`` definition so ``dt.flags = …`` /
  ``dt.common_flags = …`` both compile.

Both passes exist to close audit findings from the Bug L verification —
``main.c`` and ``hello.c`` in the Fortran-recovered tree fail
``-Wall -Werror`` without them.

These tests exercise the helpers directly — no LLM, no I/O — so they
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
    _GFORTRAN_RUNTIME_HEADER,
    _emit_runtime_externs,
    _module_uses_gfortran_dt,
    _strip_local_gfortran_dt_decls,
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


# -----------------------------------------------------------------------
# Task P — canonical gfc_dt / st_parameter_dt struct emission
# -----------------------------------------------------------------------

def test_module_uses_gfortran_dt_detects_both_spellings():
    """Detection must fire on either ``gfc_dt`` or ``st_parameter_dt``."""
    assert _module_uses_gfortran_dt("gfc_dt dt;") is True
    assert _module_uses_gfortran_dt("st_parameter_dt dt;") is True
    assert _module_uses_gfortran_dt("extern void f(gfc_dt *);") is True


def test_module_uses_gfortran_dt_negative_cases():
    """No false positives on plain C, similar names, or empty bodies."""
    assert _module_uses_gfortran_dt("") is False
    assert _module_uses_gfortran_dt("int main(void) { return 0; }") is False
    # Substring of a different identifier — must NOT match.
    assert _module_uses_gfortran_dt("int my_gfc_dt_helper(void);") is False
    assert _module_uses_gfortran_dt("int st_parameter_dt_helper;") is False


def test_strip_local_gfortran_dt_decls_removes_forward_decl():
    """The most common rewriter shape: a forward typedef that fails to
    compile because field accesses follow."""
    body = """\
extern int x;
typedef struct gfc_dt gfc_dt;

void use(void) { gfc_dt dt; (void)dt; }
"""
    out = _strip_local_gfortran_dt_decls(body)
    assert "typedef struct gfc_dt gfc_dt" not in out
    # Surrounding code is preserved.
    assert "extern int x;" in out
    assert "void use(void)" in out


def test_strip_local_gfortran_dt_decls_removes_stub_struct():
    """A stub anonymous struct with explicit fields must also be
    stripped — the canonical header is the single source of truth."""
    body = """\
/* libgfortran I/O transfer descriptor (opaque). */
typedef struct {
    long  common_flags;
    const char *filename;
    int   line;
    char  pad[600];
} st_parameter_dt;

void f(void) { st_parameter_dt dt; dt.common_flags = 0; }
"""
    out = _strip_local_gfortran_dt_decls(body)
    assert "typedef struct" not in out
    assert "common_flags = 0" in out  # use site stays


def test_strip_local_gfortran_dt_decls_idempotent_on_clean_body():
    """A body that has no stub declarations is returned unchanged."""
    body = "void f(gfc_dt *dt) { dt->flags = 0; }"
    assert _strip_local_gfortran_dt_decls(body) == body


def test_strip_local_gfortran_dt_decls_handles_empty():
    """Empty / None bodies don't crash."""
    assert _strip_local_gfortran_dt_decls("") == ""


def test_canonical_header_defines_both_field_spellings():
    """The canonical header must expose both ``flags`` and
    ``common_flags`` so any rewriter naming compiles."""
    h = _GFORTRAN_RUNTIME_HEADER
    # Anonymous union exposes both spellings on shared storage.
    assert "union {" in h
    assert "long flags;" in h
    assert "long common_flags;" in h
    # gfc_dt alias is provided.
    assert "typedef st_parameter_dt gfc_dt;" in h
    # Has filename + line for runtime error reporting.
    assert "const char *filename;" in h
    assert "int        line;" in h
    # Pragma + include guard so a module can include it freely.
    assert "#pragma once" in h


def test_canonical_header_compiles_under_gcc_wall_werror(tmp_path):
    """The whole point of Task P: a translation unit that includes the
    canonical header and exercises both field spellings + gfc_dt alias
    must compile clean under -Wall -Werror."""
    import shutil
    import subprocess

    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")

    (tmp_path / "gfortran_runtime.h").write_text(_GFORTRAN_RUNTIME_HEADER)
    test_c = tmp_path / "ut.c"
    test_c.write_text("""\
#include "gfortran_runtime.h"

extern void _gfortran_st_write(void *);

/* Exercise both spellings + the gfc_dt alias + the public fields. */
static const char SOURCE[] = "ut.c";

void use_dt(void) {
    st_parameter_dt dt1;
    dt1.flags    = 0x600000080L;
    dt1.filename = SOURCE;
    dt1.line     = 42;
    _gfortran_st_write(&dt1);

    gfc_dt dt2;
    dt2.common_flags = 0x600000080L;
    dt2.filename     = SOURCE;
    dt2.line         = 43;
    _gfortran_st_write(&dt2);
}
""")
    result = subprocess.run(
        ["gcc", "-O2", "-Wall", "-Werror", "-c",
         str(test_c), "-o", str(tmp_path / "ut.o")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"compile failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
