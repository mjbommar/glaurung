"""Regression tests for Bug T (signature_mismatch between main and
MAIN__) and the related Bug L audit findings.

Bug T's audit hypothesis: "main forwards argc/argv directly to
hello_program_main rather than to _gfortran_set_args, producing a
signature mismatch at the call boundary." Investigation revealed
that the actual recovered main.c does the right thing — argc/argv
go to set_args, MAIN__() is called with zero args. The audit's
finding was a hypothesis built on top of the [high]
invented_function gap (no extern prototypes, hence "we can't tell
what main actually does"); with Tasks P/Q closed, the prototype is
explicit and the signature is verifiable.

This test family locks in the contract that any future rewriter
refactor cannot regress on:

  1. main has the canonical signature `int main(int, char **)`.
  2. main calls `_gfortran_set_args(argc, argv)` before MAIN__.
  3. MAIN__ is called with zero arguments.
  4. The MAIN__ prototype declares zero arguments + void return.
  5. The whole module compiles clean under -Wall -Werror.

These tests parse the existing recovered fixture
(out/hello-fortran-recovered/main.c) — the artefact the Bug L
verification commit landed. If the orchestrator regenerates a main
that drifts from this shape, the test catches it.
"""

from pathlib import Path
import re
import shutil
import subprocess

import pytest

_REPO = Path(__file__).resolve().parents[2]
_MAIN_C = _REPO / "out/hello-fortran-recovered/main.c"


@pytest.mark.skipif(not _MAIN_C.exists(), reason="recovered main.c missing")
def test_main_has_canonical_signature():
    """main must accept argc and an argv pointer-to-pointer."""
    text = _MAIN_C.read_text()
    # Match `int main(int argc, char **argv)` allowing whitespace and
    # `char *argv[]` as an alternate spelling.
    sig_re = re.compile(
        r"\bint\s+main\s*\(\s*int\s+argc\s*,\s*char\s*\*{1,2}\s*argv(?:\[\])?\s*\)",
    )
    assert sig_re.search(text), (
        f"main's signature in {_MAIN_C} doesn't match the canonical "
        f"int main(int argc, char **argv) shape — Bug T regression."
    )


@pytest.mark.skipif(not _MAIN_C.exists(), reason="recovered main.c missing")
def test_main_calls_set_args_before_MAIN__():
    """argc/argv must flow through _gfortran_set_args, NOT directly
    into MAIN__. The audit's worst-case scenario was a direct
    pass-through; this test forbids it."""
    text = _MAIN_C.read_text()
    # Strip out comments and Doxygen blocks so the regex sees only
    # the executable body.
    code_only = re.sub(r"/\*[\s\S]*?\*/", "", text)
    code_only = re.sub(r"//[^\n]*", "", code_only)

    set_args_pos = code_only.find("_gfortran_set_args")
    main_call_re = re.compile(r"\bMAIN__\s*\(")
    main_call_match = main_call_re.search(code_only)

    assert set_args_pos != -1, (
        f"main.c doesn't call _gfortran_set_args at all — runtime "
        f"argv intrinsics will return empty. Bug T+Q regression."
    )
    assert main_call_match is not None, (
        f"main.c doesn't actually invoke MAIN__ — "
        f"the program would never enter user code."
    )
    # MAIN__ must be called AFTER set_args.
    assert set_args_pos < main_call_match.start(), (
        f"_gfortran_set_args is called after MAIN__ in {_MAIN_C}; "
        f"the runtime needs argc/argv before user code runs."
    )


@pytest.mark.skipif(not _MAIN_C.exists(), reason="recovered main.c missing")
def test_MAIN__call_has_zero_arguments():
    """MAIN__() takes no arguments. A direct argc/argv pass-through
    would look like `MAIN__(argc, argv)` and is the exact
    signature_mismatch the audit warned about.

    Strip extern declarations + comments first so we only inspect
    call sites (not the `extern void MAIN__(void);` prototype which
    intentionally mentions `void` as an argument-list spelling)."""
    text = _MAIN_C.read_text()
    code_only = re.sub(r"/\*[\s\S]*?\*/", "", text)
    code_only = re.sub(r"//[^\n]*", "", code_only)
    # Drop the prototype line so its `void` argument-list doesn't
    # trigger the bare-token regex below.
    code_only = re.sub(
        r"\bextern\s+[^;]*?\bMAIN__\s*\([^)]*\)\s*;",
        "",
        code_only,
    )
    # Now any `MAIN__(token)` is necessarily a call site with args.
    bad = re.compile(r"\bMAIN__\s*\(\s*[A-Za-z_]")
    match = bad.search(code_only)
    assert match is None, (
        f"MAIN__ is invoked with arguments in {_MAIN_C}: "
        f"{code_only[match.start():match.start() + 40]!r} — "
        f"Bug T regression. gfortran's MAIN__ is zero-arg."
    )


@pytest.mark.skipif(not _MAIN_C.exists(), reason="recovered main.c missing")
def test_MAIN__prototype_is_zero_arg_void_return():
    """The extern prototype Tasks P/Q emit must declare MAIN__ as
    `void MAIN__(void)`. Anything else creates a call-site mismatch
    that gcc -Werror catches."""
    text = _MAIN_C.read_text()
    proto_re = re.compile(r"\bextern\s+void\s+MAIN__\s*\(\s*void\s*\)\s*;")
    assert proto_re.search(text), (
        f"MAIN__ prototype in {_MAIN_C} isn't `extern void "
        f"MAIN__(void);` — re-check Tasks P/Q output."
    )


@pytest.mark.skipif(not _MAIN_C.exists(), reason="recovered main.c missing")
def test_main_compiles_under_wall_werror():
    """The all-up gate: the recovered main.c must build clean under
    `gcc -O2 -Wall -Werror -c`. This is the test that would have
    caught Bugs P/Q/R/T as a unit."""
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    proj = _MAIN_C.parent
    result = subprocess.run(
        ["gcc", "-O2", "-Wall", "-Werror", "-c",
         str(_MAIN_C), "-o", "/tmp/_test_main.o"],
        capture_output=True, text=True, cwd=proj,
    )
    assert result.returncode == 0, (
        f"main.c failed to compile clean:\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
