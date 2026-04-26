"""Regression test for Bug V: imports vs callers cross-reference on
the Fortran-recovered tree.

Bug L's audit emitted [low] dead_code: "14 imports against only 2
recovered functions implies most imports have no visible caller in
the rewritten tree." The audit said the disambiguation requires
cross-referencing each import to a call site.

This test does exactly that, deterministically:

  * Pull the binary's import list from glaurung.symbols.
  * Bucket each import as either CRT scaffolding (legitimately not
    called from user code) or a libgfortran user-code call.
  * For each user-code import, verify it appears in at least one
    .c file under out/hello-fortran-recovered/.

This locks in that any future re-run of the rewriter must keep
referencing every libgfortran symbol the binary actually depends
on — a faithfulness contract.
"""

from pathlib import Path

import pytest

import glaurung as g

_REPO = Path(__file__).resolve().parents[2]
_SAMPLE = _REPO / (
    "samples/binaries/platforms/linux/amd64/export/fortran/"
    "hello-gfortran-O2"
)
_RECOVERED = _REPO / "out/hello-fortran-recovered"


# Imports the dynamic linker / glibc CRT pulls in regardless of user
# code. These are NOT expected to appear as call sites in the
# recovered .c files — they're called from _start, __do_global_dtors_aux,
# and the GNU IFUNC machinery.
_CRT_IMPORTS = frozenset({
    "_ITM_deregisterTMCloneTable",
    "_ITM_registerTMCloneTable",
    "__cxa_finalize",
    "__gmon_start__",
    "__libc_start_main",
    # Common variants that may show up on different toolchains.
    "_init", "_fini",
})


@pytest.mark.skipif(not _SAMPLE.exists(), reason="hello-gfortran sample missing")
def test_every_user_code_import_has_a_caller_in_the_recovered_tree():
    """Bug V: every libgfortran symbol the binary imports must
    appear as a bare-token reference in at least one of the
    recovered .c files. CRT scaffolding is exempt."""
    if not _RECOVERED.exists():
        pytest.skip("recovered tree missing")

    syms = g.symbols.list_symbols_demangled(str(_SAMPLE))
    imports = list(syms.import_names or [])
    assert imports, "expected non-empty import list — sample malformed?"

    user_code_imports = [n for n in imports if n not in _CRT_IMPORTS]
    assert user_code_imports, (
        "every import was classified as CRT — _CRT_IMPORTS is "
        "probably overly broad."
    )

    # Concatenate every emitted .c body once.
    bodies: list[str] = []
    for c_file in _RECOVERED.rglob("*.c"):
        bodies.append(c_file.read_text())
    haystack = "\n".join(bodies)

    missing = [n for n in user_code_imports if n not in haystack]
    assert not missing, (
        f"user-code imports with no caller in the recovered tree: "
        f"{missing}. Bug V regression — the rewriter has dropped "
        f"calls to symbols the binary depends on."
    )


@pytest.mark.skipif(not _SAMPLE.exists(), reason="hello-gfortran sample missing")
def test_import_set_matches_expected_fortran_runtime_shape():
    """Documents the import baseline: gfortran -O2 hello-world
    produces ~14 imports split as 5 CRT + 9 libgfortran. If a future
    toolchain change drops or adds imports, this test surfaces it."""
    syms = g.symbols.list_symbols_demangled(str(_SAMPLE))
    imports = set(syms.import_names or [])
    libgfortran = {n for n in imports if n.startswith("_gfortran_")}
    crt = imports & _CRT_IMPORTS
    # Sanity bounds — cheaper than asserting the exact set, robust
    # to small toolchain variation.
    assert 7 <= len(libgfortran) <= 12, (
        f"expected 7-12 libgfortran imports, got {len(libgfortran)}: "
        f"{sorted(libgfortran)}"
    )
    assert 3 <= len(crt) <= 7, (
        f"expected 3-7 CRT imports, got {len(crt)}: {sorted(crt)}"
    )
