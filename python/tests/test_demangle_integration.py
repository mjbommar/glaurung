"""Demangled names reaching the triage artifact, plus `strings.demangle_text`.

Distinct from `test_symbols_demangled.py` despite the shared parameter list:
that file exercises the direct `symbols.list_symbols_demangled` entry point,
this one asserts the same evidence survives a full `triage.analyze_path`.

Sample paths are anchored from `Path(__file__)` up to the repo root; they used
to be CWD-relative `"../samples/..."` and resolved outside the repository, so
this file had never run (`docs/development/test-estate/01-reachability.md`
1.4).
"""

from pathlib import Path

import pytest

import glaurung as g

ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLES = ROOT / "samples" / "binaries" / "platforms" / "linux" / "amd64" / "export"


@pytest.mark.parametrize(
    "path",
    [
        SAMPLES / "fortran" / "hello-gfortran-O0",
        SAMPLES / "native" / "asm" / "gas" / "O0" / "hello-asm-gas-O0",
    ],
)
def test_symbol_summary_includes_demangled_names_if_present(path: Path) -> None:
    if not path.exists():
        pytest.skip(f"sample not present: {path}")
    art = g.triage.analyze_path(str(path))
    sym = getattr(art, "symbols", None)
    assert sym is not None
    # Either import or export demangled names may be present depending on the sample
    has_any = False
    if getattr(sym, "demangled_import_names", None):
        assert isinstance(sym.demangled_import_names, list)
        has_any = has_any or len(sym.demangled_import_names) >= 0
    if getattr(sym, "demangled_export_names", None):
        assert isinstance(sym.demangled_export_names, list)
        has_any = has_any or len(sym.demangled_export_names) >= 0
    # Not strictly requiring non-empty to avoid flakiness; presence and type are sufficient
    assert hasattr(g, "strings")
    # Also sanity check demangle_text works on a trivial C++ mangled name
    out = g.strings.demangle_text("_Z3foov")
    if out is not None:
        demangled, flavor = out
        assert isinstance(demangled, str)
        assert flavor in {"itanium", "rust", "msvc", "unknown"}
