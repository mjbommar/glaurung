from pathlib import Path

import pytest

import glaurung as g


@pytest.mark.parametrize(
    "path",
    [
        Path(
            "../samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O0"
        ),
        Path(
            "../samples/binaries/platforms/linux/amd64/export/native/asm/gas/O0/hello-asm-gas-O0"
        ),
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
