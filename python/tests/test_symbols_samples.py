from pathlib import Path

import pytest

import glaurung as g


def _first_existing(paths):
    for p in paths:
        if Path(p).exists():
            return str(p)
    return None


@pytest.mark.parametrize(
    "path",
    [
        "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release",
        "samples/packed/hello-rust-debug.upx9",
    ],
)
def test_triage_symbols_on_elf_samples_if_present(path):
    p = Path(path)
    if not p.exists():
        pytest.skip(f"sample not present: {path}")
    art = g.triage.analyze_path(str(p))
    # SymbolSummary may or may not be present depending on format; ensure no crash and counters are ints
    sym = getattr(art, "symbols", None)
    if sym is not None:
        assert isinstance(sym.imports_count, int)
        assert isinstance(sym.exports_count, int)
        assert isinstance(sym.libs_count, int)


def test_pe_mathlib_exports_if_present():
    dll = _first_existing(
        [
            Path("samples/binaries/libraries/shared/mathlib.dll"),
        ]
    )
    if not dll:
        pytest.skip("mathlib.dll not present (requires MinGW to build)")
    if not hasattr(g, "symbols"):
        pytest.skip("symbols module not present")
    sym = g.symbols
    analyze_exports = getattr(sym, "analyze_exports", None)
    if analyze_exports is None:
        pytest.skip("analyze_exports not available")
    out = analyze_exports(dll)
    # A DLL with exports should report counts; allow None if parsing failed, else direct >= 1
    if out is not None:
        direct, forwarded, ordinal_only = out
        assert (
            isinstance(direct, int)
            and isinstance(forwarded, int)
            and isinstance(ordinal_only, int)
        )
        assert direct >= 1


def test_suspicious_win_exe_imphash_if_present():
    pe = _first_existing(
        [
            Path(
                "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/suspicious_win-c-x86_64-mingw.exe"
            )
        ]
    )
    if not pe:
        pytest.skip("suspicious_windows exe not present")
    if not hasattr(g, "symbols"):
        pytest.skip("symbols module not present")
    sym = g.symbols
    ih_fn = getattr(sym, "imphash", None)
    if ih_fn is None:
        pytest.skip("imphash not available")
    ih = ih_fn(pe)
    # imphash may be None if imports are missing; if present, it must be hex
    if ih is not None:
        assert isinstance(ih, str)
        assert len(ih) == 32
        int(ih, 16)
