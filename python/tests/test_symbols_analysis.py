from pathlib import Path

import pytest

import glaurung as g


def _find_first(paths):
    for p in paths:
        if Path(p).exists():
            return str(p)
    return None


def test_analyze_env_on_elf_if_present():
    if not hasattr(g, "symbols"):
        pytest.skip("symbols module not present")
    sym = g.symbols
    elf = _find_first(
        [
            Path("samples/packed/hello-rust-debug.upx9"),
            Path("samples/packed/hello-rust-release.upx9"),
            Path("samples/packed/hello-gfortran-O2.upx9"),
        ]
    )
    if not elf:
        pytest.skip("ELF sample not present")

    # Check if sample is corrupted (contains text instead of binary)
    with open(elf, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {elf} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    analyze_env = getattr(sym, "analyze_env", None)
    if analyze_env is None:
        pytest.skip("analyze_env not available in current build")
    env = analyze_env(elf)
    assert isinstance(env, dict)
    # libs/rpaths/runpaths may or may not be present; ensure no crash and dict return


def test_analyze_exports_on_pe_exe_if_present():
    if not hasattr(g, "symbols"):
        pytest.skip("symbols module not present")
    sym = g.symbols
    # Prefer suspicious Windows MinGW sample if present
    pe = _find_first(
        [
            Path(
                "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/suspicious_win-c-x86_64-mingw.exe"
            ),
            Path("samples/binaries/libraries/shared/mathlib.dll"),
        ]
    )
    if not pe:
        pytest.skip("PE sample not present")

    # Check if sample is corrupted (contains text instead of binary)
    with open(pe, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {pe} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    analyze_exports = getattr(sym, "analyze_exports", None)
    if analyze_exports is None:
        pytest.skip("analyze_exports not available in current build")
    out = analyze_exports(pe)
    # EXEs may not have exports; allow None or a tuple of three ints
    if out is not None:
        assert isinstance(out, tuple)
        assert len(out) == 3
        assert all(isinstance(x, int) for x in out)


def test_imphash_if_present():
    if not hasattr(g, "symbols"):
        pytest.skip("symbols module not present")
    sym = g.symbols
    pe = _find_first(
        [
            Path(
                "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64-mingw.exe"
            ),
        ]
    )
    if not pe:
        pytest.skip("PE sample not present")

    # Check if sample is corrupted (contains text instead of binary)
    with open(pe, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {pe} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    imphash = getattr(sym, "imphash", None)
    if imphash is None:
        pytest.skip("imphash not available in current build")
    ih = imphash(pe)
    # imphash might be None if object failed or no imports; if present, it should be hex
    if ih is not None:
        assert isinstance(ih, str)
        assert len(ih) == 32
        int(ih, 16)
