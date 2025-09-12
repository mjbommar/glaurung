from pathlib import Path

import pytest

import glaurung as g


@pytest.mark.parametrize(
    "path",
    [
        Path(
            "../samples/binaries/platforms/linux/amd64/export/fortran/hello-gfortran-O0"
        ),
        Path("../samples/binaries/platforms/linux/amd64/export/native/asm/gas/O0/hello-asm-gas-O0"),
    ],
)
def test_list_symbols_demangled_if_present(path: Path) -> None:
    if not path.exists():
        pytest.skip(f"sample not present: {path}")

    # Check if sample is corrupted (contains text instead of binary)
    with open(path, "rb") as f:
        data = f.read(16)
    if data.startswith(b"version https://"):
        raise RuntimeError(
            f"Sample {path} appears to be a Git LFS pointer file. "
            "Run 'git lfs pull' or 'git lfs install && git lfs pull' to download the actual binary content."
        )

    out = g.symbols.list_symbols_demangled(str(path))
    # The API returns a SymbolSummary object, not a tuple
    assert hasattr(out, 'demangled_import_names')
    assert hasattr(out, 'demangled_export_names')
    assert hasattr(out, 'import_names')
    assert hasattr(out, 'export_names')

    # Check that the demangled names are lists (may be None if no demangling needed)
    if out.demangled_import_names is not None:
        assert isinstance(out.demangled_import_names, list)
    if out.demangled_export_names is not None:
        assert isinstance(out.demangled_export_names, list)
    if out.import_names is not None:
        assert isinstance(out.import_names, list)
    if out.export_names is not None:
        assert isinstance(out.export_names, list)
