from pathlib import Path

import pytest

import glaurung as g


@pytest.mark.parametrize(
    "path",
    [
        Path(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2"
        ),
        Path("samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release"),
    ],
)
def test_list_symbols_demangled_if_present(path: Path) -> None:
    if not path.exists():
        pytest.skip(f"sample not present: {path}")
    out = g.symbols.list_symbols_demangled(str(path))
    assert isinstance(out, tuple)
    assert len(out) == 5
    for arr in out:
        assert isinstance(arr, list)
