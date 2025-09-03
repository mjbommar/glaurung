from pathlib import Path

import pytest

import glaurung as g


def test_symbols_submodule_available():
    # Top-level symbols module should exist
    assert hasattr(g, "symbols")
    assert hasattr(g.symbols, "list_symbols")
    assert hasattr(g.symbols, "list_symbols_demangled")


@pytest.mark.parametrize("path", [str(Path("README.md"))])
def test_symbols_list_on_text_file(path: str):
    # Ensure the call works on a non-binary file and returns tuples of lists
    if not Path(path).exists():
        pytest.skip("README not present")
    # Call the standardized top-level function
    out = g.symbols.list_symbols(path, 1024, 1024)
    assert isinstance(out, tuple)
    assert len(out) == 5
    all_syms, dyn_syms, imports, exports, libs = out
    for arr in out:
        assert isinstance(arr, list)
