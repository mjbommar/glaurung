from pathlib import Path

import pytest

import glaurung as g


def test_symbols_submodule_available():
    # Top-level symbols module should exist
    assert hasattr(g, "symbols")
    assert hasattr(g.symbols, "list_symbols")
    assert hasattr(g.symbols, "list_symbols_demangled")


@pytest.mark.parametrize("path", [str(Path("../README.md"))])
def test_symbols_list_on_text_file(path: str):
    # Ensure the call works on a non-binary file and returns SymbolSummary
    if not Path(path).exists():
        pytest.skip("README not present")
    # Call the standardized top-level function
    out = g.symbols.list_symbols(path, 1024, 1024)
    # The API returns a SymbolSummary object, not a tuple
    assert hasattr(out, "import_names")
    assert hasattr(out, "export_names")
    # For a text file, these should be None or empty
    assert out.import_names is None or isinstance(out.import_names, list)
    assert out.export_names is None or isinstance(out.export_names, list)
