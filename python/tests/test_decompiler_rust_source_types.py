"""Real-fixture checks for Rust DWARF types rendered as standalone C."""

from pathlib import Path

import pytest

import glaurung as g


ROOT = Path(__file__).resolve().parent.parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"


@pytest.mark.parametrize("optimization", ["O0", "O2"])
def test_exported_rust_i32_return_uses_exact_c_width(optimization: str) -> None:
    """The real extern-C trait dispatch wrapper returns C ``int``, not ``long``."""
    binary = BUILD / f"167_rust_trait_objects-rustc-{optimization}.so"
    if not binary.is_file():
        pytest.skip(f"fixture not built: {binary}")

    functions, _ = g.analysis.analyze_functions_path(str(binary))
    target = next(
        function for function in functions if function.name == "rust_dyn_apply"
    )
    rendered = g.ir.decompile_at(
        str(binary), int(target.entry_point.value), style="decbench"
    )
    signature = next(
        line for line in rendered.splitlines() if "rust_dyn_apply(" in line
    )

    assert signature.startswith("int rust_dyn_apply("), signature
    assert "i32" not in signature
    assert "u32" not in signature
    assert "unrecovered indirect jump" not in rendered
    assert "(*(long *)" in rendered, rendered
