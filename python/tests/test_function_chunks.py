"""Tests for the Function-chunk model (#156)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


def _hello_cpp_O2() -> Path:
    """A binary that GCC -O2 builds with a `main.cold` split."""
    p = Path(
        "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2"
    )
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_chunks_default_to_single_range_for_normal_functions() -> None:
    binary = _hello_cpp_O2()
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    # Every function reports at least one chunk via all_ranges() — even if
    # the discovery pass never set `chunks` directly, the legacy `range`
    # field is mirrored automatically.
    for f in funcs:
        ranges = f.all_ranges()
        assert isinstance(ranges, list)
        # A discovered function with basic blocks must have *some* range.
        if f.basic_blocks:
            assert ranges, f"function {f.name} has blocks but no ranges"


def test_main_dot_cold_is_folded_into_main() -> None:
    binary = _hello_cpp_O2()
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    names = [f.name for f in funcs]

    # The `main.cold` symbol must NOT survive as a separate function —
    # it should have been merged into `main.chunks[1]`.
    assert "main.cold" not in names, (
        f"main.cold leaked through as a separate function; "
        f"chunk merging is broken. functions={names}"
    )

    # Find main and verify it picked up the .cold chunk.
    main = next((f for f in funcs if f.name == "main"), None)
    assert main is not None, "main not discovered"
    assert len(main.chunks) >= 2, (
        f"main.chunks should contain primary + .cold split, got "
        f"{len(main.chunks)}: {[(c.start.value, c.size) for c in main.chunks]}"
    )
    # The cold split lives at 0x1320 in this binary (verified via `nm`).
    assert main.contains_va(0x1320), (
        "main should now own the 0x1320 cold split; "
        f"chunks={[(hex(c.start.value), c.size) for c in main.chunks]}"
    )
    # The HAS_EH flag is set for any function we know has split chunks,
    # since the cold path is reached only through the unwind/EH machinery
    # in practice.
    assert main.has_flag(0x4), "HAS_EH (0x4) should be set on a chunked main"


def test_total_size_sums_all_chunks() -> None:
    binary = _hello_cpp_O2()
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    assert main is not None

    total = main.total_size()
    primary = main.chunks[0].size if main.chunks else 0
    cold_chunks = main.chunks[1:] if len(main.chunks) >= 2 else []
    expected = primary + sum(c.size for c in cold_chunks)
    assert total == expected, (
        f"total_size {total} != primary({primary}) + cold({[c.size for c in cold_chunks]})"
    )
    # And total_size should strictly exceed the primary range when chunks
    # were folded — otherwise the merge did nothing.
    if len(main.chunks) >= 2:
        assert total > primary
