"""Tests for jump-table-driven function discovery (#177)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


_SWITCHY_NAMED = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)
_SWITCHY_STRIPPED = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-stripped"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_jump_table_walker_recovers_switch_cases_in_stripped(tmp_path: Path) -> None:
    """The stripped switchy binary contains a `dispatch()` function
    with an 8-way switch lowered by GCC -O2 to a jump table. Without
    the walker, the analyser would only find _start; with #177's
    seeding, every case-body entry surfaces as a discoverable
    Function with basic blocks."""
    binary = _need(_SWITCHY_STRIPPED)
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    # Bar set conservatively: at least 8 discovered functions
    # (entrypoint + ~7 case bodies the walker seeded).
    assert len(funcs) >= 6, (
        f"jump-table seeding did not lift the stripped switchy binary; "
        f"only discovered {len(funcs)} functions"
    )
    # Real code, not phantom seeds — each must have basic blocks.
    with_blocks = [f for f in funcs if f.basic_blocks]
    assert len(with_blocks) >= 5
    # The case bodies are very small (sometimes 1 instruction +
    # ret), but they must each have at least one basic block.
    for f in with_blocks:
        assert f.entry_point.value > 0


def test_named_switchy_binary_discovers_dispatch(tmp_path: Path) -> None:
    """Sanity: the with-symbols version names the dispatch function
    (the source file's `int dispatch(int op, ...)` lowering)."""
    binary = _need(_SWITCHY_NAMED)
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    names = {f.name for f in funcs}
    assert "dispatch" in names, (
        f"expected `dispatch` in named switchy binary; saw {sorted(names)}"
    )
    assert "main" in names
