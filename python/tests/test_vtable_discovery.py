"""Tests for vtable-driven function discovery (#160 v1)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


_POLY_NAMED = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual"
)
_POLY_STRIPPED = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/poly-cpp-virtual-stripped"
)


def test_vtable_walker_discovers_virtual_methods_in_named_binary() -> None:
    """The named (un-stripped) version has Dog::speak, Spider::legs, etc.
    in the symbol table, so they'd be discovered regardless. We just
    assert the analyser finds the expected set."""
    binary = _need(_POLY_NAMED)
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    names = {f.name for f in funcs}
    # Mangled names of the virtual methods (Itanium ABI).
    expected_substrings = ["3Dog5speak", "3Dog4legs", "6Spider5speak", "6Spider4legs"]
    for sub in expected_substrings:
        assert any(sub in n for n in names), (
            f"missing virtual method matching {sub!r}; saw {sorted(names)[:8]}"
        )


def test_vtable_walker_recovers_methods_in_stripped_binary() -> None:
    """The actual #160 win: a stripped polymorphic C++ binary, where
    virtual methods are unreachable via direct calls from _start/main,
    must still surface as discovered Functions because the vtable
    walker seeded them.

    With the walker disabled, the analyser would find only the
    entrypoint (`_start`). With it, every virtual method's entry VA
    is seeded as a discovery candidate."""
    binary = _need(_POLY_STRIPPED)
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    # Exact count is sensitive to the toolchain (debug+strip vs
    # release+strip differ), but we expect substantially more than 1.
    # The poly binary has 8 virtual methods + entry → ~9 discovered.
    assert len(funcs) >= 6, (
        f"vtable walker did not seed virtual methods in stripped binary; "
        f"only discovered {len(funcs)} functions (expected >= 6)"
    )
    # All discovered functions should have actual basic blocks (proves
    # they're real code, not phantom seeds).
    with_blocks = [f for f in funcs if f.basic_blocks]
    assert len(with_blocks) >= 6, (
        f"only {len(with_blocks)} of {len(funcs)} discovered functions "
        f"have basic blocks — vtable seeds aren't being analysed properly"
    )
