"""Round-trip coverage for writable image-backed global storage."""

from __future__ import annotations

import ctypes
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import fixture_harness as H  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow


def test_writable_global_load_round_trips_in_every_lane() -> None:
    """A static data VA must become portable C storage, never a raw process VA."""
    lanes = [
        ("09_memory_effects", compiler, optimization, ("read_counter",))
        for compiler, optimization in H.REQUIRED_MATRIX
    ]

    observed = H.run_lanes(lanes, fuzz=M.FIXTURE_FUZZ, jobs=4)

    for compiler, optimization in H.REQUIRED_MATRIX:
        lane = observed[f"09_memory_effects:{compiler}:{optimization}"]
        assert lane == {"read_counter": "pass"}, lane

    binary = H.BUILD / "09_memory_effects-gcc-O2.so"
    function = D.exported_functions(str(binary))["read_counter"]
    code = D.decompiled_c(str(binary), function)
    assert code is not None
    assert "static unsigned char glaurung_global_" in code, code
    assert "*(int *)(0x" not in code, code


def test_decompiled_counter_functions_share_one_backing_object() -> None:
    """A reset/increment/read sequence must match the source binary statefully."""
    binary = H.BUILD / "09_memory_effects-gcc-O2.so"
    functions = D.exported_functions(str(binary))
    names = ("reset_counter", "tick", "tick_n", "read_counter")
    snippets = [D.decompiled_c(str(binary), functions[name]) for name in names]
    assert all(snippet is not None for snippet in snippets), snippets

    with tempfile.TemporaryDirectory(prefix="glaurung-global-sequence-") as directory:
        rebuilt_path = D.build_so(
            "\n".join(snippet for snippet in snippets if snippet is not None),
            Path(directory),
            "counter_sequence",
        )
        assert rebuilt_path is not None

        original = ctypes.CDLL(str(binary.resolve()))
        rebuilt = ctypes.CDLL(str(rebuilt_path.resolve()))
        for library in (original, rebuilt):
            library.reset_counter.argtypes = []
            library.reset_counter.restype = None
            library.tick.argtypes = []
            library.tick.restype = None
            library.tick_n.argtypes = [ctypes.c_int]
            library.tick_n.restype = None
            library.read_counter.argtypes = []
            library.read_counter.restype = ctypes.c_int

        original.reset_counter()
        rebuilt.reset_counter()
        assert original.read_counter() == rebuilt.read_counter() == 0

        for increments in (None, 0, 1, 7, -3, None):
            if increments is None:
                original.tick()
                rebuilt.tick()
            else:
                original.tick_n(increments)
                rebuilt.tick_n(increments)
            assert original.read_counter() == rebuilt.read_counter()
