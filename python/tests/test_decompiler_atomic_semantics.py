"""Round-trip coverage for conditional read-modify-write definitions."""

from __future__ import annotations

import ctypes
import shutil
import subprocess
import sys
from pathlib import Path

import glaurung as g
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow  # ty: ignore[unresolved-attribute]

_SOURCE = """
#include <stdatomic.h>

int cas_exchange(_Atomic int *slot, int expected, int desired) {
    if (atomic_compare_exchange_strong(slot, &expected, desired)) {
        return 1;
    }
    return -expected;
}
"""


def test_x86_cmpxchg_preserves_memory_when_the_comparison_fails(
    tmp_path: Path,
) -> None:
    """The false edge reads the old value and performs no conditional store."""
    if shutil.which("gcc") is None or shutil.which("objdump") is None:
        pytest.skip("gcc and objdump are required for the real cmpxchg fixture")

    source = tmp_path / "atomic_compare_exchange.c"
    source.write_text(_SOURCE)
    original = tmp_path / "atomic_compare_exchange.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-w",
            str(source),
            "-o",
            str(original),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    disassembly = subprocess.run(
        ["objdump", "-d", str(original)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembly.returncode == 0, disassembly.stderr
    assert "cmpxchg" in disassembly.stdout, disassembly.stdout

    function = D.exported_functions(str(original))["cas_exchange"]
    llir = g.ir.lift_window_at(  # ty: ignore[unresolved-attribute]
        str(original), function, 24, 64
    )
    conditional_stores = [op for op in llir if op["kind"] == "cond_store"]
    assert len(conditional_stores) == 1, llir
    assert conditional_stores[0]["cond"] == "%zf"
    assert conditional_stores[0]["src"] == {"kind": "reg", "name": "edx"}
    assert not any(
        op["kind"] == "store" and op["va"] == conditional_stores[0]["va"] for op in llir
    ), llir
    assert any(
        op["kind"] == "ite"
        and op["dst"] == "eax"
        and op["t"] == {"kind": "reg", "name": "%t0"}
        and op["e"] == {"kind": "reg", "name": "eax"}
        for op in llir
    ), llir

    code = D.decompiled_c(str(original), function)
    assert code is not None
    rebuilt = D.build_so(code, tmp_path, "decompiled_atomic_compare_exchange")
    assert rebuilt is not None, code

    original_library = ctypes.CDLL(str(original), mode=ctypes.RTLD_LOCAL)
    rebuilt_library = ctypes.CDLL(str(rebuilt), mode=ctypes.RTLD_LOCAL)
    for library in (original_library, rebuilt_library):
        library.cas_exchange.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
            ctypes.c_int,
        ]
        library.cas_exchange.restype = ctypes.c_int

    for initial, expected, desired in (
        (5, 5, 9),
        (7, 5, 9),
        (-3, -3, 4),
        (-17, 0, 4),
    ):
        original_slot = ctypes.c_int(initial)
        rebuilt_slot = ctypes.c_int(initial)
        original_result = original_library.cas_exchange(
            ctypes.byref(original_slot), expected, desired
        )
        rebuilt_result = rebuilt_library.cas_exchange(
            ctypes.byref(rebuilt_slot), expected, desired
        )
        assert (rebuilt_result, rebuilt_slot.value) == (
            original_result,
            original_slot.value,
        ), (
            f"cmpxchg mismatch for initial={initial}, expected={expected}, "
            f"desired={desired}\n{code}"
        )
