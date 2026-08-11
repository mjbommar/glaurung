"""Real-binary regression coverage for lazy call-valued select expressions."""

from __future__ import annotations

import ctypes
import re
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


class CapacityBuffer(ctypes.Structure):
    """Runtime view of the fixture's three-field buffer."""

    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("length", ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
    ]


def _compile_shared(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    """Compile one unoptimized shared object with the real host GCC."""
    return subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-fno-builtin",
            "-fno-inline",
            "-o",
            str(output),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_lazy_call_arm_remains_conditional_and_executes_identically(
    tmp_path: Path,
) -> None:
    """Recover a call in a lazy select arm without hoisting its execution."""
    if shutil.which("gcc") is None or shutil.which("strip") is None:
        pytest.skip("host gcc and strip are required")

    source = ROOT / "tests" / "fixtures" / "lazy_call_select.c"
    original = tmp_path / "lazy-call-select.so"
    stripped = tmp_path / "lazy-call-select.stripped.so"
    rebuilt_source = tmp_path / "lazy-call-select.recovered.c"
    rebuilt = tmp_path / "lazy-call-select.recovered.so"
    compiled = _compile_shared(source, original)
    assert compiled.returncode == 0, compiled.stderr

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=64)
    target = next(
        function for function in functions if function.name == "lazy_call_select"
    )
    shutil.copy2(original, stripped)
    stripped_result = subprocess.run(
        ["strip", "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped_result.returncode == 0, stripped_result.stderr

    [(_, _, rendered)] = g.ir.decompile_many(  # ty: ignore[unresolved-attribute]
        str(stripped),
        [int(target.entry_point.value)],
        style="decbench",
        timeout_ms=8000,
    )
    assert " ? " in rendered and " : " in rendered, rendered
    select = re.search(r"local_10\s*=\s*\(([^;]+\?[^;]+:[^;]+)\);", rendered)
    assert select is not None, rendered
    assert re.search(r"sub_[0-9a-f]+\([^;]+\)\s*\*\s*2", select.group(1)), rendered
    assert "0xffffffffffffffff" in rendered, rendered
    assert "glaurung-verify" not in rendered, rendered

    helper = re.search(r"extern long (sub_[0-9a-f]+)\(long, long\);", rendered)
    function = re.search(r"\bint (lazy_call_select|sub_[0-9a-f]+)\(", rendered)
    assert helper is not None and function is not None, rendered
    rebuilt_source.write_text(
        rendered
        + "\nlong "
        + helper.group(1)
        + "(long left, long right) {\n"
        + "    return (unsigned long)left <= 0xffffffffffffffffUL - "
        + "(unsigned long)right ? left + right : -1;\n}\n"
    )
    rebuilt_result = _compile_shared(rebuilt_source, rebuilt)
    assert rebuilt_result.returncode == 0, rebuilt_result.stderr

    original_lib = ctypes.CDLL(str(original))
    rebuilt_lib = ctypes.CDLL(str(rebuilt))
    original_fn = original_lib.lazy_call_select
    rebuilt_fn = getattr(rebuilt_lib, function.group(1))
    for candidate in (original_fn, rebuilt_fn):
        candidate.argtypes = [ctypes.POINTER(CapacityBuffer), ctypes.c_int]
        candidate.restype = ctypes.c_int

    for length, capacity, value in [(0, 0, 7), (1, 1, 257), (3, 8, -1)]:
        original_data = (ctypes.c_ubyte * 16)()
        rebuilt_data = (ctypes.c_ubyte * 16)()
        original_buffer = CapacityBuffer(original_data, length, capacity)
        rebuilt_buffer = CapacityBuffer(rebuilt_data, length, capacity)
        expected = original_fn(ctypes.byref(original_buffer), value)
        actual = rebuilt_fn(ctypes.byref(rebuilt_buffer), value)
        assert actual == expected
        assert rebuilt_buffer.length == original_buffer.length
        assert rebuilt_buffer.capacity == original_buffer.capacity
        assert bytes(rebuilt_data) == bytes(original_data)
