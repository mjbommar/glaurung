"""Real-binary coverage for return-reaching definition classification."""

from __future__ import annotations

import ctypes
import re
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def _compile_shared(compiler: str, source: Path, output: Path) -> None:
    """Build an optimized shared object with a canary on every function."""
    built = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-O2",
            "-fno-inline",
            "-fstack-protector-all",
            "-o",
            str(output),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr


def _rendered_name(code: str) -> str:
    """Return the one generated function identifier from a C fragment."""
    match = re.search(r"\b([A-Za-z_]\w*)\([^;{}]*\)\s*\{", code)
    assert match is not None, code
    return match.group(1)


def test_killed_canary_value_does_not_make_scalar_result_a_pointer(
    tmp_path: Path,
) -> None:
    """Use only definitions reaching return while preserving a real pointer result."""
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    if compiler is None or strip is None:
        pytest.skip("host gcc and strip are required")

    source = tmp_path / "return_defs.c"
    original = tmp_path / "return_defs.so"
    stripped = tmp_path / "return_defs.stripped.so"
    recovered_source = tmp_path / "return_defs.recovered.c"
    recovered = tmp_path / "return_defs.recovered.so"
    source.write_text(
        "#include <errno.h>\n"
        '__attribute__((visibility("default"), noinline))\n'
        "int scalar_after_pointer(int value) {\n"
        "    errno = 0;\n"
        "    return value < 0 ? -1 : (value == 0);\n"
        "}\n"
        '__attribute__((visibility("default"), noinline))\n'
        "void *pointer_after_canary(void *value) {\n"
        "    errno = 0;\n"
        "    if (value != 0)\n"
        "        (void)*(volatile unsigned char *)value;\n"
        "    return value;\n"
        "}\n"
    )
    _compile_shared(compiler, source, original)

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=128)
    targets = {
        function.name: int(function.entry_point.value)
        for function in functions
        if function.name in {"scalar_after_pointer", "pointer_after_canary"}
    }
    assert targets.keys() == {"scalar_after_pointer", "pointer_after_canary"}

    shutil.copy2(original, stripped)
    stripped_result = subprocess.run(
        [strip, "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped_result.returncode == 0, stripped_result.stderr

    results = g.ir.decompile_many(  # ty: ignore[unresolved-attribute]
        str(stripped),
        [targets["scalar_after_pointer"], targets["pointer_after_canary"]],
        style="decbench",
        timeout_ms=8000,
    )
    rendered = {int(va): text for _, va, text in results}
    scalar_code = rendered[targets["scalar_after_pointer"]]
    pointer_code = rendered[targets["pointer_after_canary"]]
    assert re.search(r"\bint\s+\w+\(int arg0\)", scalar_code), scalar_code
    assert re.search(r"\b(?:char|void)\s*\*\s*\w+\(", pointer_code), pointer_code

    recovered_source.write_text(scalar_code + "\n" + pointer_code + "\n")
    _compile_shared(compiler, recovered_source, recovered)

    original_lib = ctypes.CDLL(str(original))
    recovered_lib = ctypes.CDLL(str(recovered))
    original_lib.scalar_after_pointer.argtypes = [ctypes.c_int]
    original_lib.scalar_after_pointer.restype = ctypes.c_int
    recovered_scalar = getattr(recovered_lib, _rendered_name(scalar_code))
    recovered_scalar.argtypes = [ctypes.c_int]
    recovered_scalar.restype = ctypes.c_int
    for value in [-0x80000000, -7, -1, 0, 1, 0x7FFFFFFF]:
        assert recovered_scalar(value) == original_lib.scalar_after_pointer(value)

    original_lib.pointer_after_canary.argtypes = [ctypes.c_void_p]
    original_lib.pointer_after_canary.restype = ctypes.c_void_p
    recovered_pointer = getattr(recovered_lib, _rendered_name(pointer_code))
    recovered_pointer.argtypes = [ctypes.c_void_p]
    recovered_pointer.restype = ctypes.c_void_p
    storage = ctypes.create_string_buffer(b"x")
    for address in [None, ctypes.addressof(storage)]:
        assert recovered_pointer(address) == original_lib.pointer_after_canary(address)
