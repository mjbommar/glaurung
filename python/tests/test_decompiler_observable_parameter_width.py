"""Real-binary coverage for observable integer parameter widths."""

from __future__ import annotations

import ctypes
import re
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def _build_shared(compiler: str, source: Path, output: Path) -> None:
    """Compile one optimized shared object or fail with the compiler diagnostic."""
    built = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-O2",
            "-fno-inline",
            "-fno-omit-frame-pointer",
            "-o",
            str(output),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr


def test_real_stripped_low_byte_parameter_is_not_widened_by_its_abi_copy(
    tmp_path: Path,
) -> None:
    """Recover a byte input only when no observable use consumes higher bits."""
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    objdump = shutil.which("objdump")
    if compiler is None or strip is None or objdump is None:
        pytest.skip("host gcc, strip, and objdump are required")

    source = tmp_path / "observable_width.c"
    original = tmp_path / "observable_width.so"
    stripped = tmp_path / "observable_width.stripped.so"
    rebuilt_source = tmp_path / "observable_width.recovered.c"
    rebuilt = tmp_path / "observable_width.recovered.so"
    source.write_text(
        '__attribute__((visibility("default"), noinline))\n'
        "int byte_only(const signed char *left, const signed char *right,\n"
        "              signed char until) {\n"
        "    while (*left != 0 && *left != until && *left == *right) {\n"
        "        ++left;\n"
        "        ++right;\n"
        "    }\n"
        "    return *left - *right;\n"
        "}\n"
        '__attribute__((visibility("default"), noinline))\n'
        "int full_word(int value) {\n"
        "    return (signed char)value == 7 ? value : 0;\n"
        "}\n"
    )
    _build_shared(compiler, source, original)

    disassembled = subprocess.run(
        [objdump, "-drwC", str(original)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    byte_body = disassembled.stdout.split("<byte_only>:", 1)[1].split("\n\n", 1)[0]
    assert re.search(r"%(?:dl|r8b)\b", byte_body), byte_body
    full_body = disassembled.stdout.split("<full_word>:", 1)[1].split("\n\n", 1)[0]
    assert "%edi" in full_body or "%rdi" in full_body, full_body

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=128)
    targets = {
        function.name: int(function.entry_point.value)
        for function in functions
        if function.name in {"byte_only", "full_word"}
    }
    assert targets.keys() == {"byte_only", "full_word"}, [
        function.name for function in functions
    ]

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
        [targets["byte_only"], targets["full_word"]],
        style="decbench",
        timeout_ms=8000,
    )
    rendered = {int(va): text for _, va, text in results}
    byte_code = rendered[targets["byte_only"]]
    full_code = rendered[targets["full_word"]]
    assert re.search(
        r"\bbyte_only\(char \* arg0, char \* arg1, signed char arg2\)",
        byte_code,
    ), byte_code
    assert re.search(r"\bfull_word\(long arg0\)", full_code), full_code
    assert "full_word(signed char arg0)" not in full_code

    rebuilt_source.write_text(byte_code + "\n" + full_code + "\n")
    _build_shared(compiler, rebuilt_source, rebuilt)

    original_lib = ctypes.CDLL(str(original))
    rebuilt_lib = ctypes.CDLL(str(rebuilt))
    for library in (original_lib, rebuilt_lib):
        library.byte_only.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_byte]
        library.byte_only.restype = ctypes.c_int
        library.full_word.argtypes = [ctypes.c_int]
        library.full_word.restype = ctypes.c_int

    byte_cases = [
        (b"alpha", b"alphi", ord("h")),
        (b"same", b"same", ord("m")),
        (b"", b"x", 0),
        (bytes([0x80, 0]), bytes([0x7F, 0]), -128),
    ]
    for left, right, until in byte_cases:
        assert rebuilt_lib.byte_only(left, right, until) == original_lib.byte_only(
            left, right, until
        )
    for value in [-0x80000000, -249, 0, 7, 263, 0x7FFFFFFF]:
        assert rebuilt_lib.full_word(value) == original_lib.full_word(value)
