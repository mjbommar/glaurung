"""Canonical source recovery for the smallest hosted MinGW C program."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


EXPECTED = """// glaurung: main @ {va:#x}
int main(void) {{
    extern int puts(const char *);
    puts("Hello, World!");
    return 0;
}}
"""


@pytest.mark.parametrize("target", ["x86_64", "i686"])
@pytest.mark.parametrize("stripped", [False, True], ids=["symbols", "stripped"])
@pytest.mark.parametrize("optimization", ["O0", "O1", "O2", "O3"])
def test_mingw_hello_is_canonical(
    tmp_path: Path, target: str, stripped: bool, optimization: str
) -> None:
    """PE decoration and CRT initialization must not leak into source C."""
    compiler = shutil.which(f"{target}-w64-mingw32-gcc")
    strip = shutil.which(f"{target}-w64-mingw32-strip")
    if compiler is None or (stripped and strip is None):
        pytest.skip(f"{target} MinGW toolchain unavailable")

    source = tmp_path / "hello.c"
    binary = tmp_path / "hello.exe"
    source.write_text(
        '#include <stdio.h>\nint main(void) { puts("Hello, World!"); return 0; }\n'
    )
    built = subprocess.run(
        [compiler, f"-{optimization}", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    if stripped:
        stripped_result = subprocess.run(
            [strip, "--strip-all", str(binary)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert stripped_result.returncode == 0, stripped_result.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=2000)
    main = next((function for function in functions if function.name == "main"), None)
    assert main is not None, [function.name for function in functions]
    va = int(main.entry_point.value)
    recovered = g.ir.decompile_at(str(binary), va, style="decbench")

    assert recovered == EXPECTED.format(va=va)
