"""Real integration coverage for 32-bit x86 cdecl recovery."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest

PE32_SAMPLE = Path(
    "samples/binaries/platforms/windows/amd64/export/windows/i686/O0/"
    "hello-c-mingw32-O0.exe"
)


def _compile_i386(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    """Build a non-PIE i386 executable with the host GCC multilib toolchain."""
    return subprocess.run(
        [
            "gcc",
            "-m32",
            "-O0",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-fno-stack-protector",
            "-w",
            "-o",
            str(output),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(not PE32_SAMPLE.exists(), reason="PE32 sample missing")
def test_real_mingw32_main_has_bounded_cdecl_arguments() -> None:
    """The checked-in PE32 sample must not fabricate huge argument indices."""
    text = g.ir.decompile_at(
        str(PE32_SAMPLE),
        0x40160C,
        timeout_ms=1000,
        style="decbench",
    )

    assert "\nint _main(int arg0, int arg1) {\n" in text, text[:300]
    assert "arg536870" not in text
    assert "_printf(0x409044)" in text
    assert "strlen(" in text and "strlen()" not in text
    assert "_print_sum(stack_1)" in text


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
def test_i386_cdecl_decompile_recompile_execute_round_trip(tmp_path: Path) -> None:
    """Compare a real i386 binary with an executable rebuilt decompilation."""
    original_source = tmp_path / "original.c"
    original_source.write_text(
        """
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int helper3(int a, int b, int c) {
    return a + 2 * b + 3 * c;
}

__attribute__((noinline)) int cdecl_chain(int a, int b, int c) {
    return helper3(a, b, c);
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    printf("%d\\n", cdecl_chain(atoi(argv[1]), atoi(argv[2]), atoi(argv[3])));
    return 0;
}
""".strip()
        + "\n"
    )
    original = tmp_path / "original"
    built = _compile_i386(original_source, original)
    if built.returncode != 0 and (
        "crt1.o" in built.stderr
        or "Scrt1.o" in built.stderr
        or "cannot find -lgcc" in built.stderr
        or "bits/libc-header-start.h" in built.stderr
    ):
        pytest.skip(f"gcc multilib is unavailable: {built.stderr.splitlines()[-1]}")
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=500)
    target = next((f for f in functions if f.name == "cdecl_chain"), None)
    assert target is not None, "cdecl_chain was not discovered"
    target_va = int(target.entry_point.value)
    generated = g.ir.decompile_at(
        str(original),
        target_va,
        timeout_ms=8000,
        style="decbench",
    )
    assert "cdecl_chain(int arg0, int arg1, int arg2)" in generated, generated
    assert "helper3(arg0, arg1, arg2)" in generated, generated

    rebuilt_source = tmp_path / "rebuilt.c"
    rebuilt_source.write_text(
        """
#include <stdio.h>
#include <stdlib.h>
int helper3(int, int, int);
""".lstrip()
        + generated
        + """

__attribute__((noinline)) int helper3(int a, int b, int c) {
    return a + 2 * b + 3 * c;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    printf("%d\\n", cdecl_chain(atoi(argv[1]), atoi(argv[2]), atoi(argv[3])));
    return 0;
}
"""
    )
    rebuilt = tmp_path / "rebuilt"
    rebuilt_result = _compile_i386(rebuilt_source, rebuilt)
    assert rebuilt_result.returncode == 0, (
        f"generated C did not rebuild as i386:\n{rebuilt_result.stderr}\n{generated}"
    )

    vectors = [(-9, 4, 7), (0, 0, 0), (1, 2, 3), (31, -17, 5)]
    for vector in vectors:
        argv = [str(value) for value in vector]
        expected = subprocess.run(
            [str(original), *argv],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        actual = subprocess.run(
            [str(rebuilt), *argv],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        oracle = f"{vector[0] + 2 * vector[1] + 3 * vector[2]}\n"
        assert expected.returncode == 0, expected.stderr
        assert expected.stdout == oracle
        assert actual.returncode == 0, actual.stderr
        assert actual.stdout == oracle, (
            f"i386 cdecl mismatch for {vector}: expected {oracle!r}, got {actual.stdout!r}"
        )
