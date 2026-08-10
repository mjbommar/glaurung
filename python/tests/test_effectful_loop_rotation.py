"""Real-binary regression tests for call-driven loop recovery."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def test_stripped_call_driven_loop_keeps_seed_and_latch_calls(tmp_path: Path) -> None:
    """Recover a head-tested loop without dropping its first or later call."""
    compiler = shutil.which("gcc")
    nm = shutil.which("nm")
    strip = shutil.which("strip")
    if compiler is None or nm is None or strip is None:
        pytest.skip("host gcc, nm, and strip are required")

    source = tmp_path / "effectful_loop.c"
    binary = tmp_path / "effectful_loop"
    stripped = tmp_path / "effectful_loop.stripped"
    source.write_text(
        "__attribute__((noinline)) long *cursor_next(\n"
        "    long **items, unsigned *index) {\n"
        "    unsigned current = *index;\n"
        "    if (current == 4) return (long *)0;\n"
        "    *index = current + 1;\n"
        "    return items[current];\n"
        "}\n"
        "__attribute__((noinline, used)) long drain_cursor(\n"
        "    long **items, unsigned *index) {\n"
        "    long total = 0;\n"
        "    long *item;\n"
        "    while ((item = cursor_next(items, index)) != (long *)0) {\n"
        "        total += *item;\n"
        "    }\n"
        "    return total;\n"
        "}\n"
        "int main(void) { return 0; }\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-O2",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    symbols = subprocess.run(
        [nm, "-n", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert symbols.returncode == 0, symbols.stderr
    address = next(
        int(line.split()[0], 16)
        for line in symbols.stdout.splitlines()
        if line.split()[-1:] == ["drain_cursor"]
    )

    shutil.copy2(binary, stripped)
    stripped_result = subprocess.run(
        [strip, "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped_result.returncode == 0, stripped_result.stderr

    generated = g.ir.decompile_at(
        str(stripped),
        address,
        style="decbench",
        timeout_ms=8000,
        max_functions=1,
    )

    call_assignments = [
        line
        for line in generated.splitlines()
        if re.search(r"= .*\bsub_[0-9a-f]+\)?\(", line)
    ]
    assert "while (1)" not in generated, generated
    assert re.search(r"while \(\(.+ != 0\)\)", generated), generated
    assert len(call_assignments) == 2, generated
    callees = re.findall(r"\b(sub_[0-9a-f]+)\)?\(", "\n".join(call_assignments))
    assert len(callees) == 2, generated
    assert callees[0] == callees[1], generated
