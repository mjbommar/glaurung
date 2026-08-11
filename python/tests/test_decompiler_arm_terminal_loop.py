"""Real stripped ARM coverage for terminal infinite-loop recovery."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tests" / "fixtures" / "arm_terminal_loop.c"


def _required_tool(name: str) -> str:
    path = shutil.which(f"arm-none-eabi-{name}")
    if path is None:
        pytest.skip(f"arm-none-eabi-{name} is required for the ARM fixture")
    return path


def test_thumb_terminal_self_branch_recovers_source_infinite_loop(
    tmp_path: Path,
) -> None:
    """A terminal machine self-branch must become structured source control."""
    tools = {name: _required_tool(name) for name in ("gcc", "nm", "objdump", "strip")}

    binary = tmp_path / "arm_terminal_loop.elf"
    stripped = tmp_path / "arm_terminal_loop.stripped.elf"
    subprocess.run(
        [
            tools["gcc"],
            "-mcpu=cortex-m4",
            "-mthumb",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,main",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(SOURCE),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    symbols = subprocess.run(
        [tools["nm"], str(binary)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    main_address = next(
        int(line.split()[0], 16)
        for line in symbols.splitlines()
        if line.split()[-1:] == ["main"]
    )
    disassembly = subprocess.run(
        [tools["objdump"], "-d", "--disassemble=main", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert re.search(r"(?m)^\s*([0-9a-f]+):.*\bb(?:\.n)?\s+\1\b", disassembly), (
        disassembly
    )

    subprocess.run(
        [tools["strip"], "--strip-all", "-o", str(stripped), str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    decompiled = g.ir.decompile_at(str(stripped), main_address & ~1, style="decbench")

    assert "while (1)" in decompiled, decompiled
    assert "goto " not in decompiled, decompiled
    assert re.search(r"if \([^\n]+\) \{\n\s+[^\n]+\(\);\n\s+\}", decompiled), decompiled
