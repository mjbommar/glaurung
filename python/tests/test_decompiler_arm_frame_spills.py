"""Real ARM binary coverage for machine-frame spill cleanup."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def test_thumb_entry_lr_save_does_not_become_a_source_local(tmp_path: Path) -> None:
    """A real ``push {r7, lr}`` prologue must not invent C locals."""
    compiler = shutil.which("arm-none-eabi-gcc")
    objdump = shutil.which("arm-none-eabi-objdump")
    nm = shutil.which("arm-none-eabi-nm")
    if compiler is None or objdump is None or nm is None:
        pytest.skip("arm-none-eabi GCC/binutils are required for the ARM fixture")

    source = tmp_path / "arm_frame_spill.c"
    binary = tmp_path / "arm_frame_spill.elf"
    source.write_text(
        """
__attribute__((noinline)) int callee(int value) {
    return value + 1;
}

__attribute__((noinline)) int caller(int value) {
    return callee(value) + 2;
}
""".lstrip(),
        encoding="utf-8",
    )
    subprocess.run(
        [
            compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=hard",
            "-mfpu=fpv4-sp-d16",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,caller",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    disassembly = subprocess.run(
        [objdump, "-d", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "push\t{r7, lr}" in disassembly

    symbols = subprocess.run(
        [nm, str(binary)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    caller_address = next(
        int(line.split()[0], 16)
        for line in symbols.splitlines()
        if line.split()[-1:] == ["caller"]
    )
    decompiled = g.ir.decompile_at(str(binary), caller_address & ~1, style="decbench")

    assert "int caller(int value)" in decompiled
    assert "return (callee(value) + 2);" in decompiled
    assert "local_4" not in decompiled
    assert "long lr" not in decompiled
    assert "= lr" not in decompiled
