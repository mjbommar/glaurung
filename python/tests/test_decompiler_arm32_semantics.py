"""Real source-to-QEMU regressions for ARM32 instruction semantics."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))

import arch_roundtrip as A  # ty: ignore[unresolved-import]  # added above
import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow  # ty: ignore[unresolved-attribute]


def test_a32_o0_shift_and_signed_multiply_round_trip_loop_fixture(
    tmp_path: Path,
) -> None:
    """A32 instruction words, typed LLIR, emitted C, and QEMU agree for loops."""
    arch = "armv7_a32"
    compiler = A.TARGETS[arch].cc
    objdump = "arm-linux-gnueabihf-objdump"
    missing = [
        tool
        for tool in (compiler, objdump, "glaurung", "qemu-arm")
        if shutil.which(tool) is None
    ]
    if missing:
        pytest.skip(f"A32 round-trip tools are missing: {', '.join(missing)}")

    fixture = "03_loop_shapes"
    shift_function = "while_prefix"
    signed_function = "cond_reload_and_transform"
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-{arch}-O0.so"
    ok, error = A._cross_build(arch, source, "O0", target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-O0.so"
    ok, error = A._reference_build(source, "O0", reference)
    assert ok, error

    disassembled = subprocess.run(
        [objdump, "-d", f"--disassemble={shift_function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    assert re.search(r"\blsl\s+r3,\s*r3,\s*#2\b", disassembled.stdout), (
        disassembled.stdout
    )

    signed_asm = subprocess.run(
        [objdump, "-d", f"--disassemble={signed_function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert signed_asm.returncode == 0, signed_asm.stderr
    assert "smull" in signed_asm.stdout, signed_asm.stdout

    def decompile(function: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "glaurung",
                "decompile",
                str(target),
                "--func",
                function,
                "--style",
                "decbench",
                "--timeout-ms",
                "10000",
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "GLAURUNG_DUMP_PASSES": "1"},
        )

    lifted = decompile(shift_function)
    assert lifted.returncode == 0, lifted.stderr
    assert "===== prepared numbered LLIR =====" in lifted.stderr
    assert re.search(r"Shl %r3#\d+ 2", lifted.stderr), lifted.stderr
    assert not re.search(r"Shl %r3#\d+ %r3#\d+", lifted.stderr), lifted.stderr
    assert re.search(r"arg0\[\w+\]", lifted.stdout), lifted.stdout

    signed = decompile(signed_function)
    assert signed.returncode == 0, signed.stderr
    assert "===== prepared numbered LLIR =====" in signed.stderr
    assert "intrinsic arm.smul_hi.32" in signed.stderr, signed.stderr
    assert "long long" in signed.stdout, signed.stdout
    assert "0x92492493 *" not in signed.stdout, signed.stdout

    functions = {shift_function, signed_function}
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{arch}:O0",
        native_cc=A.native_cc(arch),
        native_runner=A.native_runner(arch),
        only=functions,
    )
    assert {
        function: results[function]["status"] for function in sorted(functions)
    } == {function: "pass" for function in sorted(functions)}, results
