"""Real i386 REP-STOS source-to-QEMU regression coverage."""

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

ARCH = "i386"
FIXTURE = "16_red_black_tree"
FUNCTION = "rb_validate"


def _require_tools() -> None:
    """Skip only if the host cannot build, inspect, or execute i386."""
    runner = A.native_runner(ARCH)
    assert runner is not None, "i386 has no target-native runner"
    required = {A.TARGETS[ARCH].cc, "glaurung", "objdump", runner[0]}
    missing = sorted(tool for tool in required if shutil.which(tool) is None)
    if missing:
        pytest.skip(f"i386 round-trip tools are missing: {', '.join(missing)}")


def _build(tmp_path: Path, opt: str) -> tuple[Path, Path, Path]:
    """Build the checked-in source for i386 and the host reference."""
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{FIXTURE}.c"
    binary = tmp_path / f"{FIXTURE}-{ARCH}-{opt}.so"
    ok, error = A._cross_build(ARCH, source, opt, binary)
    assert ok, error
    reference = tmp_path / f"{FIXTURE}-host-{opt}.so"
    ok, error = A._reference_build(source, opt, reference)
    assert ok, error
    return source, binary, reference


def _decompile(binary: Path) -> subprocess.CompletedProcess[str]:
    """Decompile while retaining numbered LLIR and AST pass evidence."""
    return subprocess.run(
        [
            "glaurung",
            "decompile",
            str(binary),
            "--func",
            FUNCTION,
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


@pytest.mark.parametrize("opt", ("O0", "O2"))  # ty: ignore[unresolved-attribute]
def test_i386_rep_stos_round_trips_source_asm_ir_c_and_execution(
    tmp_path: Path, opt: str
) -> None:
    """REP STOS must initialize every source array element, not only one."""
    _require_tools()
    source, binary, reference = _build(tmp_path, opt)

    source_text = source.read_text()
    assert "int32_t parents[16] = {0};" in source_text

    disassembled = subprocess.run(
        ["objdump", "-d", f"--disassemble={FUNCTION}", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    assert re.search(r"\brep\s+stos", disassembled.stdout), disassembled.stdout

    decompiled = _decompile(binary)
    assert decompiled.returncode == 0, decompiled.stderr
    assert "===== prepared numbered LLIR =====" in decompiled.stderr
    assert "intrinsic memory.fill.4.word4" in decompiled.stderr
    assert re.search(r"%df(?:#\d+)? = 0", decompiled.stderr), decompiled.stderr

    loop = re.search(
        r"(?P<count>t\d+) = 16;\s+"
        r"while \(\((?P=count) != 0\)\) \{(?P<body>.*?)\n\s*\}",
        decompiled.stdout,
        re.DOTALL,
    )
    assert loop is not None, decompiled.stdout
    count = loop.group("count")
    assert re.search(rf"\b{count} = \({count} - 1\);", loop.group("body")), (
        decompiled.stdout
    )
    assert "? -4 : 4" in loop.group("body"), decompiled.stdout

    results = D.run(
        str(binary),
        str(source),
        FIXTURE,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{ARCH}:{opt}",
        native_cc=A.native_cc(ARCH),
        native_runner=A.native_runner(ARCH),
        only={FUNCTION},
    )
    assert results[FUNCTION]["status"] == "pass", results
    assert results[FUNCTION]["detail"].endswith("cases (native target ABI)"), results
