"""Real ILP32 wide-return round trips across the ABI call boundary."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))

import arch_roundtrip as A  # ty: ignore[unresolved-import]  # added above
import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow  # ty: ignore[unresolved-attribute]

FIXTURE = "11_call_shapes"
FUNCTIONS = {"widen_mul", "call_fold_wide_result"}


@dataclass(frozen=True)
class TargetEvidence:
    """Tooling and stable instruction evidence for one ILP32 ABI."""

    arch: str
    objdump: str
    callee_pattern: str
    caller_patterns: tuple[str, ...]
    low_register: str
    high_register: str


TARGETS = (
    TargetEvidence(
        arch="armv7_a32",
        objdump="arm-linux-gnueabihf-objdump",
        callee_pattern=r"\bumull\b",
        caller_patterns=(r"\bstrd\s+r0",),
        low_register="r0",
        high_register="r1",
    ),
    TargetEvidence(
        arch="i386",
        objdump="objdump",
        callee_pattern=r"\bmul\s+%e[a-z]+",
        caller_patterns=(r"mov\s+%eax,", r"mov\s+%edx,"),
        low_register="rax",
        high_register="rdx",
    ),
)


def _require_tools(target: TargetEvidence) -> None:
    """Skip only when this host genuinely cannot build, inspect, or run a lane."""
    runner = A.native_runner(target.arch)
    assert runner is not None, f"{target.arch} has no target-native runner"
    required = {
        A.TARGETS[target.arch].cc,
        target.objdump,
        "glaurung",
        runner[0],
    }
    missing = sorted(tool for tool in required if shutil.which(tool) is None)
    if missing:
        pytest.skip(f"{target.arch} round-trip tools are missing: {', '.join(missing)}")


def _build(tmp_path: Path, target: TargetEvidence) -> tuple[Path, Path, Path]:
    """Build the checked-in source for the target and pinned host reference."""
    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{FIXTURE}.c"
    binary = tmp_path / f"{FIXTURE}-{target.arch}-O0.so"
    ok, error = A._cross_build(target.arch, source, "O0", binary)
    assert ok, error
    reference = tmp_path / f"{FIXTURE}-{target.arch}-reference-O0.so"
    ok, error = A._reference_build(source, "O0", reference)
    assert ok, error
    return source, binary, reference


def _disassemble(binary: Path, target: TargetEvidence, function: str) -> str:
    """Return the target disassembly for one exported source function."""
    result = subprocess.run(
        [target.objdump, "-d", f"--disassemble={function}", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _decompile(binary: Path) -> subprocess.CompletedProcess[str]:
    """Decompile the caller and retain numbered LLIR plus AST-pass evidence."""
    return subprocess.run(
        [
            "glaurung",
            "decompile",
            str(binary),
            "--func",
            "call_fold_wide_result",
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


@pytest.mark.parametrize("target", TARGETS, ids=lambda target: target.arch)  # ty: ignore[unresolved-attribute]
def test_ilp32_wide_return_round_trips_source_asm_ir_c_and_execution(
    tmp_path: Path, target: TargetEvidence
) -> None:
    """Both ABI result words must become one exact 64-bit source value."""
    _require_tools(target)
    source, binary, reference = _build(tmp_path, target)

    source_text = source.read_text()
    assert "uint64_t widen_mul(uint32_t a, uint32_t b)" in source_text
    assert "uint64_t r = widen_mul(a, b);" in source_text

    callee_asm = _disassemble(binary, target, "widen_mul")
    assert re.search(target.callee_pattern, callee_asm), callee_asm
    caller_asm = _disassemble(binary, target, "call_fold_wide_result")
    for pattern in target.caller_patterns:
        assert re.search(pattern, caller_asm), caller_asm

    decompiled = _decompile(binary)
    assert decompiled.returncode == 0, decompiled.stderr
    assert "===== prepared numbered LLIR =====" in decompiled.stderr
    assert re.search(r"\bcall 0x[0-9a-f]+", decompiled.stderr), decompiled.stderr
    assert re.search(
        rf"store\[4 bytes\].*<- %{target.low_register}(?:#\d+)?",
        decompiled.stderr,
    ), decompiled.stderr
    assert re.search(
        rf"store\[4 bytes\].*<- %{target.high_register}(?:#\d+)?",
        decompiled.stderr,
    ), decompiled.stderr
    assert "===== after split_call_result_lifetimes =====" in decompiled.stderr
    assert f"%{target.high_register}#call_lifetime_high_0" in decompiled.stderr

    assert "extern unsigned long long widen_mul(unsigned int, unsigned int);" in (
        decompiled.stdout
    )
    wide_local = re.search(r"unsigned long long (var\d+);", decompiled.stdout)
    assert wide_local is not None, decompiled.stdout
    local = wide_local.group(1)
    assert f"{local} = widen_mul(arg0, arg1);" in decompiled.stdout
    assert f"((unsigned long long)({local}) >> 32)" in decompiled.stdout
    assert f"((unsigned long)({local}) >> 32)" not in decompiled.stdout

    results = D.run(
        str(binary),
        str(source),
        FIXTURE,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{target.arch}:O0",
        native_cc=A.native_cc(target.arch),
        native_runner=A.native_runner(target.arch),
        only=FUNCTIONS,
    )
    assert {name: results[name]["status"] for name in sorted(FUNCTIONS)} == {
        name: "pass" for name in sorted(FUNCTIONS)
    }, results
    assert all(
        result["detail"].endswith("cases (native target ABI)")
        for result in results.values()
    ), results
