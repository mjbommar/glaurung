"""Tests for ABI-aware argument recovery (#162).

Extends #195 propagation with Win64 (rcx/rdx/r8/r9) and AAPCS64
(x0-x7) calling conventions. The SysV path is already covered by
test_type_propagation.py; here we exercise the ABI dispatch and the
non-SysV register tables.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from glaurung.llm.kb import xref_db


def test_register_tables_are_distinct_per_abi() -> None:
    """Sanity: the three argument-register tables are *different*. If
    they accidentally collapse, propagation would silently misattribute
    parameters on cross-ABI binaries."""
    sysv_arg0 = xref_db._SYSV_ARG_REGS_X64[0][0]
    win64_arg0 = xref_db._WIN64_ARG_REGS_X64[0][0]
    aapcs64_arg0 = xref_db._AAPCS64_ARG_REGS[0][0]
    assert sysv_arg0 == "rdi"
    assert win64_arg0 == "rcx"
    assert aapcs64_arg0 == "x0"
    assert sysv_arg0 != win64_arg0  # The defining difference.


def test_operand_destination_register_with_win64_table() -> None:
    """Win64 uses rcx/rdx/r8/r9 as the first four args. Operands
    naming those registers should resolve under the Win64 table."""
    cases = [
        ("rcx", "rcx"),
        ("ecx", "rcx"),
        ("rdx", "rdx"),
        ("r8d", "r8"),
        ("r9w", "r9"),
        # rdi is NOT a Win64 arg register — must reject under this table.
        ("rdi", None),
        ("rsi", None),
    ]
    for op, expected in cases:
        got = xref_db._operand_destination_register(
            op, arg_regs=xref_db._WIN64_ARG_REGS_X64,
        )
        assert got == expected, f"Win64 {op!r} → {got!r}, want {expected!r}"


def test_operand_destination_register_with_aapcs64_table() -> None:
    """AArch64 args go in x0..x7. The 32-bit aliases are w0..w7."""
    cases = [
        ("x0", "x0"),
        ("w0", "x0"),
        ("x7", "x7"),
        ("w3", "x3"),
        # x8 is the indirect-result register, not an arg slot.
        ("x8", None),
        ("rdi", None),  # x86 register doesn't fit AArch64
    ]
    for op, expected in cases:
        got = xref_db._operand_destination_register(
            op, arg_regs=xref_db._AAPCS64_ARG_REGS,
        )
        assert got == expected, f"AAPCS64 {op!r} → {got!r}, want {expected!r}"


def test_default_arg_regs_is_sysv() -> None:
    """Backward compat: callers that don't pass `arg_regs=` still get
    SysV behaviour, matching the pre-#162 contract."""
    assert xref_db._operand_destination_register("rdi") == "rdi"
    assert xref_db._operand_destination_register("rcx") == "rcx"
    # No table → SysV — rcx is arg3 there, valid; w0 is not in SysV.
    assert xref_db._operand_destination_register("w0") is None


def test_select_arg_regs_picks_aarch64_for_arm64_binary() -> None:
    """`_select_arg_regs` must pick AAPCS64 when the binary is ARM64.
    Use the actual ARM64 sample to drive this — no mocking."""
    candidates = [
        Path("samples/binaries/platforms/linux/arm64/export/native/gcc/O2/hello-gcc-O2"),
        Path("samples/binaries/platforms/linux/arm64/export/fortran/hello-gfortran-O2"),
    ]
    arm_path = next((p for p in candidates if p.exists()), None)
    if arm_path is None:
        pytest.skip("no ARM64 sample available")
    regs = xref_db._select_arg_regs(str(arm_path))
    assert regs is xref_db._AAPCS64_ARG_REGS, (
        f"expected AAPCS64 table for ARM64 binary; got first reg "
        f"{regs[0][0] if regs else None!r}"
    )


def test_select_arg_regs_picks_sysv_for_linux_x86_64() -> None:
    """A standard Linux x86_64 ELF must select the SysV table."""
    elf = Path(
        "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
    )
    if not elf.exists():
        pytest.skip(f"missing sample {elf}")
    regs = xref_db._select_arg_regs(str(elf))
    assert regs is xref_db._SYSV_ARG_REGS_X64


def test_select_arg_regs_picks_win64_for_pe_x86_64() -> None:
    """Any PE x86_64 binary should default to Win64 calling convention.
    MinGW PE samples use SysV in practice, but the matcher tolerates
    that — wrong table just produces zero matches, not crashes."""
    # Use whatever PE sample we have; the only branch under test is
    # format=PE + arch=x86_64 → Win64 table.
    pe_candidates = [
        Path("samples/binaries/platforms/linux/amd64/cross/windows-x86_64/hello-c-x86_64-mingw.exe"),
    ]
    pe = next((p for p in pe_candidates if p.exists()), None)
    if pe is None:
        pytest.skip("no Windows x86_64 PE sample available")
    regs = xref_db._select_arg_regs(str(pe))
    assert regs is xref_db._WIN64_ARG_REGS_X64


def test_select_arg_regs_falls_back_to_sysv_on_triage_failure(tmp_path: Path) -> None:
    """If triage raises (e.g. file is not a binary), default to SysV
    rather than crashing the propagation pass."""
    bogus = tmp_path / "not-a-binary.txt"
    bogus.write_text("hello world\n")
    regs = xref_db._select_arg_regs(str(bogus))
    assert regs is xref_db._SYSV_ARG_REGS_X64
