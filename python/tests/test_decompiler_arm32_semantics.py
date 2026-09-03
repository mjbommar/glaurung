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

A32_ARCH = "armv7_a32"
A32_OBJDUMP = "arm-linux-gnueabihf-objdump"
ARM32_ARCHES = ("armv7", A32_ARCH)


def _build_a32_fixture(tmp_path: Path, fixture: str) -> tuple[Path, Path, Path]:
    """Build one A32 fixture and its pinned host-side reference."""
    return _build_arm32_fixture(tmp_path, fixture, A32_ARCH, "O0")


def _build_arm32_fixture(
    tmp_path: Path, fixture: str, arch: str, opt: str
) -> tuple[Path, Path, Path]:
    """Build one ARM32 fixture and its pinned host-side reference."""
    missing = [
        tool
        for tool in (
            A.TARGETS[arch].cc,
            A32_OBJDUMP,
            "glaurung",
            "qemu-arm",
        )
        if shutil.which(tool) is None
    ]
    if missing:
        pytest.skip(f"A32 round-trip tools are missing: {', '.join(missing)}")

    source = ROOT / "tests" / "decompiler_fixtures" / "src" / f"{fixture}.c"
    target = tmp_path / f"{fixture}-{arch}-{opt}.so"
    ok, error = A._cross_build(arch, source, opt, target)
    assert ok, error
    reference = tmp_path / f"{fixture}-host-{opt}.so"
    ok, error = A._reference_build(source, opt, reference)
    assert ok, error
    return source, target, reference


def _decompile(target: Path, function: str) -> subprocess.CompletedProcess[str]:
    """Decompile one function while retaining the numbered IR evidence."""
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


def _assert_qemu_round_trip(
    target: Path,
    source: Path,
    reference: Path,
    fixture: str,
    functions: set[str],
    *,
    arch: str = A32_ARCH,
    opt: str = "O0",
) -> None:
    """Require every selected source function to agree under ARM32 QEMU."""
    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{arch}:{opt}",
        native_cc=A.native_cc(arch),
        native_runner=A.native_runner(arch),
        only=functions,
    )
    assert {
        function: results[function]["status"] for function in sorted(functions)
    } == {function: "pass" for function in sorted(functions)}, results


def test_a32_o0_shift_and_signed_multiply_round_trip_loop_fixture(
    tmp_path: Path,
) -> None:
    """A32 instruction words, typed LLIR, emitted C, and QEMU agree for loops."""
    fixture = "03_loop_shapes"
    shift_function = "while_prefix"
    signed_function = "cond_reload_and_transform"
    source, target, reference = _build_a32_fixture(tmp_path, fixture)

    disassembled = subprocess.run(
        [A32_OBJDUMP, "-d", f"--disassemble={shift_function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    assert re.search(r"\blsl\s+r3,\s*r3,\s*#2\b", disassembled.stdout), (
        disassembled.stdout
    )

    signed_asm = subprocess.run(
        [A32_OBJDUMP, "-d", f"--disassemble={signed_function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert signed_asm.returncode == 0, signed_asm.stderr
    assert "smull" in signed_asm.stdout, signed_asm.stdout

    lifted = _decompile(target, shift_function)
    assert lifted.returncode == 0, lifted.stderr
    assert "===== prepared numbered LLIR =====" in lifted.stderr
    assert re.search(r"Shl %r3#\d+ 2", lifted.stderr), lifted.stderr
    assert not re.search(r"Shl %r3#\d+ %r3#\d+", lifted.stderr), lifted.stderr
    assert re.search(r"p\[\w+\]", lifted.stdout), lifted.stdout

    signed = _decompile(target, signed_function)
    assert signed.returncode == 0, signed.stderr
    assert "===== prepared numbered LLIR =====" in signed.stderr
    assert "intrinsic arm.smul_hi.32" in signed.stderr, signed.stderr
    assert "long long" in signed.stdout, signed.stdout
    assert "0x92492493 *" not in signed.stdout, signed.stdout

    functions = {shift_function, signed_function}
    _assert_qemu_round_trip(target, source, reference, fixture, functions)


def test_a32_o0_frame_pointer_stack_arguments_round_trip(
    tmp_path: Path,
) -> None:
    """A32 incoming stack arguments retain their source roles through QEMU."""
    fixture = "06_calling_conventions"
    source, target, reference = _build_a32_fixture(tmp_path, fixture)

    disassembled = subprocess.run(
        [A32_OBJDUMP, "-d", "--disassemble=sum_arg5", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    assert re.search(r"\bldr\s+r2,\s*\[fp,\s*#4\]", disassembled.stdout), (
        disassembled.stdout
    )

    lifted = _decompile(target, "sum_arg5")
    assert lifted.returncode == 0, lifted.stderr
    assert "===== prepared numbered LLIR =====" in lifted.stderr
    assert re.search(r"load\[4 bytes\].*Phys\(\"fp\"\).*disp: 4", lifted.stderr), (
        lifted.stderr
    )
    assert "int a4" in lifted.stdout, lifted.stdout
    assert "stack_0" not in lifted.stdout, lifted.stdout

    functions = {
        "forward_sum6",
        "sum_arg5",
        "sum_arg6",
        "sum_arg7",
        "sum_arg8",
        "sum_arg9",
        "sum_arg10",
        "sum_mixed_widths",
    }
    _assert_qemu_round_trip(target, source, reference, fixture, functions)


@pytest.mark.parametrize("arch", ARM32_ARCHES)  # ty: ignore[unresolved-attribute]
def test_arm32_o2_rb_validate_round_trips_source_asm_ir_c_and_execution(
    tmp_path: Path, arch: str
) -> None:
    """ARM call, aggregate address, stack alias, and LDM semantics stay exact."""
    fixture = "16_red_black_tree"
    function = "rb_validate"
    source, target, reference = _build_arm32_fixture(tmp_path, fixture, arch, "O2")

    source_text = source.read_text()
    assert "int32_t parents[16] = {0};" in source_text
    assert "node_stack[top] = root;" in source_text

    disassembled = subprocess.run(
        [A32_OBJDUMP, "-d", f"--disassemble={function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    assert re.search(r"\b(?:bl|blx)\b.*<memset@plt>", disassembled.stdout), (
        disassembled.stdout
    )
    if arch == A32_ARCH:
        assert re.search(
            r"\bldr\s+\w+,\s*\[\w+,\s*\w+,\s*lsl #4\]", disassembled.stdout
        ), disassembled.stdout
        assert "ldmib" in disassembled.stdout, disassembled.stdout
    else:
        assert re.search(
            r"\bldr\.w\s+\w+,\s*\[\w+,\s*\w+,\s*lsl #2\]", disassembled.stdout
        ), disassembled.stdout

    decompiled = _decompile(target, function)
    assert decompiled.returncode == 0, decompiled.stderr
    assert "===== prototype-resolved LLIR =====" in decompiled.stderr
    assert "===== prepared numbered LLIR =====" in decompiled.stderr
    # The fill byte renders as a bare `0`, not `(int)(0)`. `5e24383` added
    # `integer_call_arg_cast_is_redundant` (src/ir/ast.rs), which drops a call
    # argument cast only when `declared_reg_ctype(register) == parameter_type`
    # — the identity, here `int` to `int`. The size argument keeps its
    # `(__SIZE_TYPE__)` cast in the same call because that one is NOT the
    # identity, which is what shows the elision is proof-backed rather than
    # cosmetic. Asserted both ways so a re-regression fails in either
    # direction.
    assert re.search(r"memset\([^\n]+,\s*0,[^\n]+64", decompiled.stdout), (
        decompiled.stdout
    )
    assert "(int)(0)" not in decompiled.stdout, decompiled.stdout
    assert "memset()" not in decompiled.stdout
    assert re.search(r"local_[0-9a-f]+\[64\]", decompiled.stdout), decompiled.stdout
    assert not re.search(r"\*\(int \*\)\(\(sp \+", decompiled.stdout), decompiled.stdout
    if arch == A32_ARCH:
        assert re.search(r"scale: 16, disp: 0, size: 4", decompiled.stderr), (
            decompiled.stderr
        )
        assert re.search(r"load\[4 bytes\].*disp: 4, size: 4", decompiled.stderr), (
            decompiled.stderr
        )
        assert re.search(r"load\[4 bytes\].*disp: 8, size: 4", decompiled.stderr), (
            decompiled.stderr
        )
    else:
        assert re.search(
            r"\b(var\d+)\s*=\s*\(\*\(int \*\)\([^\n]+\)\s*\+\s*1\);"
            r"\s*\n\s*\*\(int \*\)\([^\n]+\)\s*=\s*\1;",
            decompiled.stdout,
        ), decompiled.stdout

    results = D.run(
        str(target),
        str(source),
        fixture,
        seed=1234,
        fuzz=M.FIXTURE_FUZZ,
        reference_so=str(reference),
        lane=f"{arch}:O2",
        native_cc=A.native_cc(arch),
        native_runner=A.native_runner(arch),
        only={function},
    )
    assert results[function]["status"] == "pass", results
    assert results[function]["detail"].endswith("cases (native target ABI)"), results


@pytest.mark.parametrize(  # ty: ignore[unresolved-attribute]
    ("arch", "opt"),
    (("armv7", "O0"), ("armv7", "O2"), (A32_ARCH, "O0"), (A32_ARCH, "O2")),
)
def test_arm32_packet_parser_round_trips_bitfields_rotates_and_smlabb(
    tmp_path: Path, arch: str, opt: str
) -> None:
    """The packet summary stays exact across source, ARM IR/C, and QEMU."""
    fixture = "07_packet_parser"
    function = "parse_packet"
    source, target, reference = _build_arm32_fixture(tmp_path, fixture, arch, opt)

    source_text = source.read_text()
    assert "sum = (sum << 1) | (sum >> 31);" in source_text
    assert "+ (int)hdr.type * 7" in source_text

    parse_asm = subprocess.run(
        [A32_OBJDUMP, "-d", f"--disassemble={function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert parse_asm.returncode == 0, parse_asm.stderr
    assert re.search(r"\bror(?:\.w)?\b", parse_asm.stdout), parse_asm.stdout
    if opt == "O2":
        assert "smlabb" in parse_asm.stdout, parse_asm.stdout

    if opt == "O0":
        decode_asm = subprocess.run(
            [A32_OBJDUMP, "-d", "--disassemble=decode_header", str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert decode_asm.returncode == 0, decode_asm.stderr
        assert decode_asm.stdout.count("bfi") >= 2, decode_asm.stdout

        decoded = _decompile(target, "decode_header")
        assert decoded.returncode == 0, decoded.stderr
        assert "intrinsic bfi" not in decoded.stderr, decoded.stderr
        assert "/* asm: bfi */" not in decoded.stdout, decoded.stdout

    decompiled = _decompile(target, function)
    assert decompiled.returncode == 0, decompiled.stderr
    assert "===== prototype-resolved LLIR =====" in decompiled.stderr
    assert "intrinsic ror" not in decompiled.stderr, decompiled.stderr
    assert "intrinsic smlabb" not in decompiled.stderr, decompiled.stderr
    assert "/* asm: ror */" not in decompiled.stdout, decompiled.stdout
    assert "/* asm: smlabb */" not in decompiled.stdout, decompiled.stdout

    _assert_qemu_round_trip(
        target,
        source,
        reference,
        fixture,
        {function},
        arch=arch,
        opt=opt,
    )


@pytest.mark.parametrize("arch", ARM32_ARCHES)  # ty: ignore[unresolved-attribute]
def test_arm32_o2_finite_difference_round_trips_signed_long_accumulate(
    tmp_path: Path, arch: str
) -> None:
    """The signed 64-bit stencil survives split ARM32 destination registers."""
    fixture = "30_finite_difference"
    function = "heat_step_1d"
    source, target, reference = _build_arm32_fixture(tmp_path, fixture, arch, "O2")

    source_text = source.read_text()
    assert "int64_t weighted" in source_text
    assert "2 * (int64_t)source[i]" in source_text

    disassembled = subprocess.run(
        [A32_OBJDUMP, "-d", f"--disassemble={function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    assert re.search(r"\bsmlal\b", disassembled.stdout), disassembled.stdout

    decompiled = _decompile(target, function)
    assert decompiled.returncode == 0, decompiled.stderr
    assert "===== prepared numbered LLIR =====" in decompiled.stderr
    assert "intrinsic smlal" not in decompiled.stderr, decompiled.stderr
    assert "unknown(smlal)" not in decompiled.stderr, decompiled.stderr
    assert "<< 32" in decompiled.stderr, decompiled.stderr
    assert ">> 32" in decompiled.stderr, decompiled.stderr
    assert "/* asm: smlal */" not in decompiled.stdout, decompiled.stdout

    _assert_qemu_round_trip(
        target,
        source,
        reference,
        fixture,
        {function},
        arch=arch,
        opt="O2",
    )


@pytest.mark.parametrize("arch", ARM32_ARCHES)  # ty: ignore[unresolved-attribute]
def test_arm32_o0_rb_validate_round_trips_split_frame_addresses(
    tmp_path: Path, arch: str
) -> None:
    """O0 split affine frame addresses retain their debug-proven arrays."""
    fixture = "16_red_black_tree"
    function = "rb_validate"
    source, target, reference = _build_arm32_fixture(tmp_path, fixture, arch, "O0")

    source_text = source.read_text()
    assert "int32_t parents[16] = {0};" in source_text
    assert "int32_t node_stack[32];" in source_text
    assert "int32_t black_stack[32];" in source_text

    disassembled = subprocess.run(
        [A32_OBJDUMP, "-d", f"--disassemble={function}", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    if arch == A32_ARCH:
        assert re.search(r"\blsl\s+\w+,\s*\w+,\s*#2", disassembled.stdout), (
            disassembled.stdout
        )
        assert re.search(r"\bsub\s+\w+,\s*\w+,\s*#4", disassembled.stdout), (
            disassembled.stdout
        )
        assert re.search(r"\badd\s+\w+,\s*\w+,\s*fp", disassembled.stdout), (
            disassembled.stdout
        )
    else:
        assert re.search(r"\badd\.w\s+\w+,\s*\w+,\s*#384", disassembled.stdout), (
            disassembled.stdout
        )
        assert re.search(r"\badd\s+\w+,\s*r7", disassembled.stdout), disassembled.stdout

    decompiled = _decompile(target, function)
    assert decompiled.returncode == 0, decompiled.stderr
    assert "===== stack object hints =====" in decompiled.stderr
    for displacement, size in ((-332, 64), (-268, 128), (-140, 128)):
        assert re.search(
            rf'base: "entry_sp",\s+disp: {displacement},\s+size: {size}',
            decompiled.stderr,
        ), decompiled.stderr
    # `0` rather than `(int)(0)`; see the note on the other memset assertion.
    # The `(__SIZE_TYPE__)` cast beside it must survive — dropping that one too
    # would mean the elision had stopped checking the declared type.
    assert re.search(
        r"memset\(&local_[0-9a-f]+\[0\],\s*0,"
        r"\s*\(__SIZE_TYPE__\)\(64\)\)",
        decompiled.stdout,
    ), decompiled.stdout
    assert "long lr;" not in decompiled.stdout
    assert " = lr;" not in decompiled.stdout
    assert not re.search(r"unsigned char local_[48]\[(?:4|8)\];", decompiled.stdout)
    assert not re.search(r"<< 2\) - 4", decompiled.stdout), decompiled.stdout
    assert not re.search(r"\+ 384\).+- 132", decompiled.stdout), decompiled.stdout

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
        only={function},
    )
    assert results[function]["status"] == "pass", results
    assert results[function]["detail"].endswith("cases (native target ABI)"), results
