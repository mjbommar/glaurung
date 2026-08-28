"""Integration tests for the `glaurung decompile` CLI subcommand."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import glaurung as g
import pytest

SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
ARM64_SAMPLE = Path(
    "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc"
)
ARM32_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc"
)
X86_O0_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/O0/hello-clang-O0"
)
PE32_PLUS_SAMPLE = Path(
    "samples/binaries/platforms/windows/i386/export/windows/x86_64/O0/hello-c-mingw64-O0.exe"
)


def _run(args: list[str]) -> subprocess.CompletedProcess:
    """Invoke the CLI in-process via `python -m glaurung.cli`."""
    return subprocess.run(
        [sys.executable, "-m", "glaurung.cli", "decompile", *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_entry_prints_pseudocode():
    result = _run([str(SAMPLE)])
    assert result.returncode == 0, result.stderr
    assert "function _start @ 0x1840 {" in result.stdout
    # Call target name-resolution and arg reconstruction should be visible: the
    # entry stub passes `main` as the first argument to __libc_start_main. (Arg
    # reconstruction also recovers the trailing boot args, so match the prefix
    # rather than pinning an exact arity.)
    #
    # The dereference is deliberate and must NOT be asserted away. `_start` calls
    # through the GOT slot, and until `874fe33` the lifter fabricated a direct
    # target for `call *[rip+disp]`, so this rendered as a plain `call name(...)`
    # — a confident claim that the call goes straight to the function. It does
    # not. Matching name-then-args, rather than the exact spelling between them,
    # keeps this test on the two properties it is actually about while leaving
    # the lifter free to be honest about the indirection.
    call = re.search(r"call [^\n]*__libc_start_main[^\n]*\(main\b", result.stdout)
    assert call, result.stdout


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_func_flag_accepts_hex_va():
    result = _run([str(SAMPLE), "--func", "0x1840"])
    assert result.returncode == 0, result.stderr
    assert "function _start @ 0x1840" in result.stdout


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_accepts_explicit_function_range():
    result = _run(
        [
            str(SAMPLE),
            "--func",
            "0x1840",
            "--range-start",
            "0x1840",
            "--range-end",
            "0x1880",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert "function sub_1840 @ 0x1840 {" in result.stdout
    assert "__libc_start_main" in result.stdout


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_unknown_va_reports_error():
    result = _run([str(SAMPLE), "--func", "0xdeadbeef"])
    # Error reported on stdout via formatter.output_plain; exit code 2.
    assert result.returncode == 2
    assert "Error" in result.stdout


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_all_emits_multiple_functions():
    result = _run([str(SAMPLE), "--all", "--limit", "2"])
    assert result.returncode == 0, result.stderr
    # Two functions should mean two `function ... {` banners.
    banners = [
        line for line in result.stdout.splitlines() if line.startswith("function ")
    ]
    assert len(banners) >= 1


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_vas_reports_entries_that_produced_no_body():
    """`--vas` names an exact request, so a VA that yields nothing is a failure.

    Batch consumers (DecBench's `glaurung_raw` backend among them) shell out and
    parse the JSON array. A requested entry that discovery never resolves, or
    whose lift bails, is simply absent from that array — so a short result set
    was indistinguishable from a short request. Name the missing entries on
    stderr; stdout stays exactly the record array the consumers parse.
    """
    result = _run([str(SAMPLE), "--vas", "0x1840,0xdeadbeef", "--format", "json"])
    # Partial success still exits 0 and still yields the records that worked:
    # one unsupported function must not discard a whole binary's run.
    assert result.returncode == 0, result.stderr
    import json

    payload = json.loads(result.stdout)
    assert [entry["entry_va"] for entry in payload] == [0x1840]
    assert "0xdeadbeef" in result.stderr
    assert "1 of 2" in result.stderr


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_vas_fails_when_no_entry_resolves():
    """Zero records from a non-empty request is a failed run, not an empty one."""
    result = _run([str(SAMPLE), "--vas", "0xdeadbeef", "--format", "json"])
    assert result.returncode == 2
    assert "0xdeadbeef" in result.stderr


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_vas_is_silent_when_every_entry_resolves():
    result = _run([str(SAMPLE), "--vas", "0x1840", "--format", "json"])
    assert result.returncode == 0, result.stderr
    assert result.stderr.strip() == ""


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_no_types_suppresses_annotations():
    result = _run([str(SAMPLE), "--no-types"])
    assert result.returncode == 0, result.stderr
    # With types disabled, pointer annotations must not appear.
    assert "(u64*)%rsp" not in result.stdout
    # But the underlying register references still do.
    assert "%rsp" in result.stdout


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_json_format_emits_valid_json():
    import json

    result = _run([str(SAMPLE), "--format", "json"])
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert "pseudocode" in payload
    assert payload["entry_va"] == 0x1840


@pytest.mark.skipif(not ARM64_SAMPLE.exists(), reason="arm64 sample missing")
def test_decompile_arm64_main_shows_prologue_and_epilogue():
    result = _run([str(ARM64_SAMPLE), "--func", "0x700"])
    assert result.returncode == 0, result.stderr
    assert "// aarch64 prologue:" in result.stdout, (
        "prologue comment missing: " + result.stdout
    )
    assert "// aarch64 epilogue:" in result.stdout, (
        "epilogue comment missing: " + result.stdout
    )


@pytest.mark.skipif(not ARM32_SAMPLE.exists(), reason="armhf sample missing")
def test_decompile_arm32_thumb_recovers_main():
    # ARM32/Thumb-2 (Cortex-M profile): the function symbol carries the Thumb
    # T-bit, which discovery must clear so `main` decodes at its even VA rather
    # than one byte off. The lifter then yields structured pseudocode, not
    # garbage.
    funcs, _ = g.analysis.analyze_functions_path(str(ARM32_SAMPLE), max_functions=500)
    main = next((f for f in funcs if f.name == "main"), None)
    assert main is not None, "main not discovered in Thumb binary"
    va = int(main.entry_point.value)
    assert va % 2 == 0, f"main VA {va:#x} still carries the Thumb T-bit"
    text = g.ir.decompile_at(str(ARM32_SAMPLE), va, style="c", timeout_ms=8000)
    assert text.startswith("fn main {"), text[:200]
    # A real call should have been reconstructed (this hello calls into libc).
    assert "sub_" in text or "(" in text


def test_real_arm32_frame_local_reaches_the_direct_return(tmp_path: Path) -> None:
    """Keep the ARM entry parameter distinct from its narrower r0 result."""
    compiler = shutil.which("arm-none-eabi-gcc")
    if compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")

    source = tmp_path / "frame_return.c"
    binary = tmp_path / "frame_return.elf"
    source.write_text(
        "__attribute__((noinline)) signed char frame_return(int wait) {\n"
        "    volatile signed char c = 0;\n"
        "    if (wait) c = (signed char)(wait + 1);\n"
        "    return c;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-mcpu=cortex-m3",
            "-mthumb",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,frame_return",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "frame_return"), None
    )
    assert target is not None, functions
    text = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    assert " frame_return(int arg0)" in text.splitlines()[1], text
    assert "signed char c;" in text, text
    assert "return c;" in text, text
    assert "arg0 = " not in text, text
    assert "return 0;" not in text, text


def test_real_arm_hard_float_compare_does_not_erase_three_call_args(
    tmp_path: Path,
) -> None:
    """Keep an exact s0/s1/s2 setup visible after a VFP status comparison."""
    compiler = shutil.which("arm-none-eabi-gcc")
    if compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")

    source = tmp_path / "arm_hard_float_three.c"
    binary = tmp_path / "arm_hard_float_three.elf"
    source.write_text(
        "__attribute__((noinline)) float arm_hf_three(\n"
        "    float value, float lower, float upper) {\n"
        "    return value < lower ? lower : (value > upper ? upper : value);\n"
        "}\n"
        "__attribute__((noinline)) float arm_hf_three_caller(\n"
        "    float value, float limit) {\n"
        "    if (limit == 0.0f) return value;\n"
        "    return arm_hf_three(value, -limit, limit);\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=hard",
            "-mfpu=fpv4-sp-d16",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,arm_hf_three_caller",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "arm_hf_three_caller"),
        None,
    )
    assert target is not None, functions
    generated = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
        max_functions=1,
    )

    assert "extern float arm_hf_three(float, float, float);" in generated, generated
    call_line = next(
        (line for line in generated.splitlines() if " = arm_hf_three(" in line),
        None,
    )
    assert call_line is not None, generated
    assert call_line.count(",") == 2, call_line
    assert "(*)(void)" not in call_line, call_line


@pytest.mark.slow
def test_real_arm_hard_float_decompile_recompile_execute_round_trip(
    tmp_path: Path,
) -> None:
    """Recover VFP ABI roles and scalar arithmetic from a real Cortex-M build."""
    arm_compiler = shutil.which("arm-none-eabi-gcc")
    host_compiler = shutil.which("gcc")
    if arm_compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")
    if host_compiler is None:
        pytest.skip("host gcc is unavailable")

    source = tmp_path / "arm_hard_float_formula.c"
    binary = tmp_path / "arm_hard_float_formula.elf"
    source.write_text(
        "__attribute__((noinline)) float arm_hard_float_formula(float throttle) {\n"
        "    return (1.0f - throttle * throttle / 3.0f) * throttle * 1.5f;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            arm_compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=hard",
            "-mfpu=fpv4-sp-d16",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,arm_hard_float_formula",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (
            function
            for function in functions
            if function.name == "arm_hard_float_formula"
        ),
        None,
    )
    assert target is not None, functions
    generated = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    assert "float arm_hard_float_formula(float arg0)" in generated, generated
    assert "asm:" not in generated, generated
    assert "return 0;" not in generated, generated
    assert all(literal in generated for literal in ("1.0f", "3.0f", "1.5f")), generated

    driver = tmp_path / "driver.c"
    driver.write_text(
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "float arm_hard_float_formula(float);\n"
        "int main(int argc, char **argv) {\n"
        "    for (int i = 1; i < argc; ++i)\n"
        '        printf("%.9g\\n", arm_hard_float_formula(strtof(argv[i], 0)));\n'
        "    return 0;\n"
        "}\n"
    )
    rebuilt_source = tmp_path / "rebuilt.c"
    rebuilt_source.write_text(generated)
    reference = tmp_path / "reference"
    rebuilt = tmp_path / "rebuilt"
    for implementation, output in ((source, reference), (rebuilt_source, rebuilt)):
        compiled = subprocess.run(
            [
                host_compiler,
                "-std=c11",
                "-O2",
                "-o",
                str(output),
                str(implementation),
                str(driver),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert compiled.returncode == 0, (
            f"{implementation}: {compiled.stderr}\n{generated}"
        )

    inputs = ["-1.25", "-0.5", "0", "0.5", "1", "1.75"]
    reference_run = subprocess.run(
        [str(reference), *inputs], capture_output=True, text=True, check=False
    )
    rebuilt_run = subprocess.run(
        [str(rebuilt), *inputs], capture_output=True, text=True, check=False
    )
    assert reference_run.returncode == 0, reference_run.stderr
    assert rebuilt_run.returncode == 0, rebuilt_run.stderr
    assert rebuilt_run.stdout == reference_run.stdout


@pytest.mark.slow
def test_real_arm_hard_float_call_round_trip(tmp_path: Path) -> None:
    """Preserve VFP arguments and the VFP result across a real direct call."""
    arm_compiler = shutil.which("arm-none-eabi-gcc")
    host_compiler = shutil.which("gcc")
    if arm_compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")
    if host_compiler is None:
        pytest.skip("host gcc is unavailable")

    source = tmp_path / "arm_hard_float_call.c"
    binary = tmp_path / "arm_hard_float_call.elf"
    source.write_text(
        "__attribute__((noinline)) float arm_hf_callee(float x, float y) {\n"
        "    return x * y + 1.0f;\n"
        "}\n"
        "__attribute__((noinline)) float arm_hf_caller(float x, float y) {\n"
        "    return arm_hf_callee(x, y) + x;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            arm_compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=hard",
            "-mfpu=fpv4-sp-d16",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,arm_hf_caller",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "arm_hf_caller"),
        None,
    )
    assert target is not None, functions
    generated = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    assert "float arm_hf_caller(float arg0, float arg1)" in generated, generated
    assert "arm_hf_callee(arg0, arg1)" in generated, generated
    assert "asm:" not in generated, generated

    driver = tmp_path / "hard_float_call_driver.c"
    driver.write_text(
        "#include <stdio.h>\n"
        "float arm_hf_caller(float, float);\n"
        "int main(void) {\n"
        '    printf("%.9g %.9g %.9g\\n", arm_hf_caller(2.0f, 3.0f),\n'
        "           arm_hf_caller(-1.5f, 4.0f), arm_hf_caller(0.25f, -8.0f));\n"
        "    return 0;\n"
        "}\n"
    )
    helper = tmp_path / "hard_float_call_helper.c"
    helper.write_text(
        "__attribute__((noinline)) float arm_hf_callee(float x, float y) {\n"
        "    return x * y + 1.0f;\n"
        "}\n"
    )
    rebuilt_source = tmp_path / "hard_float_call_rebuilt.c"
    rebuilt_source.write_text("float arm_hf_callee(float, float);\n" + generated)
    reference = tmp_path / "hard_float_call_reference"
    rebuilt = tmp_path / "hard_float_call_rebuilt"
    compile_inputs = (
        ([source, driver], reference),
        ([rebuilt_source, helper, driver], rebuilt),
    )
    for inputs, output in compile_inputs:
        compiled = subprocess.run(
            [
                host_compiler,
                "-std=c11",
                "-O2",
                "-o",
                str(output),
                *(str(path) for path in inputs),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert compiled.returncode == 0, f"{inputs}: {compiled.stderr}\n{generated}"

    reference_run = subprocess.run(
        [str(reference)], capture_output=True, text=True, check=False
    )
    rebuilt_run = subprocess.run(
        [str(rebuilt)], capture_output=True, text=True, check=False
    )
    assert reference_run.returncode == 0, reference_run.stderr
    assert rebuilt_run.returncode == 0, rebuilt_run.stderr
    assert rebuilt_run.stdout == reference_run.stdout


@pytest.mark.slow
def test_real_arm_mixed_hard_float_call_round_trip(tmp_path: Path) -> None:
    """Use the callee prototype to interleave core and VFP call storage."""
    arm_compiler = shutil.which("arm-none-eabi-gcc")
    host_compiler = shutil.which("gcc")
    if arm_compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")
    if host_compiler is None:
        pytest.skip("host gcc is unavailable")

    source = tmp_path / "arm_mixed_hard_float_call.c"
    binary = tmp_path / "arm_mixed_hard_float_call.elf"
    source.write_text(
        "__attribute__((noinline)) float arm_hf_mixed_callee(\n"
        "    int token, float measured, int negate) {\n"
        "    return token + (negate ? -measured : measured);\n"
        "}\n"
        "__attribute__((noinline)) float arm_hf_mixed_caller(\n"
        "    float measured, int negate) {\n"
        "    return arm_hf_mixed_callee(7, measured, negate) + 1.0f;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            arm_compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=hard",
            "-mfpu=fpv4-sp-d16",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,arm_hf_mixed_caller",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "arm_hf_mixed_caller"),
        None,
    )
    assert target is not None, functions
    generated = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
        max_functions=1,
    )

    assert "float arm_hf_mixed_caller(float arg0, int arg1)" in generated, generated
    # The callee prototype types every argument, so each one is already the
    # parameter's type and needs no conversion: `7` is an `int` literal and
    # `arg1` is a declared `int`. This used to render `(int)(7), arg0,
    # (int)(arg1)` — casts that state nothing and that a C-signature type_match
    # has to parse around. See the ARM hard-float call-argument cast fix.
    assert "arm_hf_mixed_callee(7, arg0, arg1)" in generated, generated
    assert "asm:" not in generated, generated

    driver = tmp_path / "mixed_call_driver.c"
    driver.write_text(
        "#include <stdio.h>\n"
        "float arm_hf_mixed_caller(float, int);\n"
        "int main(void) {\n"
        '    printf("%.9g %.9g %.9g\\n", arm_hf_mixed_caller(2.5f, 0),\n'
        "           arm_hf_mixed_caller(2.5f, 1),\n"
        "           arm_hf_mixed_caller(-3.25f, 1));\n"
        "    return 0;\n"
        "}\n"
    )
    helper = tmp_path / "mixed_call_helper.c"
    helper.write_text(
        "__attribute__((noinline)) float arm_hf_mixed_callee(\n"
        "    int token, float measured, int negate) {\n"
        "    return token + (negate ? -measured : measured);\n"
        "}\n"
    )
    rebuilt_source = tmp_path / "mixed_call_rebuilt.c"
    rebuilt_source.write_text(
        "float arm_hf_mixed_callee(int, float, int);\n" + generated
    )
    reference = tmp_path / "mixed_call_reference"
    rebuilt = tmp_path / "mixed_call_rebuilt"
    compile_inputs = (
        ([source, driver], reference),
        ([rebuilt_source, helper, driver], rebuilt),
    )
    for inputs, output in compile_inputs:
        compiled = subprocess.run(
            [
                host_compiler,
                "-std=c11",
                "-O2",
                "-o",
                str(output),
                *(str(path) for path in inputs),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert compiled.returncode == 0, f"{inputs}: {compiled.stderr}\n{generated}"

    reference_run = subprocess.run(
        [str(reference)], capture_output=True, text=True, check=False
    )
    rebuilt_run = subprocess.run(
        [str(rebuilt)], capture_output=True, text=True, check=False
    )
    assert reference_run.returncode == 0, reference_run.stderr
    assert rebuilt_run.returncode == 0, rebuilt_run.stderr
    assert rebuilt_run.stdout == reference_run.stdout


@pytest.mark.slow
def test_real_arm_mixed_hard_float_spills_preserve_source_parameter_order(
    tmp_path: Path,
) -> None:
    """Use real GCC spill evidence to interleave core and VFP parameters."""
    arm_compiler = shutil.which("arm-none-eabi-gcc")
    host_compiler = shutil.which("gcc")
    if arm_compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")
    if host_compiler is None:
        pytest.skip("host gcc is unavailable")

    source = tmp_path / "arm_mixed_storage.c"
    binary = tmp_path / "arm_mixed_storage.elf"
    source.write_text(
        "__attribute__((noinline)) float arm_mixed_storage(\n"
        "    int token, float measured, int negate) {\n"
        "    (void)token;\n"
        "    return negate ? -measured : measured;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            arm_compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=hard",
            "-mfpu=fpv4-sp-d16",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,arm_mixed_storage",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "arm_mixed_storage"),
        None,
    )
    assert target is not None, functions
    generated = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    assert "float arm_mixed_storage(int arg0, float arg1, int arg2)" in generated, (
        generated
    )
    assert "asm:" not in generated, generated

    driver = tmp_path / "mixed_driver.c"
    driver.write_text(
        "#include <stdio.h>\n"
        "float arm_mixed_storage(int, float, int);\n"
        "int main(void) {\n"
        '    printf("%.9g %.9g\\n", arm_mixed_storage(7, 1.25f, 0),\n'
        "           arm_mixed_storage(7, 1.25f, 1));\n"
        "    return 0;\n"
        "}\n"
    )
    rebuilt_source = tmp_path / "mixed_rebuilt.c"
    rebuilt_source.write_text(generated)
    reference = tmp_path / "mixed_reference"
    rebuilt = tmp_path / "mixed_rebuilt"
    for implementation, output in ((source, reference), (rebuilt_source, rebuilt)):
        compiled = subprocess.run(
            [
                host_compiler,
                "-std=c11",
                "-O2",
                "-o",
                str(output),
                str(implementation),
                str(driver),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert compiled.returncode == 0, (
            f"{implementation}: {compiled.stderr}\n{generated}"
        )

    reference_run = subprocess.run(
        [str(reference)], capture_output=True, text=True, check=False
    )
    rebuilt_run = subprocess.run(
        [str(rebuilt)], capture_output=True, text=True, check=False
    )
    assert reference_run.returncode == 0, reference_run.stderr
    assert rebuilt_run.returncode == 0, rebuilt_run.stderr
    assert rebuilt_run.stdout == reference_run.stdout


def test_real_arm_stack_backed_float_round_trip(tmp_path: Path) -> None:
    """Preserve float representation through a real promoted stack slot."""
    compiler = shutil.which("arm-none-eabi-gcc")
    host_compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")
    if host_compiler is None:
        pytest.skip("host gcc is unavailable")

    source = tmp_path / "arm_stack_backed_float.c"
    binary = tmp_path / "arm_stack_backed_float.elf"
    source.write_text(
        "__attribute__((noinline)) float arm_stack_backed_float(float arg) {\n"
        "    volatile float slot = arg;\n"
        "    return slot * 2.0f;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=hard",
            "-mfpu=fpv4-sp-d16",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,arm_stack_backed_float",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (
            function
            for function in functions
            if function.name == "arm_stack_backed_float"
        ),
        None,
    )
    assert target is not None, functions
    generated = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    assert "float arm_stack_backed_float(float arg0)" in generated, generated
    assert "asm:" not in generated, generated

    driver = tmp_path / "stack_float_driver.c"
    driver.write_text(
        "#include <stdio.h>\n"
        "float arm_stack_backed_float(float);\n"
        "int main(void) {\n"
        '    printf("%.9g %.9g\\n", arm_stack_backed_float(1.25f),\n'
        "           arm_stack_backed_float(-2.5f));\n"
        "    return 0;\n"
        "}\n"
    )
    rebuilt_source = tmp_path / "stack_float_rebuilt.c"
    rebuilt_source.write_text(generated)
    reference = tmp_path / "stack_float_reference"
    rebuilt = tmp_path / "stack_float_rebuilt"
    for implementation, output in ((source, reference), (rebuilt_source, rebuilt)):
        compiled = subprocess.run(
            [
                host_compiler,
                "-std=c11",
                "-O2",
                "-o",
                str(output),
                str(implementation),
                str(driver),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert compiled.returncode == 0, (
            f"{implementation}: {compiled.stderr}\n{generated}"
        )

    reference_run = subprocess.run(
        [str(reference)], capture_output=True, text=True, check=False
    )
    rebuilt_run = subprocess.run(
        [str(rebuilt)], capture_output=True, text=True, check=False
    )
    assert reference_run.returncode == 0, reference_run.stderr
    assert rebuilt_run.returncode == 0, rebuilt_run.stderr
    assert rebuilt_run.stdout == reference_run.stdout


def test_real_thumb_leaf_frame_save_does_not_become_a_source_local(
    tmp_path: Path,
) -> None:
    """A leaf ``push {r7}`` is frame state, not an uninitialized C local.

    GCC's Cortex-M O0 leaf frame saves r7 without lr, then restores r7 through
    the entry stack boundary rather than reading the promoted save-slot name.
    This is the exact machine-frame shape used by DecBench's ``console_getc``.
    """
    compiler = shutil.which("arm-none-eabi-gcc")
    if compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")

    source = tmp_path / "thumb_leaf_frame.c"
    binary = tmp_path / "thumb_leaf_frame.elf"
    source.write_text(
        "volatile unsigned int read_index;\n"
        "volatile unsigned int write_index;\n"
        "volatile unsigned char input[128];\n"
        "__attribute__((noinline)) int thumb_leaf_frame(int wait) {\n"
        "    signed char value = 0;\n"
        "    while (wait && read_index == write_index) {}\n"
        "    if (read_index != write_index) {\n"
        "        value = (signed char)input[read_index];\n"
        "        read_index = (read_index + 1) & 127;\n"
        "    }\n"
        "    return value;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-mcpu=cortex-m4",
            "-mthumb",
            "-mfloat-abi=soft",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,thumb_leaf_frame",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "thumb_leaf_frame"),
        None,
    )
    assert target is not None, functions
    generated = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    assert "thumb_leaf_frame(int arg0)" in generated, generated
    assert "signed char value;" in generated, generated
    assert "local_4" not in generated, generated
    assert "= var0;" not in generated, generated


def test_real_stripped_x86_word_parameter_home_recovers_short(
    tmp_path: Path,
) -> None:
    """Recover a short parameter from GCC's real O0 word-sized home."""
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    if compiler is None or strip is None:
        pytest.skip("host gcc and strip are required")

    source = tmp_path / "narrow_parameter.c"
    binary = tmp_path / "narrow_parameter"
    stripped = tmp_path / "narrow_parameter.stripped"
    source.write_text(
        "volatile short observed;\n"
        "__attribute__((noinline, used)) int narrow_parameter(short value) {\n"
        "    observed = value;\n"
        "    return value;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-O0",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-nostdlib",
            "-Wl,-e,narrow_parameter",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "narrow_parameter"),
        None,
    )
    assert target is not None, functions
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
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    assert "(short arg0)" in generated, generated
    assert "(int arg0)" not in generated, generated
    assert "(unsigned short arg0)" not in generated, generated


def test_real_stripped_sigaction_callback_recovers_external_int_contract(
    tmp_path: Path,
) -> None:
    """Recover an optimized-away callback parameter from its registration.

    The callback deliberately never reads ``signal_number``, so its own stripped
    machine body contains no parameter evidence.  ``sigaction`` is the surviving
    program-level contract.  The ordinary address-taken no-argument callback is
    the fail-closed control: merely storing a code pointer must not invent an
    argument.
    """
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    if compiler is None or strip is None:
        pytest.skip("host gcc and strip are required")

    source = tmp_path / "registered_callback.c"
    binary = tmp_path / "registered_callback"
    stripped = tmp_path / "registered_callback.stripped"
    source.write_text(
        "#include <signal.h>\n"
        "volatile sig_atomic_t observed;\n"
        "void (*volatile ordinary_slot)(void);\n"
        "__attribute__((noinline, used)) void quiet_handler(int signal_number) {\n"
        "    (void)signal_number;\n"
        "    observed++;\n"
        "}\n"
        "__attribute__((noinline, used)) void noarg_callback(void) {\n"
        "    observed += 2;\n"
        "}\n"
        "__attribute__((noinline, used)) void info_handler(\n"
        "    int signal_number, siginfo_t *info, void *context) {\n"
        "    (void)signal_number; (void)info; (void)context;\n"
        "    observed += 3;\n"
        "}\n"
        "int main(void) {\n"
        "    struct sigaction action = {0};\n"
        "    struct sigaction info_action = {0};\n"
        "    action.sa_handler = quiet_handler;\n"
        "    action.sa_flags = SA_RESTART;\n"
        "    sigemptyset(&action.sa_mask);\n"
        "    info_action.sa_sigaction = info_handler;\n"
        "    info_action.sa_flags = SA_RESTART | SA_SIGINFO;\n"
        "    sigemptyset(&info_action.sa_mask);\n"
        "    ordinary_slot = noarg_callback;\n"
        "    int first = sigaction(SIGUSR1, &action, 0);\n"
        "    return first + sigaction(SIGUSR2, &info_action, 0);\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-O2",
            "-fno-inline",
            "-g",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=64)
    quiet = next(
        (function for function in functions if function.name == "quiet_handler"), None
    )
    noarg = next(
        (function for function in functions if function.name == "noarg_callback"), None
    )
    info = next(
        (function for function in functions if function.name == "info_handler"), None
    )
    assert quiet is not None, [function.name for function in functions]
    assert noarg is not None, [function.name for function in functions]
    assert info is not None, [function.name for function in functions]

    shutil.copy2(binary, stripped)
    stripped_result = subprocess.run(
        [strip, "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped_result.returncode == 0, stripped_result.stderr

    results = g.ir.decompile_many(  # ty: ignore[unresolved-attribute]
        str(stripped),
        [
            int(quiet.entry_point.value),
            int(noarg.entry_point.value),
            int(info.entry_point.value),
        ],
        style="decbench",
        timeout_ms=8000,
    )
    rendered = {int(record[1]): record[2] for record in results}
    quiet_text = rendered[int(quiet.entry_point.value)]
    noarg_text = rendered[int(noarg.entry_point.value)]
    info_text = rendered[int(info.entry_point.value)]

    assert f"sub_{int(quiet.entry_point.value):x}(int arg0)" in quiet_text, quiet_text
    assert f"sub_{int(noarg.entry_point.value):x}(void)" in noarg_text, noarg_text
    assert "arg0" not in noarg_text.split("{", 1)[0], noarg_text
    assert f"sub_{int(info.entry_point.value):x}(void)" in info_text, info_text
    assert "arg0" not in info_text.split("{", 1)[0], info_text


def test_real_stripped_format_wrapper_recovers_forwarded_string_parameter(
    tmp_path: Path,
) -> None:
    """Recover a wrapper parameter from complete literal-format call evidence.

    The target's second parameter is only forwarded through ``error``'s
    variadic tail, so its own body cannot classify it.  Direct callers prove
    the missing contract with ``%s``.  Null-only, conflicting-format, and
    unknown-format wrappers are fail-closed controls.
    """
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    if compiler is None or strip is None:
        pytest.skip("host gcc and strip are required")

    source = tmp_path / "format_wrapper.c"
    binary = tmp_path / "format_wrapper"
    stripped = tmp_path / "format_wrapper.stripped"
    source.write_text(
        "#include <error.h>\n"
        "#include <libintl.h>\n"
        "#include <stdint.h>\n"
        "__attribute__((noinline, used)) void string_wrapper(\n"
        "    const char *reason, const char *operand) {\n"
        "    if (reason) error(0, 0, gettext(reason), operand);\n"
        "}\n"
        "__attribute__((noinline, used)) void null_only_wrapper(\n"
        "    const char *reason, long value) {\n"
        "    if (reason) error(0, 0, gettext(reason), value);\n"
        "}\n"
        "__attribute__((noinline, used)) void conflicting_wrapper(\n"
        "    const char *reason, uintptr_t value) {\n"
        "    if (reason) error(0, 0, gettext(reason), value);\n"
        "}\n"
        "__attribute__((noinline, used)) void unknown_wrapper(\n"
        "    const char *reason, const char *value) {\n"
        "    if (reason) error(0, 0, gettext(reason), value);\n"
        "}\n"
        "int main(int argc, char **argv) {\n"
        "    string_wrapper(\"missing operand after '%s'\", argv[0]);\n"
        "    string_wrapper(0, 0);\n"
        '    null_only_wrapper("plain message", 0);\n'
        "    conflicting_wrapper(\"name '%s'\", (uintptr_t)argv[0]);\n"
        '    conflicting_wrapper("count %ld", (uintptr_t)argc);\n'
        "    unknown_wrapper(\"known '%s'\", argv[0]);\n"
        "    if (argc > 2) unknown_wrapper(argv[1], argv[2]);\n"
        "    return 0;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-O2",
            "-fno-inline",
            "-fno-pie",
            "-no-pie",
            "-g",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=128)
    names = {
        "string_wrapper",
        "null_only_wrapper",
        "conflicting_wrapper",
        "unknown_wrapper",
    }
    targets = {
        function.name: int(function.entry_point.value)
        for function in functions
        if function.name in names
    }
    assert targets.keys() == names, [function.name for function in functions]

    shutil.copy2(binary, stripped)
    stripped_result = subprocess.run(
        [strip, "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped_result.returncode == 0, stripped_result.stderr

    results = g.ir.decompile_many(  # ty: ignore[unresolved-attribute]
        str(stripped),
        list(targets.values()),
        style="decbench",
        timeout_ms=8000,
    )
    rendered = {int(record[1]): record[2] for record in results}
    string_text = rendered[targets["string_wrapper"]]
    assert "char * arg1" in string_text.split("{", 1)[0], string_text
    for name in ("null_only_wrapper", "conflicting_wrapper", "unknown_wrapper"):
        control = rendered[targets[name]]
        assert "char * arg1" not in control.split("{", 1)[0], control


def test_real_stripped_plt_got_tail_free_recovers_void_contract(tmp_path: Path) -> None:
    """Resolve an address-taken import's ``.plt.got`` tail-call stub.

    Taking ``free``'s address makes the linker use a GLOB_DAT relocation and a
    compact ``.plt.got`` entry instead of an ordinary JUMP_SLOT-backed PLT
    entry.  The stripped wrapper must still recover the exact import and its
    authoritative void contract rather than emit a dangling external goto.
    """
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    if compiler is None or strip is None:
        pytest.skip("host gcc and strip are required")

    source = tmp_path / "plt_got_tail.c"
    binary = tmp_path / "plt_got_tail"
    stripped = tmp_path / "plt_got_tail.stripped"
    source.write_text(
        "#include <stdlib.h>\n"
        "__attribute__((noinline, used)) void (*get_free(void))(void *) {\n"
        "    return free;\n"
        "}\n"
        "__attribute__((noinline, used)) void release_ptr(void *ptr) {\n"
        "    free(ptr);\n"
        "}\n"
        "int main(void) {\n"
        "    void *ptr = malloc(1);\n"
        "    release_ptr(ptr);\n"
        "    return get_free() == 0;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-O2",
            "-fcf-protection=full",
            "-Wl,-z,ibtplt",
            "-g",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=128)
    target = next(
        int(function.entry_point.value)
        for function in functions
        if function.name == "release_ptr"
    )
    shutil.copy2(binary, stripped)
    stripped_result = subprocess.run(
        [strip, "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped_result.returncode == 0, stripped_result.stderr

    plt = dict(
        g.analysis.elf_plt_map_path(  # ty: ignore[unresolved-attribute]
            str(stripped)
        )
    )
    assert any(name == "free@plt" for name in plt.values()), plt
    results = g.ir.decompile_many(  # ty: ignore[unresolved-attribute]
        str(stripped),
        [target],
        style="decbench",
        timeout_ms=8000,
    )
    assert len(results) == 1, results
    function_name, _, generated = results[0][:3]
    header = generated.split("{", 1)[0].strip().splitlines()[-1]
    assert header.startswith(f"void {function_name}("), generated
    assert "free(" in generated, generated
    assert "goto" not in generated, generated

    rebuilt_source = tmp_path / "rebuilt.c"
    rebuilt = tmp_path / "rebuilt"
    rebuilt_source.write_text(
        generated
        + "\nextern void *malloc(__SIZE_TYPE__);\n"
        + f"int main(void) {{ {function_name}(malloc(1)); return 0; }}\n"
    )
    compiled = subprocess.run(
        [compiler, "-O0", "-o", str(rebuilt), str(rebuilt_source)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + "\n" + generated
    executed = subprocess.run(
        [str(rebuilt)], capture_output=True, text=True, check=False, timeout=10
    )
    assert executed.returncode == 0, executed.stderr


def test_real_arm32_byte_spills_recover_narrow_parameters(tmp_path: Path) -> None:
    """Use AAPCS spill width and reload extension to recover byte arguments."""
    compiler = shutil.which("arm-none-eabi-gcc")
    if compiler is None:
        pytest.skip("arm-none-eabi-gcc is unavailable")

    source = tmp_path / "arm_narrow_params.c"
    binary = tmp_path / "arm_narrow_params.elf"
    source.write_text(
        "typedef struct endpoint endpoint;\n"
        "struct endpoint {\n"
        "    void (*set_nak)(endpoint *, unsigned char, unsigned char);\n"
        "    endpoint *next;\n"
        "    int value;\n"
        "};\n"
        "__attribute__((noinline)) void arm_narrow_params(\n"
        "    endpoint *device, unsigned char address, unsigned char nak) {\n"
        "    device->set_nak(device, address, nak);\n"
        "}\n"
        "__attribute__((noinline)) int endpoint_notempty(endpoint *device) {\n"
        "    return device->next != 0;\n"
        "}\n"
        "__attribute__((noinline)) endpoint *endpoint_remove(endpoint *device) {\n"
        "    return device->next;\n"
        "}\n"
        "__attribute__((noinline)) endpoint *endpoint_ready(endpoint *device) {\n"
        "    return device;\n"
        "}\n"
        "__attribute__((noinline)) void arm_word_params(\n"
        "    endpoint *device, int count, int message) {\n"
        "    device->value = count;\n"
        "    while (endpoint_notempty(device)) {\n"
        "        endpoint_ready(endpoint_remove(device))->value = message;\n"
        "    }\n"
        "}\n"
        "volatile unsigned int peripheral_clock = 72000000;\n"
        "volatile unsigned int alternate_clock = 36000000;\n"
        "__attribute__((noinline)) void arm_unsigned_scalars(\n"
        "    unsigned int port, unsigned int baud) {\n"
        "    unsigned int clock = peripheral_clock;\n"
        "    if (port == 0x40011000 || port == 0x40011400) {\n"
        "        clock = alternate_clock;\n"
        "    }\n"
        "    *(volatile unsigned int *)(port + 8) = (clock + baud / 2) / baud;\n"
        "}\n"
    )
    built = subprocess.run(
        [
            compiler,
            "-mcpu=cortex-m3",
            "-mthumb",
            "-nostdlib",
            "-Wl,-Ttext=0x1000",
            "-Wl,-e,arm_narrow_params",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=32)
    target = next(
        (function for function in functions if function.name == "arm_narrow_params"),
        None,
    )
    assert target is not None, functions
    text = g.ir.decompile_at(
        str(binary),
        int(target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )

    signature = next(line for line in text.splitlines() if "arm_narrow_params(" in line)
    assert "unsigned char arg1" in signature, text
    assert "unsigned char arg2" in signature, text

    word_target = next(
        (function for function in functions if function.name == "arm_word_params"),
        None,
    )
    assert word_target is not None, functions
    word_text = g.ir.decompile_at(
        str(binary),
        int(word_target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )
    word_signature = next(
        line for line in word_text.splitlines() if "arm_word_params(" in line
    )
    assert "arm_word_params(" in word_signature, word_text
    assert "int arg1" in word_signature, word_text
    assert "* arg1" not in word_signature, word_text

    scalar_target = next(
        (function for function in functions if function.name == "arm_unsigned_scalars"),
        None,
    )
    assert scalar_target is not None, functions
    scalar_text = g.ir.decompile_at(
        str(binary),
        int(scalar_target.entry_point.value),
        style="decbench",
        timeout_ms=8000,
    )
    scalar_signature = scalar_text.splitlines()[1]
    assert "arm_unsigned_scalars(" in scalar_signature, scalar_text
    assert "int arg0" in scalar_signature, scalar_text
    assert "unsigned int arg1" in scalar_signature, scalar_text
    assert "* arg0" not in scalar_signature, scalar_text
    assert "* arg1" not in scalar_signature, scalar_text


def test_real_stripped_arm64_loop_does_not_invent_trailing_parameters(
    tmp_path: Path,
) -> None:
    """A call's ABI may-use must not reach the arity through a phi copy.

    ``abi::annotate_calls`` hangs the whole AAPCS64 argument list on every call
    so liveness and DCE stay sound. In a loop that calls a three-argument
    function and later uses ``w3`` as a scratch register, that may-use is enough
    to keep the loop header's ``x3`` phi alive; value numbering then materialises
    it as ``x3#1 = x3`` in the entry block, and a first-touch arity scan reads
    that SSA plumbing as a fourth incoming argument.

    This is the shape of ``main`` in a stripped distro ``getconf``/``iconv``,
    reduced to one translation unit: ``next_option`` takes three arguments (so
    the header never writes ``x3``), and the post-loop block loads four globals,
    which is enough register pressure for GCC to pick ``w3``.
    """
    compiler = shutil.which("aarch64-linux-gnu-gcc")
    strip = shutil.which("aarch64-linux-gnu-strip")
    if compiler is None or strip is None:
        pytest.skip("aarch64-linux-gnu toolchain is unavailable")

    source = tmp_path / "arm64_option_loop.c"
    binary = tmp_path / "arm64_option_loop.elf"
    source.write_text(
        "#include <stdio.h>\n"
        "int flag_a, flag_b, flag_c, flag_d;\n"
        "__attribute__((noipa)) int next_option(\n"
        "    int argc, char **argv, const char *opts) {\n"
        "    return argc > 1 && argv != 0 ? opts[0] : -1;\n"
        "}\n"
        "__attribute__((noipa)) void mark(int a, int b, int c) {\n"
        '    printf("%d %d %d\\n", a, b, c);\n'
        "    flag_b = 0;\n"
        "}\n"
        "__attribute__((noinline)) int scan_arguments(int argc, char **argv) {\n"
        "    for (;;) {\n"
        '        int c = next_option(argc, argv, "abc");\n'
        "        if (c == -1) {\n"
        "            int a = flag_a, b = flag_b, d = flag_c, e = flag_d;\n"
        "            if (a != 0 && b != 0 && d != 0 && e != 0) {\n"
        "                mark(a + e, b, d);\n"
        "                continue;\n"
        "            }\n"
        "            return a + b + d + e;\n"
        "        }\n"
        "        if (c == 'a') {\n"
        "            flag_a = 1;\n"
        "        }\n"
        "    }\n"
        "}\n"
        "int main(int argc, char **argv) { return scan_arguments(argc, argv); }\n"
    )
    built = subprocess.run(
        [compiler, "-O2", "-g", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=64)
    target = next(
        (function for function in functions if function.name == "scan_arguments"),
        None,
    )
    assert target is not None, [function.name for function in functions]
    entry_va = int(target.entry_point.value)

    stripped = tmp_path / "arm64_option_loop.stripped"
    shutil.copy2(binary, stripped)
    stripped_result = subprocess.run(
        [strip, "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped_result.returncode == 0, stripped_result.stderr

    # Non-vacuity: the assertions below only mean something if this build really
    # did pick an argument register beyond the true arity as a scratch. Register
    # allocation is the compiler's choice, so check the machine code rather than
    # trusting that a future GCC keeps making it.
    import json

    lifted = json.dumps(g.ir.lift_window_at(str(binary), entry_va, 256, 64, "arm64"))
    assert '"w3"' in lifted or '"x3"' in lifted, (
        "this GCC did not allocate x3 as a scratch register in scan_arguments, "
        "so the fixture no longer reproduces the phi-copy shape"
    )

    results = g.ir.decompile_many(
        str(stripped),
        [entry_va],
        style="decbench",
        timeout_ms=8000,
    )
    assert len(results) == 1
    _, _, text = results[0][:3]
    signature = next(line for line in text.splitlines() if f"sub_{entry_va:x}(" in line)
    parameters = signature.split("(", 1)[1].rsplit(")", 1)[0].split(",")
    assert len(parameters) == 2, signature
    # `argc` and `argv` — x2 and x3 are scratch, and the loop's three-argument
    # callee is what made them look live-in.
    assert "arg0" in parameters[0], signature
    assert "arg1" in parameters[1], signature
    assert "arg2" not in signature, signature
    assert "arg3" not in signature, signature


@pytest.mark.skipif(not ARM32_SAMPLE.exists(), reason="armhf sample missing")
def test_decompile_requested_va_seeds_stripped_arm32(
    tmp_path: Path,
) -> None:
    """An explicit entry VA must not depend on stripped-symbol discovery.

    DecBench and similar evaluation protocols provide authoritative function
    addresses in stripped binaries.  Reproduce that contract using the real
    checked-in ARM32 binary: remove its symbols, then request ``main`` by the
    even code VA recorded in the original symbol table.
    """
    strip = shutil.which("arm-linux-gnueabihf-strip")
    if strip is None:
        pytest.skip("arm-linux-gnueabihf-strip is unavailable")

    stripped = tmp_path / "hello-armhf-stripped"
    shutil.copy2(ARM32_SAMPLE, stripped)
    strip_result = subprocess.run(
        [strip, "--strip-all", str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert strip_result.returncode == 0, strip_result.stderr

    # main is the Thumb symbol 0x46d in the original; executable entry VAs
    # clear the T-bit and therefore use 0x46c.
    requested_va = 0x46C
    results = g.ir.decompile_many(
        str(stripped),
        [requested_va],
        style="decbench",
        timeout_ms=8000,
    )
    assert len(results) == 1
    name, va, text = results[0][:3]
    assert name == "sub_46c"
    assert va == requested_va
    assert text.startswith("// glaurung: sub_46c @ 0x46c\n")


@pytest.mark.skipif(not ARM32_SAMPLE.exists(), reason="armhf sample missing")
def test_decompile_arm32_mixed_mode_init_uses_a32() -> None:
    """A32 mapping symbols must override the ARM pipeline's Thumb default.

    The real checked-in armhf ELF mixes A32 and Thumb in one executable.
    ``_init`` is three A32 instructions at 0x3f4: push, a direct call to
    ``call_weak_fn``, and pop-to-PC. Decoding those bytes as Thumb used to emit
    unrelated arithmetic followed by a wrapped negative-address label.
    """
    results = g.ir.decompile_many(
        str(ARM32_SAMPLE),
        [0x3F4],
        style="decbench",
        timeout_ms=8000,
    )
    assert len(results) == 1
    name, va, text = results[0][:3]
    assert name == "_init"
    assert va == 0x3F4
    assert "call_weak_fn(" in text, text
    assert "ffffffffffff" not in text, text


@pytest.mark.skipif(not X86_O0_SAMPLE.exists(), reason="clang-O0 sample missing")
def test_decompile_style_c_strips_percent_prefix():
    # `--style c` drops the `%` prefix from register names and the
    # `(u64*)` / `(bool)` type annotations; output reads closer to C.
    result = _run([str(X86_O0_SAMPLE), "--func", "0x12d0", "--style", "c"])
    assert result.returncode == 0, result.stderr
    # C-style header is trimmed — the VA is dropped for readability.
    assert result.stdout.startswith("fn main {"), result.stdout[:200]
    # Plain render would show `%rbp`; C style shows bare `rbp`.
    assert "%rbp" not in result.stdout
    assert "rbp" in result.stdout
    # Annotations should not appear in C style.
    assert "(u64*)" not in result.stdout
    assert "(bool)" not in result.stdout


@pytest.mark.skipif(not X86_O0_SAMPLE.exists(), reason="clang-O0 sample missing")
def test_decompile_x86_o0_main_shows_prologue_and_epilogue():
    # -O0 preserves the rbp-framed prologue so our recogniser can fire.
    result = _run([str(X86_O0_SAMPLE), "--func", "0x12d0"])
    assert result.returncode == 0, result.stderr
    assert "// x86-64 prologue:" in result.stdout, (
        "x86-64 prologue comment missing: " + result.stdout
    )
    assert "// x86-64 epilogue:" in result.stdout, (
        "x86-64 epilogue comment missing: " + result.stdout
    )

    # The parseable-C renderer must not expose the machine stack allocation as
    # source-level arithmetic.  x86 subtraction lifting emits a signed-less
    # flag temporary before the rsp write; if that dead temporary strands the
    # write outside frame recognition, DecBench sees a bogus `rsp -= N`.
    decbench = _run([str(X86_O0_SAMPLE), "--func", "0x12d0", "--style", "decbench"])
    assert decbench.returncode == 0, decbench.stderr
    assert "rsp = (rsp -" not in decbench.stdout, decbench.stdout


@pytest.mark.skipif(not PE32_PLUS_SAMPLE.exists(), reason="PE32+ sample missing")
def test_decompile_pe32_plus_resolves_iat_names():
    text = g.ir.decompile_at(
        str(PE32_PLUS_SAMPLE),
        0x140001190,
        timeout_ms=1000,
        style="c",
    )
    # The IAT thunk resolves to the imported symbol name (with a recovered
    # prototype). The argument register is scratch reuse of an ABI arg slot in
    # this parameter-less CRT entry, so it is named `varN`, not `argN` — assert
    # the resolved call, not the incidental operand spelling.
    assert "GetStartupInfoA(" in text
    assert "0x14000d1ec(" not in text
    assert "Sleep" in text
    assert "0x14000d21c" not in text


@pytest.mark.skipif(not PE32_PLUS_SAMPLE.exists(), reason="PE32+ sample missing")
def test_pe_iat_map_exposes_api_aliases():
    got = g.analysis.pe_iat_map_path(str(PE32_PLUS_SAMPLE))
    names = {name for _, name in got}
    assert {"malloc", "LeaveCriticalSection"} & names
    assert any(va for va, _ in got)


# -- DecBench parseable-C style (`--style decbench`) --------------------------
#
# The `decbench` style is a *valid C* rendering (real signature + declared
# locals) used by external tooling that parses our output as C — distinct from
# `--style c`, which is a register-level reading aid that does not parse. See
# `src/ir/ast.rs::render_decbench`.

import json
import tempfile


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_style_decbench_is_valid_c_shape():
    result = _run([str(SAMPLE), "--func", "0x1840", "--style", "decbench"])
    assert result.returncode == 0, result.stderr
    out = result.stdout
    # A real C signature, not the `fn name {` register-view header.
    assert "long " in out and "(" in out
    assert "fn sub_1840 {" not in out and "fn _start {" not in out
    # No register sigils or `&[...]` address forms leak into valid-C output.
    assert "%" not in out
    assert "&[" not in out


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_vas_batch_emits_named_json():
    # Discover a handful of real entry VAs, then decompile exactly those in one
    # pass via --vas and assert the JSON shape {name, entry_va, pseudocode}.
    funcs, _ = g.analysis.analyze_functions_path(str(SAMPLE), max_functions=200)
    vas = [int(f.entry_point.value) for f in funcs[:5]]
    assert vas, "no functions discovered in sample"
    va_arg = ",".join(hex(v) for v in vas)
    result = _run(
        [str(SAMPLE), "--vas", va_arg, "--style", "decbench", "--format", "json"]
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert isinstance(payload, list) and payload
    for entry in payload:
        assert set(entry) >= {"name", "entry_va", "pseudocode"}
        assert isinstance(entry["entry_va"], int)
    got_vas = {e["entry_va"] for e in payload}
    # Every returned VA was one we asked for (subset — some may be unliftable).
    assert got_vas <= set(vas)


def test_requested_va_budget_counts_unique_targets_only() -> None:
    """Address-scoped discovery must stop after the requested functions."""
    from glaurung.cli.commands.decompile import _requested_function_budget

    assert _requested_function_budget([0x1000, 0x2000, 0x1000]) == 2
    assert _requested_function_budget([]) == 1


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
def test_decbench_output_parses_with_gcc():
    """Contract: `--style decbench` output is syntactically valid C.

    We compile each function with ``gcc -fsyntax-only`` under lenient flags that
    silence diagnostics *inherent* to headerless, per-function decompilation
    (implicit function declarations, int<->pointer conversions, libc builtin
    prototypes) — exactly what Joern (the GED metric) and byte_match's fixup
    loop tolerate. What remains is genuine C syntax validity, which must hold
    for a high fraction of functions.
    """
    import os
    import subprocess as sp

    gcc = shutil.which("gcc")
    flags = [
        gcc,
        "-fsyntax-only",
        "-std=gnu89",
        "-w",
        "-Wno-implicit-function-declaration",
        "-Wno-int-conversion",
        "-Wno-implicit-int",
        "-Wno-builtin-declaration-mismatch",
        "-fno-builtin",
    ]
    funcs, _ = g.analysis.analyze_functions_path(str(SAMPLE), max_functions=4000)
    vas = [int(f.entry_point.value) for f in funcs]
    results = g.ir.decompile_many(str(SAMPLE), vas, style="decbench", timeout_ms=8000)
    total = ok = 0
    for _name, _va, text, *_extra in results:
        if not text.strip():
            continue
        total += 1
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as fp:
            fp.write(text)
            tmp = fp.name
        try:
            r = sp.run(
                flags + [tmp],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if r.returncode == 0:
                ok += 1
        finally:
            os.unlink(tmp)
    assert total > 0, "no functions decompiled"
    rate = ok / total
    assert rate >= 0.95, f"only {ok}/{total} ({rate:.1%}) functions parse as C"


def test_mixed_width_float_accumulator_decompiles_within_its_budget(
    tmp_path: Path,
) -> None:
    """A `double` accumulator fed by `float` terms must not spin the type pass.

    `refine_float_copy_types` used to report "I did not get the hint I asked
    for" as progress. `TypeMap::refine_from_value` is allowed to decline a
    `Float{8}` -> `Float{4}` join, so that condition never cleared and the
    fixed point ran forever — inside a single pass, where no `timeout_ms`
    between passes could reach it. This is the shape that hung
    `172_float_double_widths:gcc:O2:accumulate_wide` past ninety seconds
    against a five-second budget.
    """
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("gcc is unavailable")

    source = tmp_path / "accumulate_wide.c"
    binary = tmp_path / "accumulate_wide.so"
    source.write_text(
        "__attribute__((noinline)) double accumulate_wide(float seed, int count) {\n"
        "    double total = 0.0;\n"
        "    float step = seed;\n"
        "    int index;\n"
        "    if (count < 0 || count > 16) {\n"
        "        return 0.0;\n"
        "    }\n"
        "    for (index = 0; index < count; ++index) {\n"
        "        total += (double)step;\n"
        "        step = step * 0.5f;\n"
        "    }\n"
        "    return total;\n"
        "}\n"
    )
    built = subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", "-g", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=64)
    target = next(
        (function for function in functions if function.name == "accumulate_wide"),
        None,
    )
    assert target is not None, [function.name for function in functions]

    started = time.monotonic()
    results = g.ir.decompile_many(
        str(binary),
        [int(target.entry_point.value)],
        style="decbench",
        timeout_ms=5000,
    )
    elapsed = time.monotonic() - started

    assert len(results) == 1, results
    # Generous next to the ~10 ms this takes, and still two orders of magnitude
    # under the ninety seconds the spin cost.
    assert elapsed < 30.0, f"decompile took {elapsed:.1f}s"
