"""Integration tests for the `glaurung decompile` CLI subcommand."""

from __future__ import annotations

import shutil
import subprocess
import sys
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
    assert "call __libc_start_main(main" in result.stdout


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
    """Keep the ARM arg0/frame/result roles intact through the full pipeline."""
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
    assert "return local_" in text, text
    assert "return 0;" not in text, text


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
    rebuilt_source.write_text(
        "float arm_hf_callee(float, float);\n" + generated
    )
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

    assert (
        "float arm_mixed_storage(int arg0, float arg1, int arg2)"
        in generated
    ), generated
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

    signature = text.splitlines()[1]
    assert "arm_narrow_params(" in signature, text
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
    word_signature = word_text.splitlines()[1]
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
    name, va, text = results[0]
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
    name, va, text = results[0]
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
    for _name, _va, text in results:
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
