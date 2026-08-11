"""Real-binary coverage for caller-proven source parameter arity."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def _parameter_names(generated: str) -> list[str]:
    """Return source parameter names from one rendered function header."""
    header = generated.split("{", 1)[0].strip().splitlines()[-1]
    return re.findall(r"\barg\d+\b", header)


def test_real_stripped_direct_callers_restore_unused_stack_parameter(
    tmp_path: Path,
) -> None:
    """Lock an optimized-away eighth parameter only from agreeing direct calls.

    The definition and callers are separate translation units, matching the
    interprocedural boundary in the OpenSSH benchmark.  The eighth parameter is
    never read by either target body, but two direct calls must still pass it in
    the SysV stack area.  An otherwise identical indirect-only target and a
    six-register target are fail-closed controls.
    """
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    objdump = shutil.which("objdump")
    if compiler is None or strip is None or objdump is None:
        pytest.skip("host gcc, strip, and objdump are required")

    definitions = tmp_path / "definitions.c"
    callers = tmp_path / "callers.c"
    definitions_object = tmp_path / "definitions.o"
    callers_object = tmp_path / "callers.o"
    binary = tmp_path / "caller_arity"
    stripped = tmp_path / "caller_arity.stripped"
    definitions.write_text(
        "__attribute__((noinline, used)) long eight_target(\n"
        "    long a0, long a1, long a2, long a3,\n"
        "    long a4, long a5, long a6, long unused_a7) {\n"
        "    (void)unused_a7;\n"
        "    return a0 + a1 + a2 + a3 + a4 + a5 + a6;\n"
        "}\n"
        "__attribute__((noinline, used)) long indirect_target(\n"
        "    long a0, long a1, long a2, long a3,\n"
        "    long a4, long a5, long a6, long unused_a7) {\n"
        "    (void)unused_a7;\n"
        "    return a0 - a1 + a2 - a3 + a4 - a5 + a6;\n"
        "}\n"
        "__attribute__((noinline, used)) long single_target(\n"
        "    long a0, long a1, long a2, long a3,\n"
        "    long a4, long a5, long a6, long unused_a7) {\n"
        "    (void)unused_a7;\n"
        "    return a0 + a1 - a2 + a3 - a4 + a5 - a6;\n"
        "}\n"
        "__attribute__((noinline, used)) long six_target(\n"
        "    long a0, long a1, long a2, long a3, long a4, long a5) {\n"
        "    return a0 + a1 + a2 + a3 + a4 + a5;\n"
        "}\n"
    )
    callers.write_text(
        "typedef long (*eight_fn)(long, long, long, long, long, long, long, long);\n"
        "extern long eight_target(long, long, long, long, long, long, long, long);\n"
        "extern long indirect_target(long, long, long, long, long, long, long, long);\n"
        "extern long single_target(long, long, long, long, long, long, long, long);\n"
        "extern long six_target(long, long, long, long, long, long);\n"
        "eight_fn volatile selected_target;\n"
        "__attribute__((noinline, used)) long first_caller(long value) {\n"
        "    (void)value;\n"
        "    return eight_target(10, 2, 3, 4, 5, 6, 7, 8);\n"
        "}\n"
        "__attribute__((noinline, used)) long second_caller(long value) {\n"
        "    return eight_target(1, value, 3, 4, 5, 6, 7, 9);\n"
        "}\n"
        "__attribute__((noinline, used)) long single_caller(long value) {\n"
        "    return single_target(1, value, 3, 4, 5, 6, 7, 9);\n"
        "}\n"
        "int main(int argc, char **argv) {\n"
        "    selected_target = indirect_target;\n"
        "    long indirect = selected_target(argc, 2, 3, 4, 5, 6, 7, 8);\n"
        "    long six = six_target(argc, 2, 3, 4, 5, 6);\n"
        "    return (int)(first_caller(argc) + second_caller(argc)\n"
        "        + single_caller(argc) + indirect + six\n"
        "        + (argv == 0));\n"
        "}\n"
    )
    common = [compiler, "-O2", "-fno-inline", "-fno-pie", "-g", "-c"]
    for source, output in (
        (definitions, definitions_object),
        (callers, callers_object),
    ):
        built = subprocess.run(
            [*common, "-o", str(output), str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert built.returncode == 0, built.stderr
    linked = subprocess.run(
        [
            compiler,
            "-no-pie",
            "-o",
            str(binary),
            str(definitions_object),
            str(callers_object),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert linked.returncode == 0, linked.stderr

    disassembled = subprocess.run(
        [objdump, "-drwC", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert disassembled.returncode == 0, disassembled.stderr
    assert len(re.findall(r"call\s+[^\n]*<eight_target>", disassembled.stdout)) == 2
    assert len(re.findall(r"call\s+[^\n]*<single_target>", disassembled.stdout)) == 1
    assert not re.search(r"call\s+[^\n]*<indirect_target>", disassembled.stdout)

    functions, _ = g.analysis.analyze_functions_path(str(binary), max_functions=128)
    expected_names = {
        "eight_target",
        "indirect_target",
        "single_target",
        "six_target",
    }
    targets = {
        function.name: int(function.entry_point.value)
        for function in functions
        if function.name in expected_names
    }
    assert targets.keys() == expected_names, [function.name for function in functions]

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
    rendered = {int(va): text for _, va, text in results}
    assert _parameter_names(rendered[targets["eight_target"]]) == [
        f"arg{index}" for index in range(8)
    ], rendered[targets["eight_target"]]
    assert _parameter_names(rendered[targets["indirect_target"]]) == [
        f"arg{index}" for index in range(7)
    ], rendered[targets["indirect_target"]]
    assert _parameter_names(rendered[targets["single_target"]]) == [
        f"arg{index}" for index in range(7)
    ], rendered[targets["single_target"]]
    assert _parameter_names(rendered[targets["six_target"]]) == [
        f"arg{index}" for index in range(6)
    ], rendered[targets["six_target"]]
