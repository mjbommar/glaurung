"""Real-binary integration coverage for program-level format inference."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def test_real_stripped_local_vfprintf_sink_types_literal_format_operands(
    tmp_path: Path,
) -> None:
    """Recover caller parameters consumed by a stripped local printf wrapper.

    The local sink proves its format parameter by forwarding it to ``vfprintf``
    through a real SysV variadic register-save prologue.  The positive caller's
    translated literal then proves its first source input is a string.  A
    dynamic format and contradictory literal formats must remain unknown.
    """
    compiler = shutil.which("gcc")
    strip = shutil.which("strip")
    if compiler is None or strip is None:
        pytest.skip("host gcc and strip are required")

    source = tmp_path / "local_format_sink.c"
    binary = tmp_path / "local_format_sink"
    stripped = tmp_path / "local_format_sink.stripped"
    source.write_text(
        "#include <libintl.h>\n"
        "#include <stdarg.h>\n"
        "#include <stdint.h>\n"
        "#include <stdio.h>\n"
        "__attribute__((noinline, used, format(printf, 1, 2)))\n"
        "static void report_message(const char *format, ...) {\n"
        "    va_list args;\n"
        "    va_start(args, format);\n"
        "    vfprintf(stderr, format, args);\n"
        "    va_end(args);\n"
        '    __fprintf_chk(stderr, 1, "\\n");\n'
        "}\n"
        "__attribute__((noinline, used)) void literal_caller(\n"
        "    const char *name, unsigned long bytes) {\n"
        '    report_message(dcgettext(0, "%s: %lu bytes", 5), name, bytes);\n'
        "}\n"
        "__attribute__((noinline, used)) void dynamic_caller(\n"
        "    const char *format, const char *value) {\n"
        "    report_message(format, value);\n"
        "}\n"
        "__attribute__((noinline, used)) void conflicting_caller(uintptr_t value) {\n"
        '    if (value & 1) report_message("%s", (char *)value);\n'
        '    else report_message("%lu", (unsigned long)value);\n'
        "}\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc > 2) dynamic_caller(argv[1], argv[2]);\n"
        "    literal_caller(argv[0], (unsigned long)argc);\n"
        "    conflicting_caller((uintptr_t)argv[0]);\n"
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
    names = {"literal_caller", "dynamic_caller", "conflicting_caller"}
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
    rendered = {int(va): text for _, va, text in results}
    literal_text = rendered[targets["literal_caller"]]
    assert "char * arg0" in literal_text.split("{", 1)[0], literal_text
    for name in ("dynamic_caller", "conflicting_caller"):
        control = rendered[targets[name]]
        assert "char * arg0" not in control.split("{", 1)[0], control
