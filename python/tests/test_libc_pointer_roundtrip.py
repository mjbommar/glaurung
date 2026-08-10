"""Real round trips for pointer-bearing libc contracts and stack locals."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest


def _compile(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    """Build a debuggable non-PIE executable with stable O0 stack locals."""
    return subprocess.run(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-o",
            str(output),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
def test_nullable_saved_locale_pointer_round_trip(tmp_path: Path) -> None:
    """Preserve setlocale/strdup pointer types through a nullable stack slot."""
    original_source = tmp_path / "locale.c"
    original_source.write_text(
        """
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) int locale_name_length(void) {
    char *old_locale = setlocale(LC_ALL, NULL);
    char *saved_locale = NULL;
    if (old_locale != NULL) {
        saved_locale = strdup(old_locale);
    }
    int length = saved_locale != NULL ? (int)strlen(saved_locale) : -1;
    free(saved_locale);
    return length;
}

int main(void) {
    printf("%d\\n", locale_name_length());
    return 0;
}
""".strip()
        + "\n"
    )
    original = tmp_path / "original"
    built = _compile(original_source, original)
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=500)
    target = next(
        (function for function in functions if function.name == "locale_name_length"),
        None,
    )
    assert target is not None, "locale_name_length was not discovered"
    generated = g.ir.decompile_at(
        str(original),
        int(target.entry_point.value),
        timeout_ms=8000,
        style="decbench",
    )

    assert "locale_name_length(void)" in generated, generated
    assert "extern char * setlocale(int, const char *);" in generated, generated
    assert "extern long setlocale" not in generated, generated
    assert "char * old_locale;" in generated, generated
    assert "char * saved_locale;" in generated, generated

    rebuilt_source = tmp_path / "rebuilt.c"
    rebuilt_source.write_text(
        generated
        + """

#include <stdio.h>
int main(void) {
    printf("%d\\n", locale_name_length());
    return 0;
}
"""
    )
    rebuilt = tmp_path / "rebuilt"
    rebuilt_result = _compile(rebuilt_source, rebuilt)
    assert rebuilt_result.returncode == 0, (
        f"generated nullable-locale C did not rebuild:\n"
        f"{rebuilt_result.stderr}\n{generated}"
    )

    expected = subprocess.run(
        [str(original)],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    actual = subprocess.run(
        [str(rebuilt)],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert expected.returncode == 0, expected.stderr
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == expected.stdout


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
def test_direct_string_argument_contract_round_trip(tmp_path: Path) -> None:
    """Use strcmp's locked parameter type to recover a direct char pointer."""
    original_source = tmp_path / "strcmp_arg.c"
    original_source.write_text(
        """
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) int matches_name(const char *candidate) {
    return strcmp(candidate, "known") == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    printf("%d\\n", matches_name(argv[1]));
    return 0;
}
""".strip()
        + "\n"
    )
    original = tmp_path / "original"
    built = _compile(original_source, original)
    assert built.returncode == 0, built.stderr

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=500)
    target = next(
        (function for function in functions if function.name == "matches_name"),
        None,
    )
    assert target is not None, "matches_name was not discovered"
    generated = g.ir.decompile_at(
        str(original),
        int(target.entry_point.value),
        timeout_ms=8000,
        style="decbench",
    )

    assert "matches_name(const char * arg0)" in generated, generated
    assert "matches_name(long" not in generated, generated
    assert "extern int strcmp(const char *, const char *);" in generated, generated

    rebuilt_source = tmp_path / "rebuilt.c"
    rebuilt_source.write_text(
        generated
        + """

#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    printf("%d\\n", matches_name(argv[1]));
    return 0;
}
"""
    )
    rebuilt = tmp_path / "rebuilt"
    rebuilt_result = _compile(rebuilt_source, rebuilt)
    assert rebuilt_result.returncode == 0, (
        f"generated direct-string-argument C did not rebuild:\n"
        f"{rebuilt_result.stderr}\n{generated}"
    )

    for candidate in ("known", "unknown", "", "known-suffix"):
        expected = subprocess.run(
            [str(original), candidate],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        actual = subprocess.run(
            [str(rebuilt), candidate],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert expected.returncode == 0, expected.stderr
        assert actual.returncode == 0, actual.stderr
        assert actual.stdout == expected.stdout


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
@pytest.mark.skipif(  # ty: ignore[unresolved-attribute]
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="gcc and strip are required",
)
def test_stripped_file_parameter_contract_round_trip(tmp_path: Path) -> None:
    """Recover FILE identity from compatible canonical call constraints."""
    original_source = tmp_path / "file_arg.c"
    original_source.write_text(
        """
#include <stdio.h>

__attribute__((noinline)) void write_marker(FILE *stream, int value) {
    fputc('[', stream);
    fputc(value, stream);
    fputc(']', stream);
    fputc('\\n', stream);
}

int main(void) {
    write_marker(stdout, '7');
    return 0;
}
""".strip()
        + "\n"
    )
    original = tmp_path / "original"
    built = _compile(original_source, original)
    assert built.returncode == 0, built.stderr
    stripped = subprocess.run(
        ["strip", "--strip-debug", str(original)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert stripped.returncode == 0, stripped.stderr

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=500)
    target = next(
        (function for function in functions if function.name == "write_marker"),
        None,
    )
    assert target is not None, "write_marker was not discovered"
    generated = g.ir.decompile_at(
        str(original),
        int(target.entry_point.value),
        timeout_ms=8000,
        style="decbench",
    )

    assert "typedef struct __glaurung_opaque_FILE FILE;" in generated, generated
    assert "write_marker(FILE * arg0, int arg1)" in generated, generated

    rebuilt_source = tmp_path / "rebuilt.c"
    rebuilt_source.write_text(
        generated
        + """

extern FILE *stdout;
int main(void) {
    write_marker(stdout, '7');
    return 0;
}
"""
    )
    rebuilt = tmp_path / "rebuilt"
    rebuilt_result = _compile(rebuilt_source, rebuilt)
    assert rebuilt_result.returncode == 0, (
        f"generated FILE-pointer C did not rebuild:\n"
        f"{rebuilt_result.stderr}\n{generated}"
    )

    expected = subprocess.run(
        [str(original)], capture_output=True, text=True, timeout=5, check=False
    )
    actual = subprocess.run(
        [str(rebuilt)], capture_output=True, text=True, timeout=5, check=False
    )
    assert expected.returncode == 0, expected.stderr
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == expected.stdout == "[7]\n"
