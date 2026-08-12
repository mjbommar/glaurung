"""Real stripped round trips for inferred memory objects and aggregate cursors."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import glaurung as g
import pytest
from _pytest.capture import CaptureFixture
from _pytest.monkeypatch import MonkeyPatch


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


@pytest.mark.slow  # ty: ignore[unresolved-attribute]
@pytest.mark.skipif(  # ty: ignore[unresolved-attribute]
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="gcc and strip are required",
)
def test_stripped_aggregate_cursor_preserves_byte_stride_and_execution(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capfd: CaptureFixture[str],
) -> None:
    """Recover a no-debug 64-byte record cursor without guessing its source tag."""
    source = tmp_path / "records.c"
    source.write_text(
        """
#include <stdio.h>

typedef struct {
    long reserved[5];
    int current;
    int count;
    unsigned char tail[16];
} Record;

static Record *records;

__attribute__((noinline)) int balance_records(int total) {
    int accumulated = 0;
    Record *cursor = records;
    for (int i = 1; i <= 3; ++i) {
        int lines = total / 3;
        if (i <= total % 3) {
            ++lines;
        }
        cursor->count = lines;
        cursor->current = accumulated;
        accumulated += lines;
        ++cursor;
    }
    return records[2].current + records[2].count;
}

int main(void) {
    Record storage[3] = {0};
    records = storage;
    printf("%d\\n", balance_records(10));
    return 0;
}
""".strip()
        + "\n"
    )
    original = tmp_path / "original"
    compiled = _run(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-o",
            str(original),
            str(source),
        ]
    )
    assert compiled.returncode == 0, compiled.stderr

    functions, _ = g.analysis.analyze_functions_path(str(original), max_functions=500)
    target = next(
        (function for function in functions if function.name == "balance_records"),
        None,
    )
    assert target is not None, "balance_records was not discovered"
    target_va = int(target.entry_point.value)

    stripped = tmp_path / "stripped"
    shutil.copy2(original, stripped)
    stripped_result = _run(["strip", "--strip-all", str(stripped)])
    assert stripped_result.returncode == 0, stripped_result.stderr

    monkeypatch.setenv("GLAURUNG_DUMP_PASSES", "1")
    generated = g.ir.decompile_at(
        str(stripped),
        target_va,
        timeout_ms=8000,
        style="decbench",
    )
    diagnostic = capfd.readouterr().err
    assert "===== verified LLIR memory SSA =====" in diagnostic
    assert "===== LLIR memory objects =====" in diagnostic
    assert "LlirInstruction" in diagnostic
    assert "region: HeapUnknown" in diagnostic
    assert re.search(r"memory_region: Some\(\s+HeapUnknown,", diagnostic)
    assert "region: FullyUnknown" in diagnostic
    assert "===== invalid LLIR memory analysis =====" not in diagnostic
    cursor_match = re.search(r"char \* (local_[0-9a-f]+);", generated)
    assert cursor_match is not None, generated
    cursor_name = cursor_match.group(1)
    assert f"({cursor_name} + 64)" in generated, generated
    assert f"{cursor_name} + 256" not in generated, generated

    globals_ = sorted(set(re.findall(r"glaurung_global_[0-9a-f]+", generated)))
    assert len(globals_) == 1, generated
    function_match = re.search(r"// glaurung: (sub_[0-9a-f]+) @", generated)
    assert function_match is not None, generated

    rebuilt_source = tmp_path / "rebuilt.c"
    rebuilt_source.write_text(
        generated
        + f"""

#include <stdio.h>
#include <stdlib.h>
int main(void) {{
    void *storage = calloc(3, 64);
    if (storage == NULL) return 2;
    *(void **)(&{globals_[0]}[0]) = storage;
    printf("%d\\n", {function_match.group(1)}(10));
    free(storage);
    return 0;
}}
"""
    )
    rebuilt = tmp_path / "rebuilt"
    rebuilt_result = _run(
        [
            "gcc",
            "-O0",
            "-Werror=uninitialized",
            "-fno-pie",
            "-no-pie",
            "-o",
            str(rebuilt),
            str(rebuilt_source),
        ]
    )
    assert rebuilt_result.returncode == 0, (
        f"generated aggregate-cursor C did not rebuild:\n"
        f"{rebuilt_result.stderr}\n{generated}"
    )

    expected = _run([str(original)])
    actual = _run([str(rebuilt)])
    assert expected.returncode == 0, expected.stderr
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == expected.stdout == "10\n"
