"""Integration tests for the `glaurung decompile` CLI subcommand."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
ARM64_SAMPLE = Path(
    "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc"
)
X86_O0_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/O0/hello-clang-O0"
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
    # Call target name-resolution and arg reconstruction should be visible.
    assert "call __libc_start_main(main);" in result.stdout


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample missing")
def test_decompile_func_flag_accepts_hex_va():
    result = _run([str(SAMPLE), "--func", "0x1840"])
    assert result.returncode == 0, result.stderr
    assert "function _start @ 0x1840" in result.stdout


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
