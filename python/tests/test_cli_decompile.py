"""Integration tests for the `glaurung decompile` CLI subcommand."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import glaurung as g


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


@pytest.mark.skipif(not PE32_PLUS_SAMPLE.exists(), reason="PE32+ sample missing")
def test_decompile_pe32_plus_resolves_iat_names():
    text = g.ir.decompile_at(
        str(PE32_PLUS_SAMPLE),
        0x140001190,
        timeout_ms=1000,
        style="c",
    )
    assert "GetStartupInfoA(arg2);" in text
    assert "0x14000d1ec(" not in text
    assert "Sleep" in text
    assert "0x14000d21c" not in text


@pytest.mark.skipif(not PE32_PLUS_SAMPLE.exists(), reason="PE32+ sample missing")
def test_pe_iat_map_exposes_api_aliases():
    got = g.analysis.pe_iat_map_path(str(PE32_PLUS_SAMPLE))
    names = {name for _, name in got}
    assert {"malloc", "LeaveCriticalSection"} & names
    assert any(va for va, _ in got)
