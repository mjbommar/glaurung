"""Tests for the verify_compile / verify_runtime memory tools (#171/#202)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.tools.verify_recovery_tool import (
    build_verify_compile_tool,
    build_verify_runtime_tool,
    VerifyCompileArgs,
    VerifyRuntimeArgs,
)


def _need_compiler() -> None:
    import shutil
    if shutil.which("gcc") is None and shutil.which("clang") is None:
        pytest.skip("no C compiler on PATH")


def _stub_ctx_kb():
    """Build the smallest MemoryContext + KB pair the tools need."""
    from types import SimpleNamespace
    return SimpleNamespace(kb=SimpleNamespace()), SimpleNamespace()


def test_verify_compile_tool_accepts_clean_source() -> None:
    _need_compiler()
    tool = build_verify_compile_tool()
    ctx, kb = _stub_ctx_kb()
    res = tool.run(ctx, kb, VerifyCompileArgs(
        source="int main(void) { return 0; }",
    ))
    assert res.ok
    assert res.exit_code == 0
    assert res.stderr == "" or "warning" in res.stderr.lower()


def test_verify_compile_tool_reports_failure() -> None:
    _need_compiler()
    tool = build_verify_compile_tool()
    ctx, kb = _stub_ctx_kb()
    res = tool.run(ctx, kb, VerifyCompileArgs(
        source="not even close to C",
    ))
    assert not res.ok
    assert res.exit_code != 0
    assert res.stderr  # compiler must emit a diagnostic


def test_verify_runtime_tool_executes_source() -> None:
    _need_compiler()
    tool = build_verify_runtime_tool()
    ctx, kb = _stub_ctx_kb()
    res = tool.run(ctx, kb, VerifyRuntimeArgs(
        source="""
        #include <stdio.h>
        int main(int argc, char **argv) {
            printf("argc=%d\\n", argc);
            return argc;
        }
        """,
        args=["a", "b"],
    ))
    assert res.compile_ok
    assert res.exit_code == 3  # argv[0] + a + b
    assert "argc=3" in res.stdout


def test_verify_runtime_tool_compares_to_target(tmp_path: Path) -> None:
    """Build a target binary; pass the same source to verify_runtime
    with target_binary set; confirm same_exit_code/same_stdout."""
    _need_compiler()
    import subprocess

    src = """
    #include <stdio.h>
    int main(int argc, char **argv) {
        printf("hello\\n");
        return 0;
    }
    """
    bin_path = tmp_path / "ref"
    src_path = tmp_path / "ref.c"
    src_path.write_text(src)
    proc = subprocess.run(
        ["gcc", "-O0", "-w", "-o", str(bin_path), str(src_path)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        pytest.skip(f"target compile failed: {proc.stderr}")

    tool = build_verify_runtime_tool()
    ctx, kb = _stub_ctx_kb()
    res = tool.run(ctx, kb, VerifyRuntimeArgs(
        source=src, target_binary=str(bin_path),
    ))
    assert res.compile_ok
    assert res.same_exit_code is True
    assert res.same_stdout is True
    assert res.target_stdout == "hello\n"
