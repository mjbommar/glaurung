"""Tests for recovered-source verification (#202 v0)."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.llm.kb.verify_recovery import (
    _resolve_compiler,
    byte_similarity_against_target,
    compile_check,
    compile_to_object,
)


def _need_compiler() -> None:
    if _resolve_compiler(None) is None:
        pytest.skip("no C compiler on PATH")


def test_clean_source_compiles() -> None:
    _need_compiler()
    src = """
    #include <stdio.h>
    int add(int a, int b) { return a + b; }
    int main(void) { return add(2, 3); }
    """
    result = compile_check(src)
    assert result.ok, f"clean source should compile; stderr was:\n{result.stderr}"
    assert result.exit_code == 0


def test_broken_source_fails_with_stderr() -> None:
    _need_compiler()
    src = """
    int main(void) { broken_garbage(@$#); }
    """
    result = compile_check(src)
    assert not result.ok
    assert result.exit_code != 0
    assert result.stderr  # compiler should emit a diagnostic


def test_compile_to_object_produces_real_o_file(tmp_path: Path) -> None:
    _need_compiler()
    src = "int func(int x) { return x * 2; }"
    obj = compile_to_object(src)
    assert obj is not None
    assert obj.exists()
    assert obj.suffix == ".o"
    # Object file is a real ELF (or COFF / Mach-O); spot-check the
    # ELF magic since we're on Linux.
    head = obj.read_bytes()[:4]
    assert head == b"\x7fELF" or head[:2] == b"MZ"


def test_compile_check_reports_no_compiler_clean(monkeypatch) -> None:
    """Pretend gcc/clang/cc are all gone; the helper should report
    a clean failure rather than crash."""
    monkeypatch.setattr(
        "shutil.which", lambda _name: None,
    )
    result = compile_check("int main(void) { return 0; }")
    assert not result.ok
    assert "no C/C++ compiler" in result.stderr


def test_byte_similarity_against_target_smoke(tmp_path: Path) -> None:
    """End-to-end: pick a real binary, write a stub C source naming
    the same function, run the similarity helper. Score should be
    something — exact value depends on the compiler's codegen, but
    the report must be well-shaped."""
    _need_compiler()
    target = Path(
        "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
    )
    if not target.exists():
        pytest.skip(f"missing sample {target}")

    # A trivially-different reimplementation of `dispatch` from
    # switchy-c-gcc-O2. The byte-similarity score is expected to be
    # low (different codegen will produce wildly different bytes),
    # but the function structure is the same.
    src = """
    int dispatch(int op, int a, int b) {
        switch (op) {
            case 0: return a + b;
            case 1: return a - b;
            case 2: return a * b;
            default: return 0;
        }
    }
    """
    sim = byte_similarity_against_target(src, str(target), "dispatch")
    assert sim.function_name == "dispatch"
    # Score lives in [0, 1].
    assert 0.0 <= sim.score <= 1.0
    # Either the compile worked and we have non-zero recovered_size,
    # or the helper reported `notes` explaining why not.
    assert sim.recovered_size > 0 or sim.notes


def test_cli_subcommand_compiles_clean(tmp_path: Path) -> None:
    _need_compiler()
    from glaurung.cli.main import GlaurungCLI

    src_path = tmp_path / "ok.c"
    src_path.write_text("int main(void) { return 0; }\n")
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["verify-recovery", str(src_path)])
    out = buf.getvalue()
    assert rc == 0
    assert "compile: ✅" in out


def test_build_and_run_executes_recovered_source() -> None:
    """Compile + run a tiny C program; verify stdout / exit-code
    captured correctly."""
    _need_compiler()
    from glaurung.llm.kb.verify_recovery import build_and_run

    src = """
    #include <stdio.h>
    int main(int argc, char **argv) {
        printf("hello %s\\n", argc > 1 ? argv[1] : "world");
        return 42;
    }
    """
    rr = build_and_run(src, args=["bench"])
    assert rr.compile_ok
    assert rr.exit_code == 42
    assert rr.stdout == "hello bench\n"
    assert rr.runtime_ms >= 0.0


def test_build_and_run_reports_compile_failure() -> None:
    _need_compiler()
    from glaurung.llm.kb.verify_recovery import build_and_run

    rr = build_and_run("garbage source")
    assert not rr.compile_ok
    assert "compile-failed" in rr.notes


def test_build_and_run_runtime_timeout() -> None:
    """An infinite loop hits the configured timeout and is reported
    as `run-timeout` rather than hanging the test."""
    _need_compiler()
    from glaurung.llm.kb.verify_recovery import build_and_run

    src = "int main(void) { while (1); }"
    rr = build_and_run(src, timeout_seconds=0.5)
    assert rr.compile_ok
    assert "run-timeout" in rr.notes


def test_compare_runtime_to_target_reports_agreement() -> None:
    """Build a small binary; build a "recovered" copy of its source;
    compare execution. They should agree on every dimension."""
    _need_compiler()
    import subprocess
    import tempfile

    src = """
    #include <stdio.h>
    int main(int argc, char **argv) {
        printf("%d\\n", argc);
        return 0;
    }
    """

    # Build the target binary directly.
    with tempfile.TemporaryDirectory() as td:
        src_path = Path(td) / "target.c"
        bin_path = Path(td) / "target"
        src_path.write_text(src)
        proc = subprocess.run(
            ["gcc", "-O0", "-w", "-o", str(bin_path), str(src_path)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            pytest.skip(f"target compile failed: {proc.stderr}")

        from glaurung.llm.kb.verify_recovery import compare_runtime_to_target

        cmp = compare_runtime_to_target(
            src, str(bin_path), args=["a", "b", "c"],
        )
        # Identical sources → identical outputs.
        assert cmp.same_exit_code
        assert cmp.same_stdout
        assert cmp.same_stderr
        assert cmp.target_run.stdout.strip() == "4"
        assert cmp.recovered_run.stdout.strip() == "4"


def test_compare_runtime_detects_disagreement() -> None:
    """A "recovered" source that returns a different exit code than
    the target should produce same_exit_code=False."""
    _need_compiler()
    import subprocess
    import tempfile

    target_src = "int main(void) { return 0; }"
    recovered_src = "int main(void) { return 7; }"

    with tempfile.TemporaryDirectory() as td:
        src_path = Path(td) / "target.c"
        bin_path = Path(td) / "target"
        src_path.write_text(target_src)
        proc = subprocess.run(
            ["gcc", "-O0", "-w", "-o", str(bin_path), str(src_path)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            pytest.skip(f"target compile failed: {proc.stderr}")

        from glaurung.llm.kb.verify_recovery import compare_runtime_to_target

        cmp = compare_runtime_to_target(recovered_src, str(bin_path))
        assert cmp.target_run.exit_code == 0
        assert cmp.recovered_run.exit_code == 7
        assert cmp.same_exit_code is False
        # stdouts both empty → still equal.
        assert cmp.same_stdout is True


def test_cli_subcommand_reports_compile_failure(tmp_path: Path) -> None:
    _need_compiler()
    from glaurung.cli.main import GlaurungCLI

    src_path = tmp_path / "broken.c"
    src_path.write_text("int main(void) { syntax error here; }\n")
    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["verify-recovery", str(src_path)])
    out = buf.getvalue()
    assert rc == 1
    assert "compile:" in out and "❌" in out
