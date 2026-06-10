"""Tests for the native execution engine Python surface (`glaurung.engine`).

These drive the Rust concrete emulator end-to-end on real sample binaries.
"""

from pathlib import Path

import pytest

import glaurung

X86_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
ARM64_SAMPLE = Path(
    "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc"
)

_VALID_OUTCOMES = {"returned", "called_out", "halted", "budget_exhausted", "no_block"}


def _first_function_va(path: Path) -> int:
    """Return the VA of a discovered function (decompile_all → (name, va, src))."""
    funcs = glaurung.ir.decompile_all(str(path))
    assert funcs, "no functions discovered"
    return funcs[0][1]


def test_engine_submodule_present():
    assert hasattr(glaurung, "engine")
    assert hasattr(glaurung.engine, "emulate_function")


@pytest.mark.skipif(not X86_SAMPLE.exists(), reason="x86-64 sample missing")
def test_emulate_x86_64_function():
    va = _first_function_va(X86_SAMPLE)
    res = glaurung.engine.emulate_function(
        str(X86_SAMPLE), va, arch="x86_64", max_steps=50_000
    )
    assert res["outcome"] in _VALID_OUTCOMES
    assert res["steps"] > 0, "emulator made no progress"
    # The full x86-64 GPR set is reported.
    for r in ("rax", "rsp", "rip", "r15"):
        assert r in res["regs"]
        assert isinstance(res["regs"][r], int)


@pytest.mark.skipif(not ARM64_SAMPLE.exists(), reason="arm64 sample missing")
def test_emulate_arm64_function():
    va = _first_function_va(ARM64_SAMPLE)
    res = glaurung.engine.emulate_function(
        str(ARM64_SAMPLE), va, arch="arm64", max_steps=50_000
    )
    assert res["outcome"] in _VALID_OUTCOMES
    assert res["steps"] > 0
    for r in ("x0", "x30", "sp"):
        assert r in res["regs"]


def test_emulate_rejects_unknown_arch():
    if not X86_SAMPLE.exists():
        pytest.skip("sample missing")
    va = _first_function_va(X86_SAMPLE)
    with pytest.raises(ValueError):
        glaurung.engine.emulate_function(str(X86_SAMPLE), va, arch="sparc")


def test_emulate_rejects_unknown_va():
    if not X86_SAMPLE.exists():
        pytest.skip("sample missing")
    with pytest.raises(ValueError):
        glaurung.engine.emulate_function(str(X86_SAMPLE), 0xDEAD_BEEF, arch="x86_64")


def test_emulate_is_deterministic():
    """Two runs of the same input produce identical results (a house rule)."""
    if not X86_SAMPLE.exists():
        pytest.skip("sample missing")
    va = _first_function_va(X86_SAMPLE)
    a = glaurung.engine.emulate_function(str(X86_SAMPLE), va, arch="x86_64")
    b = glaurung.engine.emulate_function(str(X86_SAMPLE), va, arch="x86_64")
    assert a == b
