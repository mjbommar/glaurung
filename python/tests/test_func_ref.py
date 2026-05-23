"""Tests for the --func name/VA argument helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from glaurung.cli.func_ref import (
    FuncResolutionError,
    parse_func_arg,
    resolve_func_to_va,
)


# ---- parse_func_arg ----

def test_parse_func_arg_hex():
    assert parse_func_arg("0x140001480") == 0x140001480


def test_parse_func_arg_decimal():
    assert parse_func_arg("1234") == 1234


def test_parse_func_arg_binary():
    assert parse_func_arg("0b101010") == 42


def test_parse_func_arg_octal():
    assert parse_func_arg("0o777") == 511


def test_parse_func_arg_name_string():
    assert parse_func_arg("main") == "main"
    assert parse_func_arg("vuln") == "vuln"
    assert parse_func_arg("session_create") == "session_create"


def test_parse_func_arg_empty_rejected():
    with pytest.raises(ValueError):
        parse_func_arg("")
    with pytest.raises(ValueError):
        parse_func_arg("   ")


def test_parse_func_arg_strips_whitespace():
    assert parse_func_arg("  0x42  ") == 0x42
    assert parse_func_arg("  main  ") == "main"


# ---- resolve_func_to_va ----

class _FnStub:
    """Mimics glaurung.analysis.Function for resolver tests."""
    def __init__(self, name: str, va: int):
        self.name = name
        class _Addr:
            def __init__(self, v):
                self.value = v
        self.entry_point = _Addr(va)


def test_resolve_exact_match():
    fns = [
        _FnStub("vuln", 0x140001480),
        _FnStub("main", 0x1400014ed),
        _FnStub("sub_140001000", 0x140001000),
    ]
    assert resolve_func_to_va("vuln", fns) == 0x140001480


def test_resolve_suffix_module_qualified():
    fns = [
        _FnStub("sessmgr!session_create", 0x180001100),
        _FnStub("sub_180001200", 0x180001200),
    ]
    assert resolve_func_to_va("session_create", fns) == 0x180001100


def test_resolve_missing_raises_with_suggestions():
    fns = [
        _FnStub("dispatch_to_console", 0x140001000),
        _FnStub("dispatch_to_file", 0x140001100),
    ]
    with pytest.raises(FuncResolutionError) as ei:
        resolve_func_to_va("dispatch_to_logger", fns)
    msg = str(ei.value)
    assert "no function named 'dispatch_to_logger'" in msg
    # Suggest similar names
    assert "dispatch_to_console" in msg or "dispatch_to_file" in msg


def test_resolve_stripped_binary_hint():
    """When all functions are sub_<VA> (no symbols recovered), the error
    must explain that the binary is stripped, not just 'name not found'."""
    fns = [
        _FnStub("sub_140001000", 0x140001000),
        _FnStub("sub_140001100", 0x140001100),
    ]
    with pytest.raises(FuncResolutionError) as ei:
        resolve_func_to_va("vuln", fns)
    assert "stripped" in str(ei.value).lower()


def test_resolve_ambiguous_raises():
    fns = [
        _FnStub("foo", 0x100),
        _FnStub("foo", 0x200),
    ]
    with pytest.raises(FuncResolutionError) as ei:
        resolve_func_to_va("foo", fns)
    assert "ambiguous" in str(ei.value)


# ---- end-to-end CLI test ----

V1_CORPUS = Path(
    "/nas4/data/workspace-infosec/scratch/cwe-demo-corpus-2026-05-22/build/cwe121_strcpy.exe"
)


@pytest.mark.skipif(
    not V1_CORPUS.exists(),
    reason="v1 demo corpus not present at expected path",
)
def test_cli_decompile_by_name_matches_decompile_by_va():
    """`glaurung decompile --func vuln` and `--func 0x1400014b4` must produce
    the same pseudocode on the v1 corpus's cwe121_strcpy.exe (which has the
    'vuln' symbol intact)."""
    here = Path(__file__).resolve().parents[2]
    glaurung_bin = here / ".venv" / "bin" / "glaurung"
    if not glaurung_bin.exists():
        pytest.skip("venv glaurung CLI not built")

    by_name = subprocess.run(
        [str(glaurung_bin), "decompile", str(V1_CORPUS),
         "--func", "vuln", "--style", "c"],
        capture_output=True, text=True, timeout=60,
    )
    by_va = subprocess.run(
        [str(glaurung_bin), "decompile", str(V1_CORPUS),
         "--func", "0x1400014b4", "--style", "c"],
        capture_output=True, text=True, timeout=60,
    )
    assert by_name.returncode == 0, f"name path failed: {by_name.stderr}\n{by_name.stdout}"
    assert by_va.returncode == 0, f"VA path failed: {by_va.stderr}\n{by_va.stdout}"
    # Output should be identical (same VA resolved both ways).
    assert by_name.stdout == by_va.stdout
    # Sanity: the pseudocode body mentions our function name.
    assert "vuln" in by_name.stdout
