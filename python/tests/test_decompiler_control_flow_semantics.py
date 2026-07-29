"""Real-binary coverage for CFG edges that survive region structuring."""

from __future__ import annotations

import ctypes
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow


def _matching_brace(text: str, opening: int) -> int:
    """Return the closing brace paired with ``text[opening]``."""
    assert text[opening] == "{"
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unclosed brace at {opening}:\n{text}")


def test_switch_arms_reach_the_real_loop_latch(tmp_path: Path) -> None:
    """Every non-returning switch case must continue through the loop latch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "statemachine.c"
    binary = tmp_path / "statemachine-clang-O0.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["fsm"])
    assert code is not None

    # The preferred recovery is a structured switch whose C `break`s flow to
    # one latch after the switch.  Requiring a particular number of gotos made
    # this regression test fail when the structurer improved.  Check the real
    # ownership invariant instead: all ordinary cases end inside the switch,
    # and the one counter increment is lexically after it but still in the loop.
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_line = code[code.rfind("\n", 0, switch_at) + 1 : switch_at]
    assert switch_line == "        ", (
        "the typed range proof should make the switch a direct loop-body statement",
        code,
    )
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in (0, 1, 2):
        assert f"case {case}:" in switch_body, code
    assert switch_body.count("break;") >= 3, code

    explicit_latch = re.search(
        r"(?m)^\s*([A-Za-z_]\w*)\s*=.*\(\1\s*\+\s*1\)",
        code[switch_close + 1 :],
    )
    for_latch = re.search(
        r"(?m)^\s*for\s*\([^;\n]*;[^;\n]*;\s*([A-Za-z_]\w*)\s*=.*"
        r"\(\1\s*\+\s*1\).*\)\s*\{",
        code[:switch_at],
    )
    for_increment = re.search(
        r"(?m)^\s*for\s*\([^;\n]*;[^;\n]*;\s*([A-Za-z_]\w*)\+\+\s*\)\s*\{",
        code[:switch_at],
    )
    assert (
        explicit_latch is not None or for_latch is not None or for_increment is not None
    ), code

    rebuilt = D.build_so(code, tmp_path, "dec_fsm", link_against=str(binary))
    assert rebuilt is not None, code

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "statemachine",
            "--function",
            "fsm",
            "--seed",
            "1234",
            "--fuzz",
            "24",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["fsm"]["status"] == "pass", results


def test_gcc_o0_state_dispatch_recovers_switch_and_round_trips(tmp_path: Path) -> None:
    """A label-based GCC dispatch ladder must become the source switch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "statemachine.c"
    binary = tmp_path / "statemachine-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["fsm"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in (0, 1, 2, 3):
        assert f"case {case}:" in switch_body, code

    assert D.build_so(code, tmp_path, "dec_fsm_gcc", link_against=str(binary))
    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "statemachine",
            "--function",
            "fsm",
            "--seed",
            "1234",
            "--fuzz",
            "24",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["fsm"]["status"] == "pass", results


def test_cross_block_table_base_recovers_clang_o2_switch(tmp_path: Path) -> None:
    """A table base materialized in the loop preheader must reach its dispatch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "statemachine.c"
    binary = tmp_path / "statemachine-clang-O2.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["fsm"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in (0, 1, 2, 3):
        assert f"case {case}:" in switch_body, code
    assert "unrecovered indirect jump" not in code, code
    assert D.build_so(code, tmp_path, "dec_fsm_o2", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "statemachine",
            "--function",
            "fsm",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["fsm"]["status"] == "pass", results


def test_array_address_chain_folds_and_round_trips(tmp_path: Path) -> None:
    """Dead flag artifacts must not strand single-use array temporaries."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "arrays.c"
    binary = tmp_path / "arrays-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["sum_array"])
    assert code is not None
    assert "arg0[" in code and "local_4" in code, code
    assert "long var3;" not in code and "long var6;" not in code, code
    assert (
        D.build_so(code, tmp_path, "dec_sum_array", link_against=str(binary))
        is not None
    )

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "arrays",
            "--function",
            "sum_array",
            "--seed",
            "1234",
            "--fuzz",
            "24",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["sum_array"]["status"] == "pass", results


def test_gcc_o0_comparison_tree_recovers_switch_and_round_trips(tmp_path: Path) -> None:
    """The reconstructed x86 signed-greater condition must remain switch-shaped."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "switch_jt.c"
    binary = tmp_path / "switch_jt-gcc-O0.so"
    compiled = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["dispatch"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in range(8):
        assert f"case {case}:" in switch_body, code
    assert "goto L_" not in code, code
    assert D.build_so(code, tmp_path, "dec_dispatch", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "switch_jt",
            "--function",
            "dispatch",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["dispatch"]["status"] == "pass", results


def test_clang_o0_range_default_recovers_direct_return_switch(
    tmp_path: Path,
) -> None:
    """Clang's range guard and result join must recover the source switch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "switch_jt.c"
    binary = tmp_path / "switch_jt-clang-O0.so"
    compiled = subprocess.run(
        [
            "clang",
            "-shared",
            "-fPIC",
            "-g",
            "-O0",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["dispatch"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in range(8):
        assert f"case {case}:" in switch_body, code
    assert "default:" in switch_body, code
    assert switch_body.count("return ") >= 9, code
    assert "break;" not in switch_body, code
    assert "if (" not in code[:switch_at], code
    assert D.build_so(code, tmp_path, "dec_dispatch_clang", link_against=str(binary))

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "switch_jt",
            "--function",
            "dispatch",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["dispatch"]["status"] == "pass", results


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_optimized_early_default_recovers_one_exhaustive_switch(
    tmp_path: Path, compiler: str
) -> None:
    """An optimized early default return must join the following switch."""
    source = ROOT / "tests" / "decbench_corpus" / "src" / "switch_jt.c"
    binary = tmp_path / f"switch_jt-{compiler}-O2.so"
    compiled = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-g",
            "-O2",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr

    functions = D.exported_functions(str(binary))
    code = D.decompiled_c(str(binary), functions["dispatch"])
    assert code is not None
    switch_at = code.find("switch (")
    assert switch_at >= 0, code
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in range(8):
        assert f"case {case}:" in switch_body, code
    assert "default:" in switch_body, code
    assert switch_body.count("return ") >= 9, code
    assert "if (" not in code[:switch_at], code

    rebuilt = D.build_so(
        code,
        tmp_path,
        f"dec_dispatch_{compiler}_o2",
        link_against=str(binary),
    )
    assert rebuilt is not None, code

    # GCC can fragment the O2 DWARF signature beyond what the generic harness
    # currently reconstructs. Execute the known source prototype directly so
    # that missing debug metadata cannot turn this semantic check structural.
    original_lib = ctypes.CDLL(str(binary))
    rebuilt_lib = ctypes.CDLL(str(rebuilt))
    original_dispatch = original_lib.dispatch
    rebuilt_dispatch = rebuilt_lib.dispatch
    for function in [original_dispatch, rebuilt_dispatch]:
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
        function.restype = ctypes.c_int
    for op in range(-2, 10):
        for lhs, rhs in [(-9, -3), (-3, 9), (0, -1), (7, 5)]:
            assert rebuilt_dispatch(op, lhs, rhs) == original_dispatch(op, lhs, rhs)

    compared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(source),
            "--fixture",
            "switch_jt",
            "--function",
            "dispatch",
            "--seed",
            "1234",
            "--fuzz",
            "64",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results = json.loads(compared.stdout)
    assert compared.returncode == 0, results
    assert results["dispatch"]["status"] in {"pass", "structural"}, results
