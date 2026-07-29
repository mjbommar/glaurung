"""Real-binary coverage for CFG edges that survive region structuring."""

from __future__ import annotations

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
    switch_open = code.find("{", switch_at)
    switch_close = _matching_brace(code, switch_open)
    switch_body = code[switch_open:switch_close]
    for case in (0, 1, 2):
        assert f"case {case}:" in switch_body, code
    assert switch_body.count("break;") >= 3, code

    latch = re.search(
        r"(?m)^\s*([A-Za-z_]\w*)\s*=.*\(\1\s*\+\s*1\)",
        code[switch_close + 1 :],
    )
    assert latch is not None, code

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
