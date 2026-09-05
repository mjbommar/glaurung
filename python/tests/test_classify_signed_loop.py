"""The signed repeated-subtraction loop stays source-shaped and executable."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tests" / "fixtures" / "classify_signed_loop.c"


def _build(compiler: str, output: Path) -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC  # ty: ignore[unresolved-import]

    result = TC.run(
        [compiler, "-shared", "-fPIC", "-g", "-O0", "-o", str(output), str(SOURCE)],
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def _decompile(binary: Path, function: str) -> str:
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            str(binary),
            "--func",
            function,
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )
    return result.stdout


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_signed_loop_recovers_a_relational_predicate_and_executes(
    compiler: str, tmp_path: Path
) -> None:
    debug = tmp_path / f"classify-{compiler}-O0.so"
    stripped = tmp_path / f"classify-{compiler}-O0-stripped.so"
    _build(compiler, debug)
    shutil.copy2(debug, stripped)
    strip = subprocess.run(
        ["strip", "--strip-debug", str(stripped)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert strip.returncode == 0, strip.stderr

    for binary in (debug, stripped):
        text = _decompile(binary, "classify")
        signature = re.search(r"\bint classify\(int ([A-Za-z_]\w*)\)", text)
        assert signature is not None, text
        parameter = signature.group(1)
        assert "unsigned int classify(" not in text, text
        assert f"if (0 <= {parameter})" in text, text
        assert f"while (100 < {parameter})" in text, text
        assert f"(long)({parameter})" not in text, text
        assert "== 100) |" not in text, text
        assert "return -1;" in text, text
        assert "return (unsigned int)(" not in text, text
        assert "glaurung-verify" not in text, text
        syntax = subprocess.run(
            ["cc", "-fsyntax-only", "-x", "c", "-"],
            input=text,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert syntax.returncode == 0, syntax.stderr

        command = [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(SOURCE),
            "--function",
            "classify",
            "--json",
        ]
        if binary == stripped:
            command.extend(["--reference-so", str(debug), "--dwarf-so", str(debug)])
        differential = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        verdict = json.loads(differential.stdout)["classify"]
        assert verdict["status"] == "pass", verdict
        assert verdict["detail"] == "34 cases", verdict

        unsigned_text = _decompile(binary, "classify_unsigned")
        assert "unsigned int classify_unsigned(" in unsigned_text, unsigned_text
        assert "return -1;" not in unsigned_text, unsigned_text
        unsigned_syntax = subprocess.run(
            ["cc", "-fsyntax-only", "-x", "c", "-"],
            input=unsigned_text,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert unsigned_syntax.returncode == 0, unsigned_syntax.stderr

        unsigned_command = [
            sys.executable,
            str(ROOT / "tools" / "diff_decompile.py"),
            str(binary),
            str(SOURCE),
            "--function",
            "classify_unsigned",
            "--json",
        ]
        if binary == stripped:
            unsigned_command.extend(
                ["--reference-so", str(debug), "--dwarf-so", str(debug)]
            )
        unsigned_differential = subprocess.run(
            unsigned_command,
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        unsigned_verdict = json.loads(unsigned_differential.stdout)["classify_unsigned"]
        assert unsigned_verdict["status"] == "pass", unsigned_verdict
        assert unsigned_verdict["detail"] == "31 cases", unsigned_verdict
