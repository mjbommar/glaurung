"""Real-binary regression coverage for guarded call-valued selects."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def test_guarded_call_select_retains_both_value_edges(tmp_path: Path) -> None:
    """A lazy call-valued select must not lose its proven zero edge."""
    sys.path.insert(0, str(ROOT / "tools"))
    import fixture_toolchain as TC

    source = ROOT / "tests" / "fixtures" / "guarded_call_select.c"
    binary = tmp_path / "guarded-call-select-gcc-O2.so"
    compiled = TC.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O2", "-o", str(binary), str(source)],
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [
            "glaurung",
            "decompile",
            binary,
            "--func",
            "guarded_call_select",
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

    assert "if (" in result.stdout, result.stdout
    assert "} else {" in result.stdout, result.stdout
    assert re.search(r"else \{\s*\w+ = 0;", result.stdout), result.stdout
    assert "glaurung-verify" not in result.stdout, result.stdout
