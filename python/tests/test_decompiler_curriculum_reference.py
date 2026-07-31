"""The curriculum sources implement their advertised textbook algorithms."""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS = ROOT / "tools"
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
sys.path.insert(0, str(TOOLS))

TC = importlib.import_module("fixture_toolchain")


def test_curriculum_textbook_examples_execute_correctly(tmp_path: Path) -> None:
    executable = tmp_path / "curriculum-oracle"
    built = TC.run(
        [
            "gcc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            str(executable),
            str(FIXTURES / "curriculum_oracle.c"),
        ]
    )
    assert built.returncode == 0, built.stderr

    executed = subprocess.run(
        [str(executable)], capture_output=True, text=True, timeout=10, check=False
    )
    assert executed.returncode == 0, executed.stderr
