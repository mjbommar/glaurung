"""Real integration coverage for Glaurung's out-of-tree DecBench adapter."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
ADAPTER = ROOT / "tools" / "decbench_glaurung.py"
SOURCE = ROOT / "tests" / "decbench_corpus" / "src" / "arith.c"


def _decbench_checkout() -> Path:
    return Path(os.environ.get("DECBENCH_DIR", "/nas4/data/workspace-infosec/decbench"))


@pytest.mark.slow
def test_adapter_registers_and_decompiles_a_real_public_binary(tmp_path: Path) -> None:
    """The adapter must return source functions with exact ELF-space addresses."""
    checkout = _decbench_checkout()
    python = checkout / ".venv" / "bin" / "python"
    glaurung = ROOT / ".venv" / "bin" / "glaurung"
    if not python.is_file() or not glaurung.is_file():
        pytest.skip("local DecBench and Glaurung executables are required")

    binary = tmp_path / "arith.so"
    built = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-g", "-O0", "-w", "-o", binary, SOURCE],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert built.returncode == 0, built.stderr

    probe = subprocess.run(
        [python, ADAPTER, "--probe", binary],
        cwd=checkout,
        env={**os.environ, "GLAURUNG_BIN": str(glaurung), "NO_COLOR": "1"},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr
    payload = json.loads(probe.stdout)
    assert payload["decompiler"] == "glaurung"
    assert payload["functions"]["addmul"] == 0x10F9
    assert payload["functions"]["shifts"] == 0x1130
    assert payload["functions"]["signs"] == 0x114C
    assert not ({"_init", "_fini", "frame_dummy"} & payload["functions"].keys())
