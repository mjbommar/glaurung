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


@pytest.mark.slow
@pytest.mark.parametrize(
    ("selector", "expected_mode", "expected_value"),
    [
        ("{0x10F9}", "--vas", "0x10f9"),
        ("{'addmul'}", "--all", "2000"),
    ],
)
def test_adapter_passes_requested_selectors_to_the_shared_batch_pipeline(
    tmp_path: Path,
    selector: str,
    expected_mode: str,
    expected_value: str,
) -> None:
    """Address and source-name selectors must both reach the shared batch path."""
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

    argv_log = tmp_path / "argv.json"
    wrapper = tmp_path / "glaurung-wrapper"
    wrapper.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['GLAURUNG_ARGV_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
        "real = os.environ['GLAURUNG_REAL_BIN']\n"
        "os.execv(real, [real, *sys.argv[1:]])\n"
    )
    wrapper.chmod(0o755)
    script = f"""
import json
import sys
from pathlib import Path
sys.path.insert(0, {str(ADAPTER.parent)!r})
from decbench_glaurung import GlaurungDecompiler
result = GlaurungDecompiler().decompile_binary(
    Path({str(binary)!r}), function_names={selector}
)
print(json.dumps(sorted(result.functions)))
"""
    probe = subprocess.run(
        [python, "-c", script],
        cwd=checkout,
        env={
            **os.environ,
            "GLAURUNG_BIN": str(wrapper),
            "GLAURUNG_REAL_BIN": str(glaurung),
            "GLAURUNG_ARGV_LOG": str(argv_log),
            "NO_COLOR": "1",
        },
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr
    assert json.loads(probe.stdout) == ["addmul"]
    argv = json.loads(argv_log.read_text())
    assert expected_mode in argv
    assert expected_value in argv
    assert ({"--vas", "--all"} - {expected_mode}).isdisjoint(argv)
