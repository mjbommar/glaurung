#!/usr/bin/env python3
"""Where the external decompilers live, and how to override that.

Every path here is a *local* fact — which Ghidra release is unpacked, which venv
has angr — so none of it is hard-coded. Each has an environment override and a
default that matches this workstation, and `check()` reports what is missing
rather than failing halfway through a benchmark run.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# Python interpreter that can `import angr` and `import pyghidra`. The DecBench
# checkout's venv has both; any venv with them works.
DECBENCH_PY = _env(
    "EXTBENCH_PYTHON", "/nas4/data/workspace-infosec/decbench/.venv/bin/python"
)
# The glaurung CLI under test. Defaults to this checkout's venv so the harness
# measures the tree it ships with, not whatever is on PATH.
GLAURUNG_BIN = _env("EXTBENCH_GLAURUNG", str(REPO / ".venv/bin/glaurung"))
GHIDRA_DIR = _env(
    "EXTBENCH_GHIDRA", str(Path.home() / ".cache/ghidra-releases/ghidra_12.1.2_PUBLIC")
)
RETDEC_BIN = _env(
    "EXTBENCH_RETDEC", str(Path.home() / ".local/opt/retdec/bin/retdec-decompiler")
)

# Where the sample binaries come from.
SAMPLES = _env("EXTBENCH_SAMPLES", "/nas4/data/binary-analysis/glaurung/binaries-small")

ALL_TOOLS = ("glaurung", "ghidra", "angr", "retdec")


def available() -> dict[str, bool]:
    """Which tools can actually run right now."""
    ok = {}
    ok["glaurung"] = Path(GLAURUNG_BIN).exists()
    ok["ghidra"] = Path(GHIDRA_DIR).is_dir() and Path(DECBENCH_PY).exists()
    ok["angr"] = Path(DECBENCH_PY).exists()
    ok["retdec"] = Path(RETDEC_BIN).exists() or bool(shutil.which("retdec-decompiler"))
    return ok


def check(required: tuple[str, ...] = ALL_TOOLS) -> list[str]:
    """Return human-readable notes for every required tool that is missing.

    A comparison silently missing a comparator is the failure mode this whole
    harness exists to avoid, so absence is reported up front rather than showing
    up later as an empty column.
    """
    have = available()
    notes = []
    for tool in required:
        if have.get(tool):
            continue
        hint = {
            "glaurung": f"build it: `maturin develop --release` (looked in {GLAURUNG_BIN})",
            "ghidra": f"set EXTBENCH_GHIDRA (looked in {GHIDRA_DIR})",
            "angr": f"set EXTBENCH_PYTHON to a venv with angr (looked at {DECBENCH_PY})",
            "retdec": f"set EXTBENCH_RETDEC (looked at {RETDEC_BIN})",
        }[tool]
        notes.append(f"{tool}: unavailable — {hint}")
    return notes


if __name__ == "__main__":
    for tool, ok in available().items():
        print(f"{tool:9s} {'ok' if ok else 'MISSING'}")
    for note in check():
        print(f"  {note}")
