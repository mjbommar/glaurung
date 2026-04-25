"""Tests for FLIRT-style signature matching (#158)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import glaurung as g


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
_HELLO_STRIPPED = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-stripped"
)
_DEFAULT_LIBRARY = Path("data/sigs/glaurung-base.x86_64.flirt.json")


def test_library_builder_round_trips(tmp_path: Path) -> None:
    """Run the library builder against a single debug binary and verify
    the output JSON parses with the expected schema."""
    _need(_HELLO_DEBUG)
    output = tmp_path / "tiny.flirt.json"
    rc = subprocess.run(
        [
            sys.executable, "-m", "glaurung.tools.build_flirt_library",
            str(_HELLO_DEBUG),
            "--output", str(output),
            "--arch", "x86_64",
            "--quiet",
        ],
        check=False,
    ).returncode
    assert rc == 0
    data = json.loads(output.read_text())
    assert data["schema_version"] == "1"
    assert data["arch"] == "x86_64"
    assert data["prologue_len"] == 32
    assert isinstance(data["entries"], list)
    assert data["entries"], "expected at least one signature"
    # Index uses 4-byte hex prefixes.
    for prefix in data["index"]:
        assert len(prefix) == 8


def test_default_library_exists() -> None:
    """The repo ships a baseline x86_64 library so the matcher activates
    out-of-the-box."""
    if not _DEFAULT_LIBRARY.exists():
        pytest.skip(f"baseline library {_DEFAULT_LIBRARY} not committed")
    data = json.loads(_DEFAULT_LIBRARY.read_text())
    assert data["arch"] == "x86_64"
    assert data["entries"], "baseline library must not be empty"


def test_flirt_lifts_stripped_binary_naming() -> None:
    """The whole point of #158: a stripped binary that previously had 0
    named functions (besides the entrypoint) recovers multiple real
    function names via FLIRT prologue matching against the baseline
    library."""
    binary = _need(_HELLO_STRIPPED)
    if not _DEFAULT_LIBRARY.exists():
        pytest.skip("baseline FLIRT library not present")
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    named = [f for f in funcs if not f.name.startswith("sub_")]
    # Conservative bar: at least 2 named (entrypoint + 1 FLIRT match).
    # The baseline library covers the standard CRT prologues.
    assert len(named) >= 2, (
        f"FLIRT did not lift the stripped binary; named={[f.name for f in named]}"
    )
    # _start is the trivially-discoverable entrypoint; require at least
    # one FLIRT-only match BEYOND it.
    flirt_only = [f for f in named if f.name != "_start"]
    assert flirt_only, (
        "no FLIRT-only matches surfaced — only the entrypoint got named"
    )


def test_flirt_does_not_overwrite_dwarf_names() -> None:
    """When DWARF gives a function its real name, the FLIRT pass must
    not later overwrite it (FLIRT only renames placeholder `sub_*`)."""
    binary = _need(_HELLO_DEBUG)
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    assert main is not None
    # main's name must come from DWARF / symbol table, not FLIRT — and it
    # must still be just "main", not some libc-prologue-collision name.
    assert main.name == "main"
