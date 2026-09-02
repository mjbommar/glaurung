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
#: A stripped image that links the archive the shipped library is built from.
#: Committed by `tests/fixtures/flirt/build.sh`; see that directory's README.
_STRIPPED_MATHLIB = Path("tests/fixtures/flirt/mathlib_link_a.stripped.x86_64.elf")


def test_library_builder_round_trips(tmp_path: Path) -> None:
    """Run the library builder against a single debug binary and verify
    the output JSON parses with the expected schema."""
    _need(_HELLO_DEBUG)
    output = tmp_path / "tiny.flirt.json"
    rc = subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.tools.build_flirt_library",
            str(_HELLO_DEBUG),
            "--output",
            str(output),
            "--arch",
            "x86_64",
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
    # Since 2026-09-02 the shipped library is built from unlinked objects and
    # carries masks and a provenance key. A file without them is a regression
    # to harvesting linked binaries, which cannot survive a relink.
    assert data["schema_version"] == "2"
    assert data["library"]["name"]
    assert data["library"]["variant"]
    assert any(e.get("mask_hex") for e in data["entries"])


def test_flirt_lifts_stripped_binary_naming() -> None:
    """The whole point of #158: a stripped binary with no symbol table
    recovers real function names from the shipped signature library.

    The target changed on 2026-09-02 and the reason is worth recording.
    This test used to run against ``hello-clang-stripped`` and pass because
    the shipped library held 30 exact prologues harvested from *that same
    sample tree*, including its CRT stubs. That is self-recall: the library
    could name those binaries and no others, because a prologue taken from a
    linked image records the link rather than the function.

    The library is now built from the unlinked objects in ``libmathlib.a``
    with relocation-derived masks, so it names ``mathlib_*`` in any binary
    that links that archive -- which is a capability rather than a
    coincidence -- and names nothing in ``hello-clang-stripped``, which does
    not link it. The fixture below is a stripped image that does.
    See ``docs/analysis/function-signature-libraries.md``.
    """
    binary = _need(_STRIPPED_MATHLIB)
    if not _DEFAULT_LIBRARY.exists():
        pytest.skip("baseline FLIRT library not present")
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    named = [f for f in funcs if not f.name.startswith("sub_")]
    assert len(named) >= 10, (
        f"FLIRT did not lift the stripped binary; named={[f.name for f in named]}"
    )
    from_library = [f for f in named if f.name.startswith("mathlib_")]
    assert len(from_library) >= 10, (
        "the names recovered did not come from the signature library: "
        f"{[f.name for f in named]}"
    )


def test_the_shipped_library_names_nothing_it_cannot_justify() -> None:
    """The counterpart to the test above, and the more important half.

    ``hello-clang-stripped`` does not link ``libmathlib.a``, so every name
    the shipped library could put on it would be wrong -- and would be
    written at ``set_by=flirt``, which outranks ``auto`` in the KB.
    """
    binary = _need(_HELLO_STRIPPED)
    if not _DEFAULT_LIBRARY.exists():
        pytest.skip("baseline FLIRT library not present")
    funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    wrong = [f.name for f in funcs if f.name.startswith("mathlib_")]
    assert not wrong, f"library names applied to an unrelated binary: {wrong}"


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
