"""Regression tests for Windows UTF-16 string extraction."""

from __future__ import annotations

import pathlib
from pathlib import Path

import pytest

import glaurung as g

# Anchored from this file, not from the working directory. Every reference to
# these fixtures used to be `Path("tests/fixtures/msvc-pdb/...")`, which only
# resolves when pytest happens to be run from the repository root -- from
# anywhere else the skipif silently reported the fixture missing and the test
# never ran. That is the same defect that left three test files permanently
# dead until 95249c54; this is the same shape, spread across twelve files.
_MSVC_PDB = (
    pathlib.Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "msvc-pdb"
)


_NTOSKRNL = _MSVC_PDB / "ntoskrnl.exe"


def test_real_pe_utf16_strings_reach_python_triage() -> None:
    if not _NTOSKRNL.exists():
        pytest.skip(f"missing {_NTOSKRNL}")

    art = g.triage.analyze_path(
        str(_NTOSKRNL),
        max_read_bytes=104_857_600,
        max_file_size=104_857_600,
        max_depth=1,
        str_min_len=8,
        str_max_samples=100_000,
        str_lang=False,
        str_max_lang_detect=0,
        str_classify=False,
        str_max_classify=0,
        str_max_ioc_per_string=0,
    )

    assert art.strings is not None
    assert art.strings.utf16le_count > 0

    rows = [
        (str(s.text), str(s.encoding), int(s.offset))
        for s in art.strings.strings or []
        if s.offset is not None
    ]
    assert ("HARDWARE", "utf16le", 129328) in rows
    assert ("0123456789abcdef", "utf16le", 288936) in rows
