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


NTOSKRNL = _MSVC_PDB / "ntoskrnl.exe"


@pytest.mark.skipif(not NTOSKRNL.exists(), reason="ntoskrnl fixture missing")
def test_large_pe_truncated_read_does_not_panic() -> None:
    funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(
        str(NTOSKRNL),
        10_485_760,
        104_857_600,
        32,
        2_048,
        20_000,
        2_000,
    )

    assert len(funcs) <= 32
    assert stats.get("truncated") is True
