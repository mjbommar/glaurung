from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g


NTOSKRNL = Path("tests/fixtures/msvc-pdb/ntoskrnl.exe")


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
