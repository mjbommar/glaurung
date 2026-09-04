"""Real-fixture contracts for the structure-v2 corpus comparison."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import structure_v2_compare as S  # ty: ignore[unresolved-import]  # added above


def test_mixed_real_batch_counts_verified_output_and_local_decline() -> None:
    """A refused loop must not erase a verified sibling from measurement."""
    binary = BUILD / "03_loop_shapes-gcc-O0.so"
    if not binary.is_file():
        pytest.skip("real decompiler fixture matrix is absent")
    exports = D.exported_functions(str(binary))
    rows = [
        {"obj": binary.name, "fn": "for_sum", "va": exports["for_sum"]},
        {
            "obj": binary.name,
            "fn": "dowhile_recompute",
            "va": exports["dowhile_recompute"],
        },
    ]

    result = S.compare_object(binary.name, rows)

    by_name = {function["fn"]: function for function in result["functions"]}
    assert by_name["for_sum"]["shadow_gotos"] is not None
    assert by_name["dowhile_recompute"]["status"] == "shadow_declined"
    assert by_name["dowhile_recompute"]["shadow_gotos"] is None
