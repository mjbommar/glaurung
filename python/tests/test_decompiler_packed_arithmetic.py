"""Round-trip coverage for packed integer arithmetic lowered by compilers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))

import fixture_harness as H  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow


def test_clang_vectorized_byte_accumulator_round_trips() -> None:
    """PSLLD/PSUBD must preserve the vectorized seed-times-31 calculation."""
    observed = H.run_lanes(
        [("11_call_shapes", "clang", "O2", ("call_accumulate_bytes",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["11_call_shapes:clang:O2"]
    assert lane == {"call_accumulate_bytes": "pass"}, lane
