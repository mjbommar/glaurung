"""Round-trip coverage for signed double-width division setup."""

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


def test_clang_signed_remainder_loop_condition_round_trips() -> None:
    """CDQ/IDIV must retain negative C remainder semantics after SSA."""
    observed = H.run_lanes(
        [("03_loop_shapes", "clang", "O0", ("cond_reload_and_transform",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["03_loop_shapes:clang:O0"]
    assert lane == {"cond_reload_and_transform": "pass"}, lane
