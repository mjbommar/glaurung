"""Executable regressions for optimized flag/predicate dataflow.

These are intentionally real round trips through the fixture compiler, Glaurung,
the generated-C compiler, and the differential runner.  Text shape alone cannot
distinguish a valid loop condition from a stale flag that happens to look plausible.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))

import fixture_harness as H
import manifest as M


pytestmark = pytest.mark.slow


def test_gcc_o2_loop_flags_round_trip() -> None:
    """Arithmetic-produced ZF and signed predicates must reach their branches."""
    functions = ("dec_loop", "shift_until_zero")
    observed = H.run_lanes(
        [("14_flag_effects", "gcc", "O2", functions)],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["14_flag_effects:gcc:O2"]
    assert lane == {name: "pass" for name in functions}, (
        f"optimized flag consumers did not preserve executable behavior: {lane}"
    )
