"""Round-trip coverage for vector-width memory effects."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import fixture_harness as H  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow


def test_vectorized_mem_copy_round_trips_clang_o2() -> None:
    """Each 16-byte machine load/store must copy all 16 bytes in emitted C."""
    observed = H.run_lanes(
        [("09_memory_effects", "clang", "O2", ("mem_copy",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["09_memory_effects:clang:O2"]
    assert lane == {"mem_copy": "pass"}, lane

    binary = H.BUILD / "09_memory_effects-clang-O2.so"
    function = D.exported_functions(str(binary))["mem_copy"]
    code = D.decompiled_c(str(binary), function)
    assert code is not None
    assert "__builtin_memmove(" in code, code
