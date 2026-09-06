"""Full-text equivalence contracts for public decompilation entry points."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import glaurung as g
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
sys.path.insert(0, str(ROOT / "tools"))

D = importlib.import_module("diff_decompile")
INCOMPLETE_MARKER = "GLAURUNG-INCOMPLETE"


@pytest.mark.parametrize(("style", "types"), [("decbench", True), ("c", False), ("", False)])
def test_discovered_exact_range_matches_every_whole_cfg_entry_point(
    style: str, types: bool
) -> None:
    """An exact known range must not discard CFG or indirect-callee facts."""
    binary = FIXTURES / "build" / "08_indirect_dispatch-gcc-O2.so"
    path = str(binary)
    va = D.exported_functions(path)["tail_dispatch"]
    common = {
        "style": style,
        "max_blocks": 4096,
        "max_instructions": 200_000,
        "timeout_ms": 5000,
    }
    equal_max_functions = 64

    by_address = g.ir.decompile_at(
        path, va, max_functions=equal_max_functions, types=types, **common
    )
    by_range = g.ir.decompile_range_at(
        path,
        va,
        va,
        va + 0x26,
        max_functions=equal_max_functions,
        types=types,
        **common,
    )
    [(_name, _va, by_batch, *_extra)] = g.ir.decompile_many(
        path, [va], max_functions=equal_max_functions, types=types, **common
    )
    by_all = next(
        row[2]
        for row in g.ir.decompile_all(
            path,
            limit=equal_max_functions,
            max_functions=equal_max_functions,
            **common,
        )
        if row[1] == va
    )

    assert by_address == by_range == by_batch == by_all


def test_lower_exact_range_budget_preserves_output_and_names_the_fired_limit() -> None:
    """Changing only the range CFG budget must make incompleteness explicit."""
    binary = FIXTURES / "build" / "08_indirect_dispatch-gcc-O2.so"
    path = str(binary)
    va = D.exported_functions(path)["tail_dispatch"]
    common = {
        "max_functions": 64,
        "max_instructions": 200_000,
        "timeout_ms": 5000,
        "types": True,
        "style": "decbench",
    }

    complete = g.ir.decompile_range_at(path, va, va, va + 0x26, max_blocks=4096, **common)
    limited = g.ir.decompile_range_at(path, va, va, va + 0x26, max_blocks=1, **common)

    assert limited != complete
    assert INCOMPLETE_MARKER not in complete
    assert INCOMPLETE_MARKER in limited
    assert "tail_dispatch" in complete and "tail_dispatch" in limited

    header = "\n".join(line for line in limited.splitlines() if line.startswith("//"))
    assert "max_blocks=1" in header
    assert "max_instructions=" not in header
    assert "timeout_ms=" not in header
