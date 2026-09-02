"""Real-binary contracts for authoritative function declarations.

The debug build already contains the source declaration for ``tail_dispatch``.
Recovery is useful evidence about the machine body, but it must not replace the
stronger declaration with wider or unsigned guesses. Parameter names are part
of that declaration, not cosmetic post-processing.
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import glaurung as g

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(ROOT / "tools"))

D = importlib.import_module("diff_decompile")


def _signature(body: str) -> str:
    match = re.search(r"^.*\btail_dispatch\([^)]*\)", body, re.MULTILINE)
    assert match, body
    return match.group(0)


def test_tail_dispatch_renders_its_authoritative_dwarf_declaration() -> None:
    """DWARF's exact source declaration must beat inferred machine types."""
    binary = FIXTURES / "build" / "08_indirect_dispatch-gcc-O2.so"
    exports = D.exported_functions(str(binary))

    g.ir.take_render_verification()
    [(_name, _va, body, *_extra)] = g.ir.decompile_many(
        str(binary), [exports["tail_dispatch"]], style="decbench"
    )

    assert _signature(body) == "int tail_dispatch(int tag, int a, int b)", body

    report = g.ir.take_render_verification()
    assert report["prototype_conflict_count"] == 1, report
    [conflict] = report["prototype_conflicts"]
    assert conflict["function"] == "tail_dispatch"
    assert conflict["authoritative_source"] == "dwarf"
    assert conflict["authoritative"]["return_type"] == "int"
    assert conflict["authoritative"]["parameter_types"] == ["int", "int", "int"]
    # Machine prototype recovery already proves the narrow return; the former
    # `long` was a renderer fallback, not a second prototype fact.
    assert conflict["candidate_source"] == "inferred"
    assert conflict["candidate"]["return_type"] == "int"
    assert conflict["candidate"]["parameter_types"] == [
        "unsigned int",
        "unsigned int",
        "int",
    ]
    assert conflict["disagreements"] == ["parameter_types"]

    # Draining metadata cannot perturb deterministic scored text.
    [(_name, _va, repeated, *_extra)] = g.ir.decompile_many(
        str(binary), [exports["tail_dispatch"]], style="decbench"
    )
    assert repeated == body


def test_all_four_entry_points_apply_the_same_declaration() -> None:
    """Address, range, batch, and whole-image paths share declaration authority."""
    binary = FIXTURES / "build" / "08_indirect_dispatch-gcc-O2.so"
    path = str(binary)
    va = D.exported_functions(path)["tail_dispatch"]

    by_address = g.ir.decompile_at(path, va, style="decbench")
    by_range = g.ir.decompile_range_at(path, va, va, va + 0x26, style="decbench")
    [(_name, _va, by_batch, *_extra)] = g.ir.decompile_many(
        path, [va], style="decbench"
    )
    [by_all] = [
        row[2]
        for row in g.ir.decompile_all(path, style="decbench")
        if row[0] == "tail_dispatch"
    ]

    expected = "int tail_dispatch(int tag, int a, int b)"
    assert {_signature(body) for body in (by_address, by_range, by_batch, by_all)} == {
        expected
    }


def test_analyst_prototype_outranks_dwarf_and_keeps_its_variadic_tail() -> None:
    binary = FIXTURES / "build" / "08_indirect_dispatch-gcc-O2.so"
    path = str(binary)
    va = D.exported_functions(path)["tail_dispatch"]

    g.ir.take_render_verification()
    body = g.ir.decompile_at(
        path,
        va,
        style="decbench",
        analyst_prototype=(
            "unsigned long",
            ["short", "short", "short"],
            True,
            ["selector", "left", "right"],
        ),
    )

    assert _signature(body) == (
        "unsigned long tail_dispatch(short selector, short left, short right, ...)"
    )
    assert "arg0" not in body
    assert "arg1" not in body
    assert "arg2" not in body

    report = g.ir.take_render_verification()
    assert report["prototype_conflict_count"] == 2, report
    assert [item["candidate_source"] for item in report["prototype_conflicts"]] == [
        "dwarf",
        "inferred",
    ]
    assert all(
        item["authoritative_source"] == "analyst"
        for item in report["prototype_conflicts"]
    )


def test_legacy_three_part_analyst_prototype_remains_supported() -> None:
    """The names extension must not break callers of the shipped tuple API."""
    binary = FIXTURES / "build" / "08_indirect_dispatch-gcc-O2.so"
    path = str(binary)
    va = D.exported_functions(path)["tail_dispatch"]

    body = g.ir.decompile_at(
        path,
        va,
        style="decbench",
        analyst_prototype=("unsigned long", ["short", "short", "short"], True),
    )

    assert _signature(body) == (
        "unsigned long tail_dispatch(short arg0, short arg1, short arg2, ...)"
    )
