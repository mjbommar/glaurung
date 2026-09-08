"""Structured decompiler line mappings from AST instruction origins."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import glaurung as g

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures"
sys.path.insert(0, str(ROOT / "tools"))
D = importlib.import_module("diff_decompile")


def test_batch_line_mappings_are_opt_in_structured_and_deterministic() -> None:
    binary = FIXTURES / "build" / "01_conditional_polarity-gcc-O0.so"
    va = D.exported_functions(str(binary))["classify"]

    [legacy] = g.ir.decompile_many(str(binary), [va], style="decbench")
    [mapped] = g.ir.decompile_many(
        str(binary), [va], style="decbench", include_line_mappings=True
    )

    assert len(legacy) == 5
    assert len(mapped) == 6
    assert mapped[:5] == legacy
    lines = mapped[2].splitlines()
    line_mappings = mapped[5]
    assert line_mappings
    assert [row["line_number"] for row in line_mappings] == sorted(
        {row["line_number"] for row in line_mappings}
    )
    for row in line_mappings:
        assert set(row) == {"line_number", "addresses"}
        assert 1 <= row["line_number"] <= len(lines)
        assert row["addresses"] == sorted(set(row["addresses"]))
        assert row["addresses"]

    assert any(len(row["addresses"]) > 1 for row in line_mappings)
    address_owners: dict[int, int] = {}
    for row in line_mappings:
        for address in row["addresses"]:
            address_owners[address] = address_owners.get(address, 0) + 1
    assert any(owner_count > 1 for owner_count in address_owners.values())

    [repeated] = g.ir.decompile_many(
        str(binary), [va], style="decbench", include_line_mappings=True
    )
    assert repeated == mapped
