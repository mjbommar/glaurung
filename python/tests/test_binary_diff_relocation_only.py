"""`glaurung diff` exposes a `relocation_only` verdict on changed rows.

Pure relocations already collapse to status `same` (structural_fingerprint
masks call/branch/global targets); what still reaches `changed` with
similarity ~1.0 is relocation / block-reordering noise, which this flag
names so consumers can drop it instead of re-deriving the judgment.
"""
from __future__ import annotations

from dataclasses import asdict

from glaurung.llm.kb.binary_diff import (
    FunctionDiff, FunctionFingerprint, is_relocation_only,
    RELOCATION_ONLY_SIMILARITY,
)


def test_is_relocation_only_predicate():
    assert is_relocation_only("changed", 1.0) is True
    assert is_relocation_only("changed", RELOCATION_ONLY_SIMILARITY) is True
    assert is_relocation_only("changed", 0.95) is False   # a real edit stays
    assert is_relocation_only("changed", None) is False    # one-sided / no fp
    assert is_relocation_only("same", 1.0) is False        # only "changed" rows
    assert is_relocation_only("added", 1.0) is False


def test_function_diff_field_defaults_and_serializes():
    fp = FunctionFingerprint(name="f", entry_va=0x1000, size=64,
                             body_hash="bh", structural_hash="sh")
    row = FunctionDiff(name="f", status="changed", a=fp, b=fp,
                       similarity=1.0,
                       relocation_only=is_relocation_only("changed", 1.0))
    d = asdict(row)
    assert d["relocation_only"] is True
    assert d["similarity"] == 1.0
    # default is False (e.g. genuine changes, same/added/removed rows)
    assert FunctionDiff(name="g", status="changed").relocation_only is False
