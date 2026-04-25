"""Tests for auto-struct recovery (#163 v1)."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import type_db, xref_db
from glaurung.llm.kb.persistent import PersistentKnowledgeBase


_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_parse_reg_offset_handles_canonical_forms() -> None:
    cases = [
        ("[rdi + 0x10]", ("rdi", 0x10)),
        ("[rdi+0x18]", ("rdi", 0x18)),
        ("rax:[rax + 0x8]", ("rax", 0x8)),
        ("[rsi - 0x4]", ("rsi", -0x4)),
        ("[rdi]", ("rdi", 0)),
        # SIB-with-index → reject (it's an array, not a struct).
        ("[rax + rcx*8]", None),
        ("rax", None),  # not a memory operand
    ]
    for op, expected in cases:
        got = type_db._parse_reg_offset(op)
        assert got == expected, f"{op!r} → {got!r}, want {expected!r}"


def test_size_to_c_type_round_trips() -> None:
    assert type_db._size_to_c_type(1) == "char"
    assert type_db._size_to_c_type(2) == "short"
    assert type_db._size_to_c_type(4) == "int"
    assert type_db._size_to_c_type(8) == "void *"
    # Unknown sizes fall back to pointer-width.
    assert type_db._size_to_c_type(16) == "void *"


def test_discover_emits_struct_candidates_on_cpp_binary(tmp_path: Path) -> None:
    """C++ methods access `this->member` through rdi — every method
    in hello-clang-debug should produce a struct candidate."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "auto.glaurung"
    kb = PersistentKnowledgeBase.open(
        db, binary_path=binary, auto_load_stdlib=True,
    )
    xref_db.index_callgraph(kb, str(binary))

    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    total = 0
    for f in funcs:
        if not f.basic_blocks:
            continue
        total += type_db.discover_struct_candidates(
            kb, str(binary), int(f.entry_point.value),
        )
    assert total >= 3, (
        f"expected ≥3 struct candidates from C++ method bodies; got {total}"
    )

    autos = [t for t in type_db.list_types(kb, kind="struct") if t.set_by == "auto"]
    assert autos
    # Each auto candidate should have ≥2 fields with sequential offsets.
    sample = autos[0]
    assert len(sample.body["fields"]) >= 2
    offsets = [f["offset"] for f in sample.body["fields"]]
    assert offsets == sorted(offsets), "fields should be sorted by offset"
    # Total size matches max(offset + size).
    total_size = sample.body["total_size"]
    expected = max(f["offset"] + f["size"] for f in sample.body["fields"])
    assert total_size == expected
    kb.close()


def test_min_field_count_filter(tmp_path: Path) -> None:
    """A function whose `this` access pattern is `arg0->fld_0` only
    (single field) shouldn't generate a struct candidate."""
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "auto.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    main = next((f for f in funcs if f.name == "main"), None)
    if main is None:
        pytest.skip("main not discovered")

    # Restrict to >= 100 fields → impossible bar, should always be 0.
    n = type_db.discover_struct_candidates(
        kb, str(binary), int(main.entry_point.value),
        min_field_count=100,
    )
    assert n == 0
    kb.close()


def test_manual_structs_survive_auto_overwrite(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "auto.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    xref_db.index_callgraph(kb, str(binary))

    # Pre-name a struct that the auto pass would otherwise create.
    funcs, _ = g.analysis.analyze_functions_path(str(binary))
    f = next((f for f in funcs if not f.name.startswith("sub_") and f.basic_blocks), None)
    if f is None:
        pytest.skip("no named function with blocks")

    # Run once to discover the auto name.
    type_db.discover_struct_candidates(
        kb, str(binary), int(f.entry_point.value),
    )
    autos_before = [t for t in type_db.list_types(kb, kind="struct") if t.set_by == "auto"]
    if not autos_before:
        pytest.skip("auto-discovery produced no candidates for this function")
    target = autos_before[0]

    # Analyst overrides.
    type_db.add_struct(
        kb, target.name,
        [type_db.StructField(0, "manual_field", "void *", 8)],
        set_by="manual",
    )
    # Re-run auto-discovery — manual entry must win.
    type_db.discover_struct_candidates(
        kb, str(binary), int(f.entry_point.value),
    )
    after = type_db.get_type(kb, target.name)
    assert after is not None
    assert after.set_by == "manual"
    assert after.body["fields"][0]["name"] == "manual_field"
    kb.close()
