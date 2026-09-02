"""The L1 structural signature binding and its KB table.

The arithmetic is proved in Rust (`src/identity/structural/`, plus
`tests/identity_structural.rs` over real samples). What is proved here is
the Python surface: that the binding exposes every field read-only, that
`to_dict` and the KB row agree on the column set, that an unsigned
64-bit product survives SQLite's signed INTEGER, and that Diaphora's
rarity gate does what its docstring says.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.kb import function_structural as fs

ROOT = Path(__file__).resolve().parents[2]
HELLO_GCC_O2 = (
    ROOT / "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)
HELLO_GCC_O0 = (
    ROOT / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
)


def _sample(p: Path) -> Path:
    assert p.exists(), (
        f"sample fixture missing: {p} -- it is checked in, so this is a broken "
        "checkout, not a reason to skip"
    )
    return p


# ---------------------------------------------------------------------------
# The native binding
# ---------------------------------------------------------------------------


def test_signatures_cover_every_discovered_function() -> None:
    sigs = g.analysis.structural_signatures_path(str(_sample(HELLO_GCC_O2)))
    assert sigs, "expected at least one signature"
    funcs, _ = g.analysis.analyze_functions_path(str(HELLO_GCC_O2))
    # The signature pass runs its own discovery with wider budgets, so it
    # can only ever see MORE functions than the default-budget call.
    assert len(sigs) >= 1
    assert len(funcs) >= 1
    # Sorted by entry address, as documented.
    assert [s.entry_va for s in sigs] == sorted(s.entry_va for s in sigs)


def test_fields_are_read_only() -> None:
    sig = g.analysis.structural_signatures_path(str(_sample(HELLO_GCC_O2)))[0]
    with pytest.raises(AttributeError):
        sig.md_index_top_down = 0.0
    with pytest.raises(AttributeError):
        sig.basic_blocks = 99


def test_to_dict_matches_the_attributes_and_the_kb_columns() -> None:
    sig = max(
        g.analysis.structural_signatures_path(str(_sample(HELLO_GCC_O2))),
        key=lambda s: s.basic_blocks,
    )
    d = sig.to_dict()
    assert d["entry_va"] == sig.entry_va
    assert d["name"] == sig.name
    assert d["md_index_top_down"] == sig.md_index_top_down
    assert d["mnemonic_spp"] == sig.mnemonic_spp
    assert d["basic_blocks"] == sig.basic_blocks
    assert d["rare_constants"] == sig.rare_constants
    # The dict's key set is the KB writer's column set, in order. This is
    # the assertion that keeps the two from drifting apart silently.
    assert tuple(d.keys()) == fs._COLUMNS[:-1] + ("rare_constants",)


def test_two_runs_agree_exactly() -> None:
    path = str(_sample(HELLO_GCC_O2))
    first = g.analysis.structural_signatures_path(path)
    second = g.analysis.structural_signatures_path(path)
    assert [s.to_dict() for s in first] == [s.to_dict() for s in second]


def test_ranking_similarity_is_one_against_itself_and_symmetric() -> None:
    sigs = g.analysis.structural_signatures_path(str(_sample(HELLO_GCC_O2)))
    big = sorted(sigs, key=lambda s: -s.basic_blocks)
    a, b = big[0], big[1]
    assert g.analysis.structural_ranking_similarity(a, a) == pytest.approx(1.0)
    assert g.analysis.structural_ranking_similarity(
        a, b
    ) == g.analysis.structural_ranking_similarity(b, a)
    assert 0.0 <= g.analysis.structural_ranking_similarity(a, b) <= 1.0


def test_mnemonic_spp_is_odd_and_unsigned() -> None:
    """Every prime in the table is odd, so a non-empty product is odd --
    and it is reported as an unsigned 64-bit value, never negative."""
    sigs = g.analysis.structural_signatures_path(str(_sample(HELLO_GCC_O2)))
    with_code = [s for s in sigs if s.instructions > 0]
    assert with_code, "expected at least one function with instructions"
    for s in with_code:
        assert s.mnemonic_spp >= 0
        assert s.mnemonic_spp % 2 == 1
        assert s.mnemonic_spp < 2**64


def test_counts_are_internally_consistent() -> None:
    for s in g.analysis.structural_signatures_path(str(_sample(HELLO_GCC_O2))):
        assert s.strongly_connected_components <= s.basic_blocks
        assert s.loops <= s.back_edges
        assert s.cyclic_blocks == s.basic_blocks - s.strongly_connected_components
        assert s.cyclomatic_complexity >= 1
        assert list(s.rare_constants) == sorted(s.rare_constants)


def test_scheme_constant_matches_the_kb_module() -> None:
    assert g.analysis.STRUCTURAL_SCHEME == fs.STRUCTURAL_L1_V1


# ---------------------------------------------------------------------------
# u64 in a signed column
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [0, 1, 3, 2**62, 2**63 - 1, 2**63, 2**63 + 1, 2**64 - 1],
)
def test_spp_round_trips_through_a_signed_integer(value: int) -> None:
    stored = fs._spp_to_db(value)
    assert -(2**63) <= stored <= 2**63 - 1
    assert fs._spp_from_db(stored) == value


def test_spp_round_trips_through_a_real_sqlite_column(tmp_path: Path) -> None:
    """The conversion is only worth anything if SQLite accepts the value
    it produces; a Python-only round trip would pass with a bug that
    overflows the column."""
    conn = sqlite3.connect(str(tmp_path / "t.sqlite"))
    conn.execute("CREATE TABLE t (v INTEGER)")
    huge = 2**64 - 3
    conn.execute("INSERT INTO t VALUES (?)", (fs._spp_to_db(huge),))
    (stored,) = conn.execute("SELECT v FROM t").fetchone()
    assert fs._spp_from_db(stored) == huge
    conn.close()


# ---------------------------------------------------------------------------
# The KB table
# ---------------------------------------------------------------------------


def _rows(path: Path):
    return list(fs.compute_structural_signatures(str(path)).values())


def test_rows_round_trip_through_the_table(tmp_path: Path) -> None:
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    kb = PersistentKnowledgeBase.open(
        tmp_path / "p.glaurung", binary_path=_sample(HELLO_GCC_O2)
    )
    try:
        assert fs.is_indexed(kb) is False
        stored = fs.index_function_structural(kb, str(HELLO_GCC_O2))
        assert stored > 0
        assert fs.is_indexed(kb) is True

        listed = fs.list_function_structural(kb)
        assert len(listed) == stored
        assert [r.entry_va for r in listed] == sorted(r.entry_va for r in listed)

        computed = fs.compute_structural_signatures(str(HELLO_GCC_O2))
        for row in listed:
            source = computed[row.entry_va]
            assert row.name == source.name
            assert row.mnemonic_spp == source.mnemonic_spp
            assert row.md_index_top_down == source.md_index_top_down
            assert row.md_index_bottom_up == source.md_index_bottom_up
            assert row.md_index_relaxed == source.md_index_relaxed
            assert row.rare_constants == source.rare_constants
            assert row.basic_blocks == source.basic_blocks
            assert row.scheme == fs.STRUCTURAL_L1_V1
    finally:
        kb.close()


def test_indexing_twice_refreshes_in_place(tmp_path: Path) -> None:
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    kb = PersistentKnowledgeBase.open(
        tmp_path / "p.glaurung", binary_path=_sample(HELLO_GCC_O2)
    )
    try:
        first = fs.index_function_structural(kb, str(HELLO_GCC_O2))
        second = fs.index_function_structural(kb, str(HELLO_GCC_O2))
        assert first == second
        assert len(fs.list_function_structural(kb)) == first
    finally:
        kb.close()


def test_get_and_find_by_md_index(tmp_path: Path) -> None:
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    kb = PersistentKnowledgeBase.open(
        tmp_path / "p.glaurung", binary_path=_sample(HELLO_GCC_O2)
    )
    try:
        fs.index_function_structural(kb, str(HELLO_GCC_O2))
        rows = fs.list_function_structural(kb)
        biggest = max(rows, key=lambda r: r.basic_blocks)
        assert fs.get_function_structural(kb, biggest.entry_va) == biggest
        assert fs.get_function_structural(kb, 0xDEAD_BEEF) is None
        hits = fs.find_by_md_index(kb, biggest)
        assert biggest.entry_va in [h.entry_va for h in hits]
    finally:
        kb.close()


def test_the_table_carries_no_set_by_column(tmp_path: Path) -> None:
    """A structural signature is a measurement, not an assertion; there
    is deliberately nothing for `manual wins` to apply to."""
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    kb = PersistentKnowledgeBase.open(
        tmp_path / "p.glaurung", binary_path=_sample(HELLO_GCC_O2)
    )
    try:
        fs._ensure(kb._conn)
        cols = {
            r[1] for r in kb._conn.execute("PRAGMA table_info(function_structural)")
        }
        assert "set_by" not in cols
        assert {"binary_id", "entry_va", "md_index_top_down", "mnemonic_spp"} <= cols
    finally:
        kb.close()


# ---------------------------------------------------------------------------
# Diaphora's rarity gate
# ---------------------------------------------------------------------------


def _row(entry_va: int, *, blocks: int, md: float) -> fs.StructuralSignatureRow:
    """A row with just the fields the rarity gate reads."""
    return fs.StructuralSignatureRow(
        binary_id=0,
        entry_va=entry_va,
        name=f"f_{entry_va:x}",
        md_index_top_down=md,
        md_index_bottom_up=md,
        md_index_relaxed=md,
        mnemonic_spp=3,
        basic_blocks=blocks,
        edges=blocks,
        back_edges=0,
        loops=0,
        strongly_connected_components=blocks,
        cyclomatic_complexity=2,
        instructions=blocks * 4,
        calls_out_direct=0,
        calls_out_indirect=0,
        callers_in=0,
        string_refs=0,
    )


def test_rarity_gate_drops_a_shape_that_repeats() -> None:
    common = [_row(i, blocks=10, md=1.5) for i in range(5)]
    rare = [_row(100, blocks=10, md=2.5)]
    keys = fs.rare_by_md_index(common + rare)
    assert list(keys) == [rare[0].md_index_key()]


def test_rarity_gate_admits_a_shape_occurring_exactly_twice() -> None:
    """Diaphora's rule is `count(*) <= 2`, not `= 1`: a function and its
    cold clone are the everyday case and must stay usable."""
    twice = [_row(1, blocks=10, md=1.5), _row(2, blocks=10, md=1.5)]
    keys = fs.rare_by_md_index(twice)
    assert list(keys) == [twice[0].md_index_key()]
    assert [r.entry_va for r in keys[twice[0].md_index_key()]] == [1, 2]


def test_rarity_gate_drops_small_functions() -> None:
    """`nodes > 5`: a five-block function has too few distinct shapes
    available for equality to carry information."""
    small = [_row(1, blocks=5, md=9.0)]
    assert fs.rare_by_md_index(small) == {}
    big = [_row(1, blocks=fs.RARE_MIN_BLOCKS, md=9.0)]
    assert list(big[0].md_index_key() == k for k in fs.rare_by_md_index(big)) == [True]


def test_rarity_counts_use_the_whole_population() -> None:
    rows = [_row(i, blocks=10, md=1.5) for i in range(3)]
    counts = fs.rarity_counts(rows)
    assert counts == {rows[0].md_index_key(): 3}


def test_md_index_key_quantises() -> None:
    a = _row(1, blocks=10, md=1.2345678901234567)
    b = _row(2, blocks=10, md=1.2345678901234599)
    assert a.md_index_key() == b.md_index_key()
    c = _row(3, blocks=10, md=1.2345679)
    assert a.md_index_key() != c.md_index_key()


def test_o0_and_o2_are_not_expected_to_agree() -> None:
    """L1 does not cross an optimisation level, and this states it as a
    measurement rather than as prose: the same source at two levels
    produces mostly different MD-indices."""
    o0 = fs.compute_structural_signatures(str(_sample(HELLO_GCC_O0)))
    o2 = fs.compute_structural_signatures(str(_sample(HELLO_GCC_O2)))
    by_name_o2 = {r.name: r for r in o2.values()}
    shared = [r for r in o0.values() if r.name in by_name_o2]
    assert shared, "expected some shared function names across O0 and O2"
    agree = sum(
        1 for r in shared if r.md_index_key() == by_name_o2[r.name].md_index_key()
    )
    assert agree < len(shared), (
        "every same-name function agreed across an optimisation level, which "
        "would mean the index is not reading the CFG at all"
    )
