"""The v4 structural pass in `binary_diff`: ranking and MD-index rematch.

Two things are under test. The **ranking**: every two-sided row carries a
`structural_delta`, and the changed table is ordered by it. The
**rematch**: residual added/removed rows are re-paired when their
control-flow shape is identical AND globally rare on both sides, which is
Diaphora's `HAVING count(*) <= 2` plus `nodes > 5`.

The rematch's gating is exercised with hand-built rows rather than a
binary, because the interesting cases -- a shape that repeats, a function
too small to gate on, two survivors sharing one key -- are the ones a
real fixture happens not to contain today and would stop containing
tomorrow.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaurung.llm.kb import function_structural as fs
from glaurung.llm.kb.binary_diff import (
    BinaryDiff,
    FunctionDiff,
    FunctionFingerprint,
    _rematch_by_rare_md_index,
    diff_binaries,
    render_diff_markdown,
    to_json,
)

ROOT = Path(__file__).resolve().parents[2]
SWITCHY_V1 = ROOT / "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
SWITCHY_V2 = (
    ROOT / "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


# ---------------------------------------------------------------------------
# Ranking over a real pair
# ---------------------------------------------------------------------------


def test_changed_rows_carry_a_structural_delta() -> None:
    diff = diff_binaries(str(_need(SWITCHY_V1)), str(_need(SWITCHY_V2)))
    assert diff.structural_rematch_ran is True
    changed = diff.changed_rows()
    assert changed, "v1 -> v2 should produce at least one changed function"
    measured = [r for r in changed if r.structural_delta is not None]
    assert measured, "no changed row got a structural delta"
    for r in measured:
        delta = r.structural_delta
        assert delta is not None
        assert 0.0 <= delta <= 1.0
        assert r.md_index_pre is not None
        assert r.md_index_post is not None


def test_changed_table_is_ranked_by_structural_delta() -> None:
    diff = diff_binaries(str(_need(SWITCHY_V1)), str(_need(SWITCHY_V2)))
    ranked = diff.changed_by_structural_delta()
    measured = [r.structural_delta for r in ranked if r.structural_delta is not None]
    assert measured == sorted(measured, reverse=True)
    # Unmeasured rows sort last, never interleaved.
    seen_unmeasured = False
    for r in ranked:
        if r.structural_delta is None:
            seen_unmeasured = True
        else:
            assert not seen_unmeasured, "a measured row sorted after an unmeasured one"


def test_self_diff_skips_the_structural_pass_entirely() -> None:
    """A self-diff has nothing changed, added or removed, so the pass is
    not worth a second discovery run and must not do one."""
    diff = diff_binaries(str(_need(SWITCHY_V1)), str(SWITCHY_V1))
    assert diff.changed == diff.added == diff.removed == 0
    assert diff.structural_rematch_ran is False
    assert diff.md_index_matched == 0


def test_the_pass_can_be_turned_off() -> None:
    diff = diff_binaries(
        str(_need(SWITCHY_V1)), str(_need(SWITCHY_V2)), structural_rematch=False
    )
    assert diff.structural_rematch_ran is False
    assert all(r.structural_delta is None for r in diff.rows)
    assert diff.md_index_matched == 0


def test_json_schema_4_exposes_the_structural_fields() -> None:
    diff = diff_binaries(str(_need(SWITCHY_V1)), str(_need(SWITCHY_V2)))
    parsed = json.loads(to_json(diff))
    assert parsed["schema_version"] == "4"
    assert parsed["md_index_matched"] == diff.md_index_matched
    assert parsed["structural_rematch_ran"] is True
    for row in parsed["rows"]:
        assert "structural_delta" in row
        assert "md_index_pre" in row
        assert "md_index_post" in row
        assert "md_index_matched" in row


def test_markdown_shows_the_delta_column() -> None:
    diff = diff_binaries(str(_need(SWITCHY_V1)), str(_need(SWITCHY_V2)))
    md = render_diff_markdown(diff)
    assert "Δstruct" in md
    assert "## Changed functions" in md


def test_cli_accepts_no_structural_rematch(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout

    from glaurung.cli.main import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(
            [
                "diff",
                str(_need(SWITCHY_V1)),
                str(SWITCHY_V1),
                "--no-structural-rematch",
            ]
        )
    assert rc == 0
    assert "Binary diff" in buf.getvalue()


# ---------------------------------------------------------------------------
# The rematch gate, on hand-built rows
# ---------------------------------------------------------------------------


def _row(
    entry_va: int, *, blocks: int, md: float, name: str = ""
) -> fs.StructuralSignatureRow:
    return fs.StructuralSignatureRow(
        binary_id=0,
        entry_va=entry_va,
        name=name or f"sub_{entry_va:x}",
        md_index_top_down=md,
        md_index_bottom_up=md + 0.5,
        md_index_relaxed=md + 1.0,
        mnemonic_spp=3,
        basic_blocks=blocks,
        edges=blocks + 1,
        back_edges=0,
        loops=0,
        strongly_connected_components=blocks,
        cyclomatic_complexity=3,
        instructions=blocks * 4,
        calls_out_direct=0,
        calls_out_indirect=0,
        callers_in=0,
        string_refs=0,
    )


def _fp(name: str, entry_va: int) -> FunctionFingerprint:
    return FunctionFingerprint(
        name=name, entry_va=entry_va, size=64, body_hash="ab" * 8, structural_hash=""
    )


def _diff_with(
    removed: list[tuple[str, int]], added: list[tuple[str, int]]
) -> BinaryDiff:
    d = BinaryDiff(binary_a="a", binary_b="b")
    for name, va in removed:
        d.rows.append(FunctionDiff(name=name, status="removed", a=_fp(name, va)))
        d.removed += 1
    for name, va in added:
        d.rows.append(FunctionDiff(name=name, status="added", b=_fp(name, va)))
        d.added += 1
    return d


def test_rematch_pairs_a_rare_identical_shape() -> None:
    diff = _diff_with([("sub_100", 0x100)], [("sub_200", 0x200)])
    rows_a = {0x100: _row(0x100, blocks=12, md=3.25)}
    rows_b = {0x200: _row(0x200, blocks=12, md=3.25)}
    _rematch_by_rare_md_index(diff, rows_a, rows_b, {}, {})

    assert diff.md_index_matched == 1
    assert diff.changed == 1
    assert diff.added == 0
    assert diff.removed == 0
    (row,) = diff.rows
    assert row.status == "changed"
    assert row.md_index_matched is True
    assert row.a is not None and row.b is not None
    assert row.a.entry_va == 0x100
    assert row.b.entry_va == 0x200
    # No Jaccard score was computed for this pair, and inventing one
    # would make `relocation_only` fire on a guess.
    assert row.similarity is None
    assert row.relocation_only is False


def test_rematch_refuses_a_shape_that_is_not_globally_rare() -> None:
    """The count is over the WHOLE binary. Three functions share the
    shape on the `a` side even though only one of them is unmatched, so
    the shape is not an identity and nothing may be paired on it."""
    diff = _diff_with([("sub_100", 0x100)], [("sub_200", 0x200)])
    rows_a = {
        0x100: _row(0x100, blocks=12, md=3.25),
        0x101: _row(0x101, blocks=12, md=3.25),
        0x102: _row(0x102, blocks=12, md=3.25),
    }
    rows_b = {0x200: _row(0x200, blocks=12, md=3.25)}
    _rematch_by_rare_md_index(diff, rows_a, rows_b, {}, {})

    assert diff.md_index_matched == 0
    assert diff.added == 1
    assert diff.removed == 1


def test_rematch_refuses_a_function_below_the_block_floor() -> None:
    diff = _diff_with([("sub_100", 0x100)], [("sub_200", 0x200)])
    small = fs.RARE_MIN_BLOCKS - 1
    rows_a = {0x100: _row(0x100, blocks=small, md=3.25)}
    rows_b = {0x200: _row(0x200, blocks=small, md=3.25)}
    _rematch_by_rare_md_index(diff, rows_a, rows_b, {}, {})
    assert diff.md_index_matched == 0


def test_rematch_refuses_an_ambiguous_pair() -> None:
    """Two residual survivors share one rare key. Picking one would be a
    guess dressed as a match; both stay added/removed."""
    diff = _diff_with(
        [("sub_100", 0x100), ("sub_101", 0x101)],
        [("sub_200", 0x200), ("sub_201", 0x201)],
    )
    rows_a = {
        0x100: _row(0x100, blocks=12, md=3.25),
        0x101: _row(0x101, blocks=12, md=3.25),
    }
    rows_b = {
        0x200: _row(0x200, blocks=12, md=3.25),
        0x201: _row(0x201, blocks=12, md=3.25),
    }
    _rematch_by_rare_md_index(diff, rows_a, rows_b, {}, {})
    assert diff.md_index_matched == 0
    assert diff.added == 2
    assert diff.removed == 2


def test_rematch_refuses_a_different_shape() -> None:
    diff = _diff_with([("sub_100", 0x100)], [("sub_200", 0x200)])
    rows_a = {0x100: _row(0x100, blocks=12, md=3.25)}
    rows_b = {0x200: _row(0x200, blocks=12, md=4.75)}
    _rematch_by_rare_md_index(diff, rows_a, rows_b, {}, {})
    assert diff.md_index_matched == 0


def test_rematch_is_a_noop_without_signatures() -> None:
    """A build where the native L1 binding produced nothing must leave
    the v3 answer exactly as it was."""
    diff = _diff_with([("sub_100", 0x100)], [("sub_200", 0x200)])
    before = (diff.changed, diff.added, diff.removed, len(diff.rows))
    _rematch_by_rare_md_index(diff, {}, {}, {}, {})
    assert diff.structural_rematch_ran is True
    assert (diff.changed, diff.added, diff.removed, len(diff.rows)) == before


def test_rematch_conserves_the_row_accounting() -> None:
    """Every match moves exactly one added and one removed row into one
    changed row, and drops the consumed partner from the row list."""
    diff = _diff_with(
        [("sub_100", 0x100), ("sub_110", 0x110)],
        [("sub_200", 0x200), ("sub_210", 0x210)],
    )
    rows_a = {
        0x100: _row(0x100, blocks=12, md=3.25),
        0x110: _row(0x110, blocks=20, md=8.5),
    }
    rows_b = {
        0x200: _row(0x200, blocks=12, md=3.25),
        0x210: _row(0x210, blocks=20, md=8.5),
    }
    _rematch_by_rare_md_index(diff, rows_a, rows_b, {}, {})
    assert diff.md_index_matched == 2
    assert diff.changed == 2
    assert diff.added == 0
    assert diff.removed == 0
    assert len(diff.rows) == 2
    assert {r.status for r in diff.rows} == {"changed"}
