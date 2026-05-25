"""Tests for the structural fingerprint (BinDiff-style)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.kb.binary_diff import diff_binaries


_SWITCHY_V1 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_switchy_self_diff_all_rows_have_identical_structural_hash() -> None:
    """Diffing a binary against itself: every paired row must have the
    same structural_hash on both sides. This is the basic invariant —
    structural fingerprinting can't lose information that's already in
    the bytes."""
    binary = _need(_SWITCHY_V1)
    diff = diff_binaries(str(binary), str(binary))
    paired = [r for r in diff.rows if r.a is not None and r.b is not None]
    assert paired, "self-diff should produce at least one paired row"
    for r in paired:
        # Either both sides have a non-empty fingerprint and they match,
        # or both are empty (thunk/0-block function). They CAN'T differ
        # for a self-diff.
        assert r.a.structural_hash == r.b.structural_hash, (
            f"self-diff row {r.name!r} has divergent structural_hash: "
            f"{r.a.structural_hash!r} vs {r.b.structural_hash!r}"
        )


def test_switchy_self_diff_similarity_is_one() -> None:
    """Every paired row in a self-diff must have similarity == 1.0."""
    binary = _need(_SWITCHY_V1)
    diff = diff_binaries(str(binary), str(binary))
    paired = [r for r in diff.rows if r.a is not None and r.b is not None]
    for r in paired:
        # Similarity of 1.0 is the strong invariant for a self-diff.
        # ``None`` would only happen if the structural lifter failed on
        # one side but not the other — impossible for self-diff.
        assert r.similarity == 1.0, (
            f"self-diff row {r.name!r} has similarity={r.similarity}"
        )


def test_switchy_v1_v2_dispatch_has_low_similarity() -> None:
    """The dispatch function in v2 adds a bounds-check block; its
    structural similarity to v1 must be strictly less than 1.0 (the
    fingerprint correctly detects the new block) and strictly greater
    than 0.0 (most blocks survive — it's a single-block patch, not a
    rewrite)."""
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    diff = diff_binaries(str(a), str(b))
    changed = [r for r in diff.rows if r.status == "changed"]
    dispatch = next((r for r in changed if r.name == "dispatch"), None)
    assert dispatch is not None, "dispatch must be in changed rows"
    assert dispatch.similarity is not None
    assert 0.0 < dispatch.similarity < 1.0, (
        f"dispatch similarity {dispatch.similarity} is out of (0,1) range"
    )


def test_switchy_v1_v2_unchanged_functions_classified_as_same() -> None:
    """In switchy v1 → v2, only `dispatch` actually changes. The other
    functions (e.g. main, _start) have different *body bytes* because
    of address-shift in their call/jmp targets, but their structural
    fingerprint MUST match — that's the whole point of the v2 oracle.

    Before this change those rows showed up as "changed". The fix turns
    them into "same" with similarity 1.0 even when body_hash differs."""
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    diff = diff_binaries(str(a), str(b))
    # Find rows where the body_hash differs but the structural_hash
    # matches — these are precisely the "same code, shifted addresses"
    # cases that v2 fixes.
    body_shifted_but_structurally_same = [
        r for r in diff.rows
        if r.status == "same"
        and r.a is not None and r.b is not None
        and r.a.body_hash != r.b.body_hash
        and r.a.structural_hash == r.b.structural_hash
    ]
    assert body_shifted_but_structurally_same, (
        "expected at least one row where bytes differ but structure matches "
        "(the v2 noise-reduction case)"
    )


def test_to_json_emits_structural_hash_and_similarity() -> None:
    """The v2 JSON schema must expose both new fields per row so
    downstream consumers (the LLM agent, the diff UI) can act on them."""
    import json
    from glaurung.llm.kb.binary_diff import to_json
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    diff = diff_binaries(str(a), str(b))
    parsed = json.loads(to_json(diff))
    assert parsed["schema_version"] == "2"
    for row in parsed["rows"]:
        assert "similarity" in row
        if row.get("a"):
            assert "structural_hash" in row["a"]
        if row.get("b"):
            assert "structural_hash" in row["b"]
