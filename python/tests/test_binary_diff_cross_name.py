"""Tests for the v3 cross-name structural rematch in binary_diff.

The cross-name pass (Diaphora-style) re-pairs unmatched ``added`` /
``removed`` rows using Jaccard similarity of their per-block token
multisets. The integration tests below exercise the path end-to-end
against the existing switchy samples, and the unit tests poke
``_rematch_unnamed_by_structure`` directly with synthetic structures
so we get a deterministic check of the algorithm itself (threshold
gating, greedy match, one-sided rows).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaurung.llm.kb.binary_diff import (
    BinaryDiff,
    CROSS_NAME_THRESHOLD_DEFAULT,
    FunctionDiff,
    FunctionFingerprint,
    _rematch_unnamed_by_structure,
    diff_binaries,
    to_json,
)
from glaurung.llm.kb.structural_fingerprint import FunctionStructure


_SWITCHY_V1 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)
_SWITCHY_STRIPPED = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-stripped"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


# ---------------------------------------------------------------------------
# Unit tests against the algorithm directly. These don't depend on any
# binary fixture — they construct the exact diff state the rematch pass
# expects and assert on the post-pass state.
# ---------------------------------------------------------------------------


def _mk_fp(name: str, va: int = 0x1000, size: int = 32) -> FunctionFingerprint:
    """Tiny fingerprint helper."""
    return FunctionFingerprint(
        name=name,
        entry_va=va,
        size=size,
        body_hash="aa" * 8,
        structural_hash="bb" * 8,
    )


def _mk_structure(
    token_hashes: tuple,
    n_blocks: int = 3,
) -> FunctionStructure:
    """Tiny structure helper. Token hashes are the per-block fingerprints
    that drive the Jaccard similarity; n_blocks is the count used by the
    pre-filter."""
    return FunctionStructure(
        fingerprint="dead" * 4,
        block_token_hashes=token_hashes,
        stats=(n_blocks, 0, 0, 0, 0, 0, 1),
    )


def test_rematch_collapses_a_high_similarity_pair() -> None:
    """Two unmatched rows whose per-block token multisets fully overlap
    must collapse into one ``changed`` row at similarity 1.0."""
    diff = BinaryDiff(binary_a="a", binary_b="b", functions_a=1, functions_b=1)
    diff.added = 1
    diff.removed = 1
    diff.rows = [
        FunctionDiff(name="sub_A", status="removed", a=_mk_fp("sub_A")),
        FunctionDiff(name="sub_B", status="added", b=_mk_fp("sub_B")),
    ]
    tokens = ("h1", "h2", "h3", "h4")
    structures_a = {"sub_A": _mk_structure(tokens, n_blocks=4)}
    structures_b = {"sub_B": _mk_structure(tokens, n_blocks=4)}

    _rematch_unnamed_by_structure(
        diff,
        structures_a=structures_a,
        structures_b=structures_b,
        pdb_map_a={},
        pdb_map_b={},
        threshold=0.85,
    )

    # One row should remain — a merged ``changed`` row carrying both
    # sides' fingerprints.
    assert diff.cross_name_matched == 1
    assert diff.added == 0
    assert diff.removed == 0
    assert diff.changed == 1
    assert len(diff.rows) == 1
    merged = diff.rows[0]
    assert merged.status == "changed"
    assert merged.a is not None and merged.a.name == "sub_A"
    assert merged.b is not None and merged.b.name == "sub_B"
    assert merged.similarity == 1.0
    assert diff.cross_name_threshold == 0.85


def test_rematch_leaves_below_threshold_pair_alone() -> None:
    """When the Jaccard similarity sits below the threshold the rows
    must NOT collapse — they stay added/removed for the caller to
    inspect manually."""
    diff = BinaryDiff(binary_a="a", binary_b="b", functions_a=1, functions_b=1)
    diff.added = 1
    diff.removed = 1
    diff.rows = [
        FunctionDiff(name="sub_A", status="removed", a=_mk_fp("sub_A")),
        FunctionDiff(name="sub_B", status="added", b=_mk_fp("sub_B")),
    ]
    # Disjoint token multisets — Jaccard = 0.0.
    structures_a = {"sub_A": _mk_structure(("h1", "h2", "h3"), n_blocks=3)}
    structures_b = {"sub_B": _mk_structure(("h7", "h8", "h9"), n_blocks=3)}

    _rematch_unnamed_by_structure(
        diff,
        structures_a=structures_a,
        structures_b=structures_b,
        pdb_map_a={},
        pdb_map_b={},
        threshold=0.85,
    )

    assert diff.cross_name_matched == 0
    assert diff.added == 1
    assert diff.removed == 1
    assert diff.changed == 0
    statuses = sorted(r.status for r in diff.rows)
    assert statuses == ["added", "removed"]


def test_rematch_one_sided_added_function_stays_added() -> None:
    """A truly added function (no plausible removed partner) must
    survive as an ``added`` row. The greedy match must never pair it
    with an unrelated removed row even if there's exactly one."""
    diff = BinaryDiff(binary_a="a", binary_b="b", functions_a=1, functions_b=2)
    diff.added = 2
    diff.removed = 1
    diff.rows = [
        FunctionDiff(name="sub_X", status="removed", a=_mk_fp("sub_X")),
        FunctionDiff(name="sub_Y", status="added", b=_mk_fp("sub_Y")),
        FunctionDiff(name="sub_Z", status="added", b=_mk_fp("sub_Z")),
    ]
    # sub_X tokens match sub_Y but not sub_Z. sub_Z is the genuinely-new
    # function with disjoint tokens — it MUST stay added.
    tokens_match = ("h1", "h2", "h3", "h4", "h5")
    tokens_new = ("zz1", "zz2", "zz3", "zz4", "zz5")
    structures_a = {"sub_X": _mk_structure(tokens_match, n_blocks=5)}
    structures_b = {
        "sub_Y": _mk_structure(tokens_match, n_blocks=5),
        "sub_Z": _mk_structure(tokens_new, n_blocks=5),
    }

    _rematch_unnamed_by_structure(
        diff,
        structures_a=structures_a,
        structures_b=structures_b,
        pdb_map_a={},
        pdb_map_b={},
        threshold=0.85,
    )

    # sub_X <-> sub_Y collapses; sub_Z stays as a genuinely-new ``added``.
    assert diff.cross_name_matched == 1
    assert diff.added == 1
    assert diff.removed == 0
    assert diff.changed == 1
    statuses = sorted(r.status for r in diff.rows)
    assert statuses == ["added", "changed"]
    # And the surviving added row IS sub_Z.
    survivor = next(r for r in diff.rows if r.status == "added")
    assert survivor.name == "sub_Z"
    # The merged row pairs X with Y.
    merged = next(r for r in diff.rows if r.status == "changed")
    assert merged.a is not None and merged.a.name == "sub_X"
    assert merged.b is not None and merged.b.name == "sub_Y"


def test_rematch_picks_best_partner_greedily() -> None:
    """When one removed row could pair with several added rows, the
    greedy match must lock it to the HIGHEST-similarity partner and
    leave the others to compete for a different partner (or remain
    added)."""
    diff = BinaryDiff(binary_a="a", binary_b="b", functions_a=1, functions_b=2)
    diff.added = 2
    diff.removed = 1
    diff.rows = [
        FunctionDiff(name="sub_X", status="removed", a=_mk_fp("sub_X")),
        FunctionDiff(name="sub_Y_good", status="added", b=_mk_fp("sub_Y_good")),
        FunctionDiff(name="sub_Y_close", status="added", b=_mk_fp("sub_Y_close")),
    ]
    structures_a = {
        "sub_X": _mk_structure(("h1", "h2", "h3", "h4", "h5"), n_blocks=5),
    }
    # sub_Y_good has Jaccard ~1.0 with sub_X; sub_Y_close has ~0.86.
    structures_b = {
        "sub_Y_good": _mk_structure(
            ("h1", "h2", "h3", "h4", "h5"), n_blocks=5,
        ),
        "sub_Y_close": _mk_structure(
            ("h1", "h2", "h3", "h4", "h6"), n_blocks=5,
        ),
    }

    _rematch_unnamed_by_structure(
        diff,
        structures_a=structures_a,
        structures_b=structures_b,
        pdb_map_a={},
        pdb_map_b={},
        threshold=0.85,
    )

    # One pair locks; the other added row keeps status=added.
    assert diff.cross_name_matched == 1
    merged = next(r for r in diff.rows if r.status == "changed")
    # The high-similarity partner must win.
    assert merged.b is not None and merged.b.name == "sub_Y_good"
    survivor = next(r for r in diff.rows if r.status == "added")
    assert survivor.name == "sub_Y_close"


def test_rematch_threshold_none_skips_pass() -> None:
    """``cross_name_threshold=None`` must bypass the pass entirely
    (the v2 contract). Counts and row identities stay untouched."""
    diff = diff_binaries(
        str(_need(_SWITCHY_V1)),
        str(_need(_SWITCHY_STRIPPED)),
        skip_anonymous=False,
        cross_name_threshold=None,
    )
    assert diff.cross_name_matched == 0
    # threshold sentinel value when disabled.
    assert diff.cross_name_threshold == -1.0


def test_rematch_propagates_pdb_names_into_merged_row() -> None:
    """When one side of a cross-name pair has a PDB symbol, the merged
    ``changed`` row must surface it in the appropriate
    ``public_name_*`` field."""
    diff = BinaryDiff(binary_a="a", binary_b="b", functions_a=1, functions_b=1)
    diff.added = 1
    diff.removed = 1
    fa = _mk_fp("sub_A", va=0xAAAA)
    fb = _mk_fp("sub_B", va=0xBBBB)
    diff.rows = [
        FunctionDiff(name="sub_A", status="removed", a=fa, public_name_pre=None),
        FunctionDiff(name="sub_B", status="added", b=fb, public_name_post="known_post"),
    ]
    tokens = ("h1", "h2", "h3", "h4")
    structures_a = {"sub_A": _mk_structure(tokens, n_blocks=4)}
    structures_b = {"sub_B": _mk_structure(tokens, n_blocks=4)}

    _rematch_unnamed_by_structure(
        diff,
        structures_a=structures_a,
        structures_b=structures_b,
        pdb_map_a={0xAAAA: "known_pre"},
        pdb_map_b={},
        threshold=0.85,
    )

    merged = diff.rows[0]
    assert merged.status == "changed"
    # The pre-side picks up the PDB lookup; the post-side keeps the
    # row's already-resolved value.
    assert merged.public_name_pre == "known_pre"
    assert merged.public_name_post == "known_post"


# ---------------------------------------------------------------------------
# Integration tests against the switchy stripped/unstripped pair. The
# stripped binary loses several symbols (e.g. ``_start`` becomes
# ``sub_<hex>``), so the cross-name pass must collapse at least one
# (added, removed) pair into a ``changed`` row.
# ---------------------------------------------------------------------------


def test_switchy_stripped_cross_name_collapses_at_least_one_pair() -> None:
    a, b = _need(_SWITCHY_V1), _need(_SWITCHY_STRIPPED)
    with_pass = diff_binaries(str(a), str(b), skip_anonymous=False)
    without_pass = diff_binaries(
        str(a), str(b), skip_anonymous=False, cross_name_threshold=None,
    )
    # The pass MUST find at least one rename.
    assert with_pass.cross_name_matched >= 1
    # And it MUST reduce the unmatched set.
    assert with_pass.added + with_pass.removed < without_pass.added + without_pass.removed
    # The conservation invariant: matched pairs move one added + one
    # removed into one changed row each.
    assert with_pass.changed - without_pass.changed == with_pass.cross_name_matched
    assert without_pass.added - with_pass.added == with_pass.cross_name_matched
    assert without_pass.removed - with_pass.removed == with_pass.cross_name_matched


def test_switchy_self_diff_no_cross_name_matches() -> None:
    """A self-diff cannot produce any cross-name matches — every
    function pairs by name, leaving the rematch pass with an empty
    candidate set."""
    binary = _need(_SWITCHY_V1)
    diff = diff_binaries(str(binary), str(binary), skip_anonymous=False)
    assert diff.cross_name_matched == 0
    assert diff.cross_name_threshold == CROSS_NAME_THRESHOLD_DEFAULT


def test_schema_3_json_carries_cross_name_diagnostics() -> None:
    """The new JSON schema must expose ``cross_name_matched`` and
    ``cross_name_threshold`` at the top level."""
    a, b = _need(_SWITCHY_V1), _need(_SWITCHY_STRIPPED)
    diff = diff_binaries(str(a), str(b), skip_anonymous=False)
    parsed = json.loads(to_json(diff))
    assert parsed["schema_version"] == "3"
    assert parsed["cross_name_matched"] == diff.cross_name_matched
    assert parsed["cross_name_threshold"] == diff.cross_name_threshold
