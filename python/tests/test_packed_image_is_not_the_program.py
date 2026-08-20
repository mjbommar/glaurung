"""A packed binary must not be reported as though it were the program.

Function discovery over a UPX-packed image does not fail. It succeeds — on the
decompressor stub — and returns a handful of real functions that belong to the
packer rather than to the binary's author. Measured against
`tests/realistic_corpus/`, whose ground truth is eighty-three functions we
compiled and linked ourselves, the packed variant returned eight functions and
not one of them was ours: 0% recall, presented with exactly the same confidence
as the 100% the unstripped control earns.

The tests here are scoped one claim apiece, in the order the claims matter:

1. the analysis *says* the image was packed, and by what;
2. it says whether the functions it is returning are the program's;
3. when it cannot reach the program, the functions it does return are not named
   as if they were;
4. when it can, the recovered image is byte-for-byte the one that was packed —
   checked against the packer's own recorded checksum and against `upx -d`;
5. recall against the ground truth goes up accordingly.

Point 4 is what makes the rest safe. An unpacker that is *nearly* right produces
an image that disassembles into plausible nonsense, which is the failure mode
this whole file exists to prevent, so the round-trip is asserted on real
`upx`-produced input rather than assumed from the recall number moving.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import glaurung as g

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "realistic_corpus"))
sys.path.insert(0, str(ROOT / "tools"))

import realistic_corpus  # noqa: E402

pytestmark = pytest.mark.skipif(
    bool(realistic_corpus.missing_tools()),
    reason=(
        "needs "
        + ", ".join(realistic_corpus.missing_tools() or ["-"])
        + " (sudo apt-get install -y upx-ucl elfkickers)"
    ),
)

#: UPX's own method numbering, for asserting on refusals by name.
M_LZMA = 14


@pytest.fixture(scope="module")
def packed() -> Path:
    return realistic_corpus.variant_path("upx")


@pytest.fixture(scope="module")
def original() -> Path:
    """The exact file that was packed to make the `upx` variant."""
    return realistic_corpus.variant_path("strip")


def _repack(tmp_path: Path, method: str) -> Path:
    """Pack the corpus with a chosen compressor, for coverage of that codec.

    Real `upx` output, produced here rather than committed, because a codec we
    claim to decode must be tested against bytes the packer actually emits.
    """
    src = tmp_path / f"corpus.{method}.in"
    out = tmp_path / f"corpus.{method}.upx"
    shutil.copy2(realistic_corpus.variant_path("strip"), src)
    r = subprocess.run(
        ["upx", "-9", "-q", "-f", f"--{method}", "-o", str(out), str(src)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0 or not out.exists():
        pytest.skip(
            f"this upx cannot pack with --{method}: {(r.stderr or r.stdout)[:120]}"
        )
    return out


def test_the_analysis_says_the_image_was_packed(packed):
    """Claim 1: the result carries the packer's name.

    Without this a consumer cannot tell a packed binary from a small one; the
    function count is low either way.
    """
    _funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(str(packed))
    assert stats.get("packer") == "UPX", (
        "analysis of a UPX-packed image did not report a packer. "
        f"stats keys present: {sorted(stats)[:12]}..."
    )


def test_the_analysis_says_whether_these_are_the_programs_functions(packed):
    """Claim 2: `unpacked` distinguishes the program from the stub."""
    _funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(str(packed))
    assert stats.get("unpacked") is True, (
        "the corpus is packed with NRV2B and no filter, which is exactly the "
        f"case we unpack; stats said unpacked={stats.get('unpacked')!r} "
        f"error={stats.get('unpack_error')!r}"
    )
    assert stats.get("original_entry") is not None, (
        "the original program's entry point was not recovered"
    )


def test_an_image_we_cannot_unpack_does_not_name_its_stub_like_the_program(tmp_path):
    """Claim 3: refusing to unpack must not mean quietly mislabelling.

    LZMA blocks are not decoded by this build. That is a fine answer — but the
    functions still discovered belong to the unpacker, and a result list of
    `sub_...` entries claims otherwise to every consumer downstream.
    """
    lzma_packed = _repack(tmp_path, "lzma")
    funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(str(lzma_packed))
    assert stats.get("packer") == "UPX"
    assert stats.get("unpacked") is False
    assert str(M_LZMA) in (stats.get("unpack_error") or ""), (
        "the refusal must name the method that stopped it, so a reader knows "
        f"what is missing; got {stats.get('unpack_error')!r}"
    )
    mislabelled = [f.name for f in funcs if f.name.startswith("sub_")]
    assert not mislabelled, (
        f"{len(mislabelled)} functions of the UPX stub are named as if they were "
        f"the program's: {mislabelled[:5]}"
    )


def test_the_unpacker_reproduces_the_packed_file_byte_for_byte(packed, original):
    """Claim 4: the recovered image is the original, not an approximation."""
    result = g.unpack.unpack_path(str(packed))
    assert result["packer"] == "UPX"
    assert result["bytes"] == original.read_bytes(), (
        f"recovered {result['size']} bytes; the file that was packed is "
        f"{original.stat().st_size} bytes and they are not the same bytes"
    )


@pytest.mark.parametrize("method", ["nrv2b", "nrv2d", "nrv2e"])
def test_every_codec_we_claim_round_trips_on_real_packer_output(
    method, tmp_path, original
):
    """Claim 4, across the compressors UPX actually chooses between."""
    repacked = _repack(tmp_path, method)
    result = g.unpack.unpack_path(str(repacked))
    assert result["bytes"] == original.read_bytes(), (
        f"--{method} image did not round-trip to the file that was packed"
    )


def test_a_codec_we_do_not_implement_is_refused_by_name(tmp_path):
    """Claim 4's other half: no guessing when the method is unknown."""
    lzma_packed = _repack(tmp_path, "lzma")
    with pytest.raises(ValueError) as excinfo:
        g.unpack.unpack_path(str(lzma_packed))
    assert str(M_LZMA) in str(excinfo.value), (
        f"the refusal should name method {M_LZMA}; got {excinfo.value}"
    )


def test_the_container_is_readable_even_when_the_image_is_not_unpackable(tmp_path):
    """What stays knowable when unpacking is off the table.

    The original size, the method and the filter are in the packer's own header
    and need no decompression. Reporting them is strictly more than reporting
    the stub's function list.
    """
    lzma_packed = _repack(tmp_path, "lzma")
    info = g.unpack.describe_path(str(lzma_packed))
    assert info is not None
    assert info["packer"] == "UPX"
    assert info["method"] == M_LZMA
    assert (
        info["original_size"] == realistic_corpus.variant_path("strip").stat().st_size
    )


def test_an_ordinary_binary_is_not_described_as_packed(original):
    """The detector must not fire on the unpacked control."""
    assert g.unpack.describe_path(str(original)) is None


@pytest.mark.parametrize("variant", ["upx", "upxg"])
def test_recall_against_our_own_functions_survives_packing(variant):
    """Claim 5: the number that started this. 0% recall is the bug.

    Scored by entry address against the eighty-three functions the corpus driver
    holds pointers to, so a high count of *something* cannot pass for finding
    them.
    """
    import recall

    scored = recall.measure(variant)
    assert scored["recall"] >= 0.90, (
        f"{variant}: recall {scored['recall']:.1%} against the {scored['true_positive'] + scored['missed']} "
        f"functions we linked in ourselves. Full measurement: {scored}"
    )


@pytest.mark.parametrize("variant", ["upx", "upxg"])
def test_precision_on_a_packed_image_matches_the_unpacked_one(variant):
    """Recall bought with false positives is not a fix.

    The packed variants unpack to exactly the `strip` and `dwarf` files, so
    their scores should track those, not merely improve.
    """
    import recall

    truth = recall.ground_truth_addresses()
    control = "strip" if variant == "upx" else "dwarf"
    got = recall.measure(variant, truth)
    want = recall.measure(control, truth)
    assert got["precision"] >= want["precision"] - 0.02, (
        f"{variant} precision {got['precision']:.1%} against {control}'s "
        f"{want['precision']:.1%}"
    )
    assert got["true_positive"] >= want["true_positive"], (
        f"{variant} recovered {got['true_positive']} of our functions against "
        f"{control}'s {want['true_positive']}"
    )
