"""Discovery and naming on realistic binaries: stripped, section-header-less, packed.

The corpus is built from our own fixture sources by `tools/realistic_corpus.py`
(see that module for why each variant exists). These tests pin what the analysis
recovers from each one, so that a change which quietly costs us a whole class of
real-world input cannot pass unnoticed.

Scoping is deliberate: **one test per variant**, so a failure names the shape
that broke rather than reporting one aggregate that has to be bisected by hand.
The control (`dwarf`) is asserted exactly — it has full symbols, so anything
less than complete recall there is a defect in a lane that should be easy. The
hostile variants are asserted with a tolerance band, because seeding heuristics
legitimately move by a function or two, and a ratchet that fires on noise gets
disabled.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "realistic_corpus"))
sys.path.insert(0, str(ROOT / "tools"))

import realistic_corpus  # noqa: E402

BASELINE = ROOT / "tests" / "realistic_corpus" / "discovery_baseline.json"

#: How far a hostile variant may drift before it is a regression. Discovery on
#: these shapes rests on heuristics, so an exact pin would fire on noise; a band
#: this tight still catches anything structural.
TOLERANCE = 3

pytestmark = pytest.mark.skipif(
    bool(realistic_corpus.missing_tools()),
    reason=(
        "needs "
        + ", ".join(realistic_corpus.missing_tools() or ["-"])
        + " (sudo apt-get install -y upx-ucl elfkickers)"
    ),
)


@pytest.fixture(scope="module")
def baseline() -> dict:
    if not BASELINE.exists():
        pytest.skip(f"no baseline at {BASELINE}")
    return json.loads(BASELINE.read_text())


@pytest.fixture(scope="module")
def measured() -> dict:
    import discovery

    return discovery.report()


def test_every_variant_actually_executes():
    """A variant that does not run is not evidence about anything.

    Post-processing can produce a file that still parses but no longer works —
    a packer that mangles the entry point, a strip that removes something the
    loader needed. Measuring recovery on such a file would be measuring noise.
    """
    manifest = realistic_corpus.build()
    broken = [v for v, info in manifest["variants"].items() if not info["runs"]]
    assert not broken, (
        f"variants that no longer execute: {broken}. "
        "Rebuild with `uv run python tools/realistic_corpus.py --force`."
    )


def test_the_control_recovers_every_function_we_linked_in(measured, baseline):
    """With DWARF present, recall against our own driver table must be total."""
    got = measured["dwarf"]
    truth = baseline["ground_truth_count"]
    assert got["truth_hit"] == truth, (
        f"control lane recovered {got['truth_hit']}/{truth} of the functions we "
        f"linked in ourselves. discovered={got['discovered']} named={got['named']}"
    )


@pytest.mark.parametrize("variant", ["strip", "sstrip", "upx", "upxg"])
def test_hostile_variant_discovery_holds_its_baseline(variant, measured, baseline):
    """Discovery must not silently fall further on an already-hostile shape."""
    want = baseline["variants"][variant]["discovered"]
    got = measured[variant]["discovered"]
    assert got >= want - TOLERANCE, (
        f"{variant}: discovered {got} functions, baseline {want} "
        f"(tolerance {TOLERANCE}). Fewer functions found on a shape that was "
        f"already stripped or packed. Full measurement: {measured[variant]}"
    )


#: How far `sstrip` may fall behind `strip` before the section-header
#: dependency is back. Held at the ordinary heuristic-noise band rather than at
#: a wider "some seeds are legitimately harder" allowance: as of the
#: `PT_GNU_EH_FRAME` fallback the sectionless lane is not behind at all, it is
#: one function *ahead*, so any slack beyond noise is slack that would hide a
#: real fall.
SECTIONLESS_ALLOWANCE = TOLERANCE


def test_removing_section_headers_does_not_cost_us_discovery(measured):
    """Parity across the section-header cliff.

    `sstrip` removes only the section header table: the PT_LOAD segments are
    identical and the executable bytes hash the same, so a loader cannot tell
    the two files apart. Discovery should not either.

    This test was originally written the other way round — asserting the gap
    *existed*, at 43 against 105 — and inverted once the fallback landed. The
    gap closed by reading what the loader reads: loadable segments instead of
    sections, `PT_DYNAMIC` instead of `.dynamic` to tell the GOT from a real
    pointer table, and `PT_GNU_EH_FRAME` instead of `.eh_frame`.
    """
    stripped = measured["strip"]["discovered"]
    sectionless = measured["sstrip"]["discovered"]
    assert sectionless >= stripped - SECTIONLESS_ALLOWANCE, (
        f"discovery fell to {sectionless} without section headers against "
        f"{stripped} with them, a gap of {stripped - sectionless} beyond the "
        f"{SECTIONLESS_ALLOWANCE} allowed. The executable bytes are identical "
        "in both files, so this is metadata dependence, not a harder binary."
    )


@pytest.fixture(scope="module")
def seed_kinds() -> dict[str, dict[str, int]]:
    """`seed_kind_counts` for the two variants that differ only in metadata."""
    import glaurung

    out: dict[str, dict[str, int]] = {}
    for variant in ("strip", "sstrip"):
        path = realistic_corpus.variant_path(variant)
        _functions, _cg, stats = glaurung.analysis.analyze_functions_path_with_stats(
            str(path)
        )
        out[variant] = dict(stats.get("seed_kind_counts", {}))
    return out


def test_eh_frame_seeds_survive_the_loss_of_the_section_headers(seed_kinds):
    """`.eh_frame` FDE starts are found through `PT_GNU_EH_FRAME` too.

    Asserted on the seed census rather than on the function total, and on this
    one seed kind rather than on all of them, because the total is not
    discriminating: the weaker `prologue` scan picks up several of the same
    entries, so losing every trusted FDE start moved the function count by
    only three. A count that barely moves is exactly how a whole evidence
    class goes missing unnoticed.

    Equality, not "non-zero": these two files have byte-identical executable
    segments, so the unwinder finds the same FDEs in both and so must we.
    """
    with_sections = seed_kinds["strip"].get("trusted_eh_frame", 0)
    without = seed_kinds["sstrip"].get("trusted_eh_frame", 0)
    assert with_sections > 0, (
        "the stripped lane found no .eh_frame seeds at all, so this test "
        f"discriminates nothing. seed kinds: {seed_kinds['strip']}"
    )
    assert without == with_sections, (
        f"{with_sections} trusted_eh_frame seeds with section headers, "
        f"{without} without. PT_GNU_EH_FRAME is a program header and survives "
        f"sstrip, so the FDE starts are still there to be read. "
        f"sectionless seed kinds: {seed_kinds['sstrip']}"
    )
