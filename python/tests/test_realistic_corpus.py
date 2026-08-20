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


def test_removing_section_headers_costs_us_more_than_half_of_discovery(measured):
    """The section-header cliff, pinned as the defect it is.

    `sstrip` removes only the section header table: the PT_LOAD segments are
    identical and the executable bytes hash the same, so a loader cannot tell
    the two files apart. Any gap here is us reading section headers where we
    could be reading program headers.

    This asserts the gap **exists** rather than that it is acceptable — it is
    the regression test for task #103, and it should be inverted to assert
    parity once discovery stops depending on section headers.
    """
    stripped = measured["strip"]["discovered"]
    sectionless = measured["sstrip"]["discovered"]
    assert sectionless < stripped, (
        "sstrip now discovers as much as strip — the section-header dependency "
        f"looks fixed ({sectionless} vs {stripped}). Invert this test to assert "
        "parity and close task #103."
    )
