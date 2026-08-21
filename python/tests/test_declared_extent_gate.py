"""A function's declared extent is evidence; a byte pattern is not.

Discovery refuses a heuristic seed that lands inside a function it has *walked*.
That test is blind to a C++ landing pad, because it reasons about reachable
blocks and the unwinder arrives by indirect jump from outside the CFG — so no
walk of the parent ever covers the pad. `.eh_frame` knows, and was not asked.

Two things then have to hold at once, and getting one without the other is the
whole difficulty:

1. A prologue-shaped address strictly inside another function's FDE is **not**
   a function. Without this, `136_cpp_exception_unwinding:gcc:O0` emits
   `sub_14f0` — a landing pad rendered standalone, which necessarily reads an
   undefined value because the frame it dereferences belongs to its parent.
2. A PLT import stub **is** a function, even though the linker covers the whole
   `.plt` with a single FDE. Trusting that FDE deleted six real stubs from the
   same fixture on the first attempt here, and five more from the `sstrip`
   corpus lane, where no section table exists to say where the PLT is.

These are asserted on real built binaries rather than on synthetic ranges,
because the unit tests in `analysis::cfg::extents` already cover the containment
arithmetic; what they cannot cover is whether the PLT is actually locatable on
an image whose section headers are gone.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

FIXTURES = ROOT / "tests" / "decompiler_fixtures" / "build"

#: `cpp_destructors_run_while_unwinding` is `0x13f0 + 360 = 0x1558`; the landing
#: pad sits at `0x14f0`, strictly inside it, opening with `endbr64` because the
#: unwinder reaches it by indirect jump.
LANDING_PAD_FIXTURE = "136_cpp_exception_unwinding-gcc-O0.so"


def _entry_points(path: Path) -> set[int]:
    import glaurung

    functions, _callgraph = glaurung.analysis.analyze_functions_path(str(path))
    return {f.entry_point.value for f in functions}


def _plt_bounds(path: Path) -> tuple[int, int]:
    """`.plt`-family address bounds, read with an external tool as an oracle.

    Deliberately not read through Glaurung: this file exists to check that our
    own PLT location is right, so taking the bounds from our own code would make
    the assertion circular.
    """
    out = subprocess.run(
        ["readelf", "-SW", str(path)], capture_output=True, text=True, check=False
    ).stdout
    lows, highs = [], []
    for line in out.splitlines():
        parts = line.replace("[", " ").replace("]", " ").split()
        if len(parts) > 5 and parts[1] in (".plt", ".plt.sec", ".plt.got", ".iplt"):
            address, size = int(parts[3], 16), int(parts[6], 16)
            lows.append(address)
            highs.append(address + size)
    if not lows:
        pytest.skip(f"{path.name} has no PLT sections to bound")
    return min(lows), max(highs)


@pytest.fixture(scope="module")
def landing_pad_fixture() -> Path:
    path = FIXTURES / LANDING_PAD_FIXTURE
    if not path.is_file():
        pytest.skip(
            f"{LANDING_PAD_FIXTURE} not built "
            "(uv run python tools/dectest.py 136_cpp_exception_unwinding:gcc:O0)"
        )
    return path


def test_a_landing_pad_is_not_promoted_to_a_function(landing_pad_fixture):
    """The address the FDE table says belongs to somebody else.

    Asserted by containment rather than by the literal `0x14f0`, so a rebuild
    that shifts addresses still tests the real property instead of silently
    passing.
    """
    import glaurung

    entries = _entry_points(landing_pad_fixture)
    functions, _ = glaurung.analysis.analyze_functions_path(str(landing_pad_fixture))
    named = {f.entry_point.value: f.name for f in functions}
    parent = next(
        (
            va
            for va, name in named.items()
            if name == "cpp_destructors_run_while_unwinding"
        ),
        None,
    )
    assert parent is not None, (
        f"parent function not discovered at all: {sorted(named.values())}"
    )

    # Its FDE end, taken from the unwind table rather than from us.
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(landing_pad_fixture)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    end = None
    for line in out.splitlines():
        if "FDE" in line and "pc=" in line:
            span = line.split("pc=")[1].split()[0]
            low, high = (int(x, 16) for x in span.split(".."))
            if low == parent:
                end = high
    assert end is not None, f"no FDE starts at the parent {parent:#x}"

    intruders = sorted(va for va in entries if parent < va < end)
    assert not intruders, (
        f"{[hex(va) for va in intruders]} were emitted as functions but lie inside "
        f"{parent:#x}..{end:#x}, which the FDE table declares as one function. A "
        "landing pad rendered standalone reads its parent's frame."
    )


def test_every_plt_stub_survives_the_gate(landing_pad_fixture):
    """The counter-pressure: one FDE covers the whole `.plt`, and every 16-byte
    slot inside it is a real function that must still be discovered."""
    low, high = _plt_bounds(landing_pad_fixture)
    entries = _entry_points(landing_pad_fixture)
    found = sorted(va for va in entries if low <= va < high)
    # Exact, not a floor: this fixture's PLT is ten 16-byte slots and all ten
    # are discovered today. A floor would let the next stub go missing quietly,
    # which is precisely the failure this file exists to catch.
    expected = (high - low) // 16
    assert len(found) == expected, (
        f"{len(found)} of {expected} PLT slots in {low:#x}..{high:#x} were "
        f"discovered: {[hex(va) for va in found]}. A section-wide PLT FDE was "
        "probably mistaken for a single function."
    )


def test_stripping_the_section_table_does_not_lose_plt_stubs():
    """`sstrip` deletes the section headers, and the PLT must still be found.

    This is the case that makes the gate safe. Every PLT lookup in the tree
    locates the table by section NAME, so on an image with no section table the
    gate would read the `.plt` FDE as a single function and delete the stubs
    inside it — five of them, measured, before
    `formats::elf::dynamic_segment::plt_stub_ranges` gave it a relocation-backed
    answer instead.
    """
    import realistic_corpus  # noqa: PLC0415

    missing = realistic_corpus.missing_tools()
    if missing:
        pytest.skip("needs " + ", ".join(missing))
    try:
        stripped = realistic_corpus.variant_path("strip")
        sstripped = realistic_corpus.variant_path("sstrip")
    except Exception as exc:  # corpus not built
        pytest.skip(f"realistic corpus unavailable: {exc}")
    if not (stripped.is_file() and sstripped.is_file()):
        pytest.skip("realistic corpus not built (tools/realistic_corpus.py)")

    low, high = _plt_bounds(stripped)
    with_sections = {va for va in _entry_points(stripped) if low <= va < high}
    without = {va for va in _entry_points(sstripped) if low <= va < high}
    assert with_sections, "no PLT stubs discovered even with section headers"
    assert with_sections == without, (
        "deleting the section header table changed which PLT stubs were found; "
        f"only in strip: {[hex(v) for v in sorted(with_sections - without)]}, "
        f"only in sstrip: {[hex(v) for v in sorted(without - with_sections)]}"
    )
