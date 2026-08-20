"""Discovery on realistic binaries: stripped, lying, self-decrypting, packed.

The corpus is built from our own fixture sources by `tools/realistic_corpus.py`
(see that module for why each variant exists). These tests pin what the analysis
recovers from each one, so that a change which quietly costs us a whole class of
real-world input cannot pass unnoticed.

Scoping is deliberate: **one test per variant**, so a failure names the shape
that broke rather than reporting one aggregate that has to be bisected by hand.

The baseline is a ratchet. Move it only with
``uv run python tools/gen_realistic_baseline.py`` (``--check`` to test for
staleness), never by hand: a ratchet that can be reset by an ad-hoc snippet is
not a ratchet, and a baseline written from a stale ``.so`` records the previous
build's behaviour under this commit with nothing downstream able to tell.
The control (`dwarf`) is asserted exactly — it has full symbols, so anything
less than complete recall there is a defect in a lane that should be easy. The
hostile variants are asserted with a tolerance band, because seeding heuristics
legitimately move by a function or two, and a ratchet that fires on noise gets
disabled.

Two things the older half of this file gets wrong, kept working but not copied:

* it ratchets on a **count**, and a count cannot tell recovery from invention.
  `upxg` is the demonstration. Its committed baseline said 8 functions; it now
  finds 90, of which 10 are real — the ratchet is one-sided, so an 82-function
  swing into almost entirely wrong answers reads as a pass. Worse, the count is
  not even stable: five links differing only by comment padding in the driver
  gave 90, 90, 90, 8, 90. The lanes below therefore assert on address-level
  recall *and* precision.
* the corpus hands the answer away. In a PIE the driver's address table becomes
  one `R_X86_64_RELATIVE` relocation per corpus function, and `.eh_frame` holds
  one FDE per function; either is a complete function list, readable without
  decoding an instruction. `bare`/`encfn_bare` are the lanes with neither.
"""

from __future__ import annotations

import json
import subprocess
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
        + " (sudo apt-get install -y upx-ucl elfkickers patchelf binutils)"
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


@pytest.mark.parametrize("variant", ["strip", "sstrip"])
def test_stripped_variant_discovery_holds_its_baseline(variant, measured, baseline):
    """Discovery must not silently fall further on an already-hostile shape.

    Only the *stripped* lanes are ratcheted on a count. The packed ones are
    not, and cannot be — see below.
    """
    want = baseline["variants"][variant]["discovered"]
    got = measured[variant]["discovered"]
    assert got >= want - TOLERANCE, (
        f"{variant}: discovered {got} functions, baseline {want} "
        f"(tolerance {TOLERANCE}). Fewer functions found on a shape that was "
        f"already stripped or packed. Full measurement: {measured[variant]}\n"
        "If this is a deliberate improvement, ratchet with "
        "`uv run python tools/gen_realistic_baseline.py` — that is the only "
        "supported way to move this file, and it refuses to measure against a "
        "stale extension."
    )


#: Packed variant -> the unpacked build it was made from. Recovering the payload
#: means recovering *that file*, so its recall is the standard to meet.
PACKED_ORIGIN = {"upx": "strip", "upxg": "dwarf"}


@pytest.mark.parametrize("variant", sorted(PACKED_ORIGIN))
def test_a_packed_image_gives_up_the_program_it_was_hiding(variant, measured):
    """Unpacking must recover the payload as well as the file it was made from.

    This test was written the other way round a few hours earlier, asserting
    that recall stayed near zero, with a note that if it ever failed because
    recall went *up* it should be rewritten to demand the capability instead of
    tolerating its absence. It failed at 100%. This is that rewrite.

    Asserted against the origin build rather than an absolute number, because
    the recovered image *is* that file — byte for byte — so anything the origin
    lane finds we must find too. An absolute threshold would drift with the
    corpus; this cannot.

    Deliberately still **not** a count ratchet. The raw discovered count is not
    stable across links: five builds of the same corpus differing only by
    comment padding gave 90, 90, 90, 8, 90 findings on `upxg`, and the 90
    contained ten real functions. Recall against our own constructed ground
    truth has no such freedom.
    """
    truth = realistic_corpus.build()["ground_truth"]
    origin = PACKED_ORIGIN[variant]
    got = measured[variant]["truth_hit"] / len(truth)
    want = measured[origin]["truth_hit"] / len(truth)
    assert got >= want, (
        f"{variant}: recall {got:.1%} against {origin}'s {want:.1%}. The "
        "recovered image is supposed to be that file byte for byte, so it "
        "cannot yield fewer of our own functions."
    )


def test_an_image_we_cannot_unpack_is_not_silently_mislabelled():
    """The honest half: refusing must stay louder than guessing.

    Unpacking will not always work — LZMA and filtered images are refused by
    name, and PE-packed UPX is not handled. What must never happen is the
    original failure this whole lane exists for: reporting a decompressor
    stub's functions as though they were the program's.
    """
    import glaurung

    path = str(realistic_corpus.variant_path("upx"))
    _functions, _cg, stats = glaurung.analysis.analyze_functions_path_with_stats(path)
    assert stats.get("packer"), (
        "a UPX-packed image was analysed without the result saying it was "
        f"packed. stats keys: {sorted(stats)}"
    )
    assert stats.get("unpacked") or stats.get("unpack_error"), (
        "the analysis reported a packer but said neither that it recovered the "
        "payload nor why it could not — that is the ambiguity this lane exists "
        f"to remove. stats keys: {sorted(stats)}"
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


# ---------------------------------------------------------------------------
# Binary-level adversarial variants.
#
# Everything above this line varies *metadata* (symbols, section headers) or
# wraps the whole file in a packer. These vary the things a real sample has
# usually had done to it by the time an analyst sees it, and they are built from
# our own sources by a documented post-processing step — never copied from the
# system.
# ---------------------------------------------------------------------------

#: The binary-level adversarial shapes. Each is a separate lane so that a
#: failure names the shape rather than an aggregate.
ADVERSARIAL = ("rename", "patchelf", "overlap", "encfn", "bare", "encfn_bare")

#: Recall is measured against ground-truth function ADDRESSES, so it moves in
#: whole functions out of 83+. A band of 4 points is under four functions.
RECALL_TOLERANCE_PCT = 4.0


@pytest.mark.parametrize("variant", ADVERSARIAL)
def test_adversarial_variant_holds_its_address_recall(variant, measured, baseline):
    """Recall against the ground-truth addresses must not fall on a hostile shape."""
    want = baseline["variants"][variant]["truth_recall_pct"]
    got = measured[variant]["truth_recall_pct"]
    assert got >= want - RECALL_TOLERANCE_PCT, (
        f"{variant}: address recall {got}% against baseline {want}% "
        f"(tolerance {RECALL_TOLERANCE_PCT}). Full measurement: {measured[variant]}"
    )


@pytest.mark.parametrize("variant", ADVERSARIAL)
def test_adversarial_variant_holds_its_address_precision(variant, measured, baseline):
    """Precision against the variant's own symbol-bearing control must not fall.

    Precision is the half that anti-disassembly attacks: a desynchronised linear
    sweep does not lose functions so much as invent them, and a discovery count
    that holds while precision collapses looks like success.
    """
    want = baseline["variants"][variant]["control_precision_pct"]
    got = measured[variant]["control_precision_pct"]
    assert got >= want - RECALL_TOLERANCE_PCT, (
        f"{variant}: precision {got}% against baseline {want}%. "
        f"Full measurement: {measured[variant]}"
    )


def test_a_section_name_lie_costs_us_nothing(measured):
    """`.text` renamed away and `.rodata` renamed to `.text`.

    `objcopy --rename-section` touches only `.shstrtab`: every program header,
    every byte of every PT_LOAD and the entry point are identical to `strip`, so
    the loader cannot tell the two files apart. Anything that moves here moved
    because it matched on a section NAME rather than on what the bytes are.
    """
    lie = measured["rename"]["truth_recall_pct"]
    honest = measured["strip"]["truth_recall_pct"]
    assert lie >= honest - 1.0, (
        f"recall fell to {lie}% when `.text` was renamed `.rsrc` and `.rodata` "
        f"renamed `.text`, against {honest}% on the byte-identical `strip` "
        "build. The loadable bytes are the same in both files; this is a "
        "name dependence."
    )


def test_overlapping_instructions_do_not_poison_the_rest_of_the_binary(measured):
    """One anti-disassembly function must not cost recall on the other 83.

    `overlap` links an assembly function whose jumps land mid-instruction, so
    linear sweep desynchronises inside it. The question this pins is blast
    radius: a sweep that recovers after the hostile function keeps the ordinary
    functions, one that does not loses everything downstream of it.
    """
    hostile = measured["overlap"]["truth_recall_pct"]
    plain = measured["strip"]["truth_recall_pct"]
    assert hostile >= plain - 10.0, (
        f"recall fell to {hostile}% with one overlapping-instruction function "
        f"present, against {plain}% without it. The other functions are "
        "compiled identically; this is desynchronisation spreading."
    )


#: How far apart honest bytes and ciphertext must stay on the `bare` pair before
#: the corpus has stopped distinguishing them. Measured at 38.6 against 0.0 on
#: 2026-08-20; a gap under this means either the sweep has learned to read
#: encrypted code (re-record and celebrate) or `bare` has stopped working.
BARE_SEPARATION_PCT = 20.0


def test_the_bare_pair_still_separates_honest_bytes_from_ciphertext(measured):
    """The one lane where recall has to come out of the instruction stream.

    Every other variant still carries a list of every function somewhere: a
    symbol table, the `R_X86_64_RELATIVE` block the driver's address table
    compiles to in a PIE, or one FDE per function in `.eh_frame`. `bare` and
    `encfn_bare` have neither the table nor the unwind tables, and differ from
    each other only in whether the code bytes are encrypted — so the distance
    between them is the part of recall that is actually disassembly.

    It is not a large distance. On 2026-08-20 it was 38.6% against 0.0%: with
    the function list taken away, honest code gave up under two functions in
    five, and ciphertext gave up nothing at all.
    """
    honest = measured["bare"]["truth_recall_pct"]
    cipher = measured["encfn_bare"]["truth_recall_pct"]
    assert honest - cipher >= BARE_SEPARATION_PCT, (
        f"`bare` recovered {honest}% and `encfn_bare` {cipher}%, a gap of "
        f"{honest - cipher} points. These two files differ only in whether the "
        "executable section is encrypted, so a gap this small means the "
        "measurement is no longer telling code analysis apart from metadata."
    )


def test_overlapping_instructions_do_not_move_the_function_boundaries():
    """The anti-disassembly functions must come back at their real extents.

    Blast radius (the test above) is the cheap half. The expensive half is
    whether the two hostile functions themselves are recovered as the bytes the
    CPU executes rather than as the bytes a linear sweep reads, and only their
    *extent* can answer that — an entry point proves nothing here, because the
    driver calls both probes directly and recursive descent gets the addresses
    for free.

    `objdump -d` is the negative control, and it fails this comfortably. Against
    `glaurung_overlap_maze`, seventeen bytes long, it emits::

        11b7:   74 01                   je     11ba
        11b9:   0f 83 c0 0b eb 01       jae    1eb1d7f <_end+0x1eadd67>
        11bf:   c3                      ret

    -- one junk byte at `11b9` has swallowed the `add $11, %eax` and the `jmp`
    that follow it, so the add never appears at all and the branch target is
    nonsense. Sizes taken from `nm -S` on the control, which is the assembler's
    own `.size`, not anything we inferred.
    """
    control = realistic_corpus.variant_path("overlap_control")
    wanted = {n for n, _a, _e in realistic_corpus.OVERLAP_PROBES}
    truth: dict[str, tuple[int, int]] = {}
    for line in subprocess.run(
        ["nm", "-S", "--defined-only", str(control)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] in wanted:
            truth[parts[3]] = (int(parts[0], 16), int(parts[1], 16))
    assert truth.keys() == wanted, f"probe symbols missing from the control: {truth}"

    import glaurung

    functions, _ = glaurung.analysis.analyze_functions_path(
        str(realistic_corpus.variant_path("overlap"))
    )
    by_addr = {int(f.entry_point.value): f for f in functions}
    for name, (addr, size) in sorted(truth.items()):
        got = by_addr.get(addr)
        assert got is not None, (
            f"{name} at {addr:#x} was not recovered at all from the stripped "
            "anti-disassembly build."
        )
        assert got.size == size, (
            f"{name} at {addr:#x}: recovered {got.size} bytes, the assembler "
            f"says {size}. A sweep that desynchronises on the junk opcode runs "
            "past the end of the function or stops short of it."
        )
