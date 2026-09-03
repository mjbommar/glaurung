"""The FLIRT signature builder, against the real archive this repo ships.

The builder's whole job is to produce signatures that survive a relink, and
the only way to check that is against an unlinked `.o` with a real relocation
table. `samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a`
is committed, so these tests need no compiler and no fixture build.

The Rust side of the same story -- matching the resulting library against two
images that link that archive different ways -- is
`tests/flirt_signature_matching.rs`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import glaurung as g
from glaurung.tools.build_flirt_library import (
    PROLOGUE_LEN,
    SCHEMA_VERSION_MASKED,
    _masked_pattern,
    build_library_from_archive,
    main,
)

REPO = Path(__file__).resolve().parents[2]
ARCHIVE = REPO / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
SHIPPED = REPO / "data/sigs/glaurung-base.x86_64.flirt.json"


@pytest.fixture(scope="module")
def library() -> dict:
    assert ARCHIVE.is_file(), (
        f"{ARCHIVE} is committed, not generated; its absence means the samples "
        "tree was pruned"
    )
    return build_library_from_archive(
        ARCHIVE,
        library_name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        arch="x86_64",
    )


def test_the_archive_yields_a_masked_library(library: dict) -> None:
    """The headline: signatures come out, and they carry masks."""
    assert library["schema_version"] == SCHEMA_VERSION_MASKED
    assert library["prologue_len"] == PROLOGUE_LEN
    assert len(library["entries"]) >= 15
    assert library["stats"]["signatures_with_masked_bytes"] >= 15
    # Four of the archive's twenty functions are 10 to 11 bytes of generic
    # code and get no signature at all; see the `min_fixed_bytes` note in
    # `src/flirt/archive.rs`. A library that suddenly held all twenty would
    # mean that floor had been lowered.
    assert len(library["entries"]) <= 18


def test_the_library_is_keyed_by_name_version_variant_and_arch(library: dict) -> None:
    """A corpus across compilers is N libraries, not one, so the variant is
    part of the identity rather than a comment."""
    assert library["library"] == {
        "name": "mathlib",
        "version": "1.0.0",
        "variant": "gcc-15.2.0-O2",
        "arch": "x86_64",
    }


def test_every_mask_is_the_same_byte_length_as_its_pattern(library: dict) -> None:
    """A mask of the wrong length makes the Rust loader drop the entry, so the
    library would shrink silently rather than fail."""
    for e in library["entries"]:
        assert len(e["prologue_hex"]) == PROLOGUE_LEN * 2, e["name"]
        assert len(e["mask_hex"]) == len(e["prologue_hex"]), e["name"]
        assert set(e["mask_hex"]) <= set("f0"), e["name"]


def test_masks_are_not_uniformly_open_or_uniformly_closed(library: dict) -> None:
    """A mask that is all-fixed is v1 again; one that is all-variant matches
    everything. Both are failure modes that a length check cannot see."""
    for e in library["entries"]:
        mask = bytes.fromhex(e["mask_hex"])
        fixed = sum(1 for b in mask if b)
        assert fixed >= 16, f"{e['name']} compares only {fixed} bytes"
        assert fixed <= PROLOGUE_LEN, e["name"]
    assert any(
        b == 0 for e in library["entries"] for b in bytes.fromhex(e["mask_hex"])
    ), "no entry masked a single byte; the relocation table was not read"


def test_the_crc_is_recorded_with_its_length_or_not_at_all(library: dict) -> None:
    """`crc_len == 0` is FLIRT's way of saying "no CRC"; a CRC without a length
    would be unverifiable and a length without a CRC would reject everything."""
    for e in library["entries"]:
        if e["crc_len"]:
            assert isinstance(e["crc16"], int)
            assert 0 <= e["crc16"] <= 0xFFFF
        else:
            assert e["crc16"] is None, e["name"]


def test_references_are_sorted_and_inside_the_function(library: dict) -> None:
    for e in library["entries"]:
        offsets = [r["offset"] for r in e["refs"]]
        assert offsets == sorted(offsets), e["name"]
        for r in e["refs"]:
            assert r["name"]
            if e["function_len"] is not None:
                assert r["offset"] < e["function_len"], e["name"]


def test_the_build_is_deterministic(library: dict) -> None:
    """A rebuild that changed nothing must produce a zero-line diff, or the
    committed library becomes unreviewable."""
    again = build_library_from_archive(
        ARCHIVE,
        library_name="mathlib",
        version="1.0.0",
        variant="gcc-15.2.0-O2",
        arch="x86_64",
    )
    assert json.dumps(again, sort_keys=True) == json.dumps(library, sort_keys=True)


def test_ambiguity_is_keyed_on_the_masked_pattern() -> None:
    """Two signatures that differ only in bytes nobody compares are the same
    signature. Keying the ambiguity check on the raw hex would let both in and
    let whichever came first win -- a coin flip written at `set_by=flirt`."""
    assert _masked_pattern("aabbccdd", "ffff0000") == "aabb0000"
    assert _masked_pattern("aabbeeff", "ffff0000") == "aabb0000"
    assert _masked_pattern("aabbccdd", None) == "aabbccdd"


def test_archive_builder_keeps_public_name_for_same_address_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = {
        "prologue_hex": "aa" * 32,
        "mask_hex": "ff" * 32,
        "crc16": 7,
        "crc_len": 4,
        "function_len": 64,
        "refs": [],
        "member": "ioputs.o",
        "address": 0,
        "masked_bytes": 0,
    }
    rows = [
        {**base, "name": "_IO_puts", "source_binary": "ioputs.o!_IO_puts"},
        {**base, "name": "puts", "source_binary": "ioputs.o!puts"},
    ]
    monkeypatch.setattr(
        g.analysis, "flirt_signatures_from_archive_path", lambda *_args: rows
    )

    built = build_library_from_archive(
        Path("libc.a"), library_name="glibc", version="test", variant="test", arch="armv7"
    )

    assert [entry["name"] for entry in built["entries"]] == ["puts"]
    assert built["stats"]["aliases_coalesced"] == 1
    assert built["stats"]["dropped_ambiguous"] == 0


def test_archive_builder_preserves_same_pattern_at_distinct_lengths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The matcher can resolve this collision from an exact function boundary."""
    base = {
        "prologue_hex": "aa" * 32,
        "mask_hex": "ff" * 32,
        "crc16": None,
        "crc_len": 0,
        "refs": [],
        "address": 0,
        "masked_bytes": 0,
    }
    rows = [
        {
            **base,
            "name": "puts",
            "member": "ioputs.o",
            "source_binary": "ioputs.o!puts",
            "function_len": 628,
        },
        {
            **base,
            "name": "other",
            "member": "other.o",
            "source_binary": "other.o!other",
            "function_len": 664,
        },
    ]
    monkeypatch.setattr(
        g.analysis, "flirt_signatures_from_archive_path", lambda *_args: rows
    )

    built = build_library_from_archive(
        Path("libc.a"),
        library_name="glibc",
        version="test",
        variant="test",
        arch="aarch64",
    )

    assert [(entry["name"], entry["function_len"]) for entry in built["entries"]] == [
        ("other", 664),
        ("puts", 628),
    ]
    assert built["stats"]["dropped_ambiguous"] == 0


def test_the_shipped_library_is_what_the_builder_produces(library: dict) -> None:
    """The committed file must be a rebuild of the committed archive.

    If it drifts, the tests that measure the shipped library are measuring
    something nobody can reproduce.
    """
    shipped = json.loads(SHIPPED.read_text())
    assert shipped["library"] == library["library"]
    assert shipped["entries"] == library["entries"]
    assert shipped["schema_version"] == library["schema_version"]


def test_a_non_archive_input_is_refused(tmp_path: Path) -> None:
    junk = tmp_path / "notanarchive.a"
    junk.write_bytes(b"this is not an ar archive")
    with pytest.raises(ValueError):
        build_library_from_archive(
            junk, library_name="x", version="0", variant="v", arch="x86_64"
        )


def test_archive_and_linked_roots_cannot_be_mixed(tmp_path: Path) -> None:
    """They are different input classes producing different schema versions;
    merging them would put unmasked and masked entries in one file with no way
    to tell which is which."""
    out = tmp_path / "lib.json"
    rc = main(["--archive", str(ARCHIVE), "--output", str(out), str(ARCHIVE)])
    assert rc == 2
    assert not out.exists()


def test_the_cli_writes_a_loadable_library(tmp_path: Path) -> None:
    out = tmp_path / "mathlib.json"
    rc = main(
        [
            "--archive",
            str(ARCHIVE),
            "--library-name",
            "mathlib",
            "--library-version",
            "1.0.0",
            "--variant",
            "gcc-15.2.0-O2",
            "--arch",
            "x86_64",
            "--output",
            str(out),
            "--quiet",
        ]
    )
    assert rc == 0
    written = json.loads(out.read_text())
    assert written["schema_version"] == SCHEMA_VERSION_MASKED
    assert len(written["entries"]) >= 15
    assert out.read_text().endswith("\n")


def test_the_native_extractor_reports_masked_byte_counts() -> None:
    """The binding is what the builder stands on; if it stops reporting
    relocations the builder emits all-fixed masks and nothing complains."""
    rows = g.analysis.flirt_signatures_from_archive_path(str(ARCHIVE))
    assert len(rows) >= 15
    assert sum(1 for r in rows if r["masked_bytes"] > 0) >= 15
    assert all(r["member"] == "mathlib.o" for r in rows)
