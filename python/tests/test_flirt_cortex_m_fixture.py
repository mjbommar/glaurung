"""The Cortex-M (bare metal) half of the FLIRT signature builder.

Companion to `test_flirt_library_builder.py` (ELF/x86_64, `libmathlib.a`) and
the COFF tests inside it. This file exercises the same builder against a real
**Thumb-2** newlib archive: `tests/fixtures/flirt/armtc/`, three objects
extracted from the ARM GNU Toolchain 13.2.Rel1's
`arm-none-eabi/lib/thumb/v7e-m+fp/hard/libc.a`. See that directory's
`README.md` for provenance and licence.

The point of this fixture, specifically, is a relocation **inside** the
32-byte pattern window (`R_ARM_ABS32`-flavoured `MOVW`/`MOVT` halves loading
`_ctype_`) rather than only past-function-end padding, which is what every
other fixture in this repository happens to exercise for ARM so far
(`src/flirt/archive.rs`'s own unit tests use a synthetic COFF fixture, not a
real Thumb-2 object).

A broader validation -- naming recall against real Cortex-M firmware --
lives in `docs/reference/function-signature-libraries.md`, "Cortex-M (bare
metal)", run via `tools/build_armtc_signatures.py` and
`tools/validate_cortex_m_signatures.py` against the NAS-hosted toolchain and
firmware corpora (`$GLAURUNG_ARMTC`, `/nas4/data/binary-analysis/...`); those
are not part of the pytest suite because they read paths outside the
repository and outside CI's reach.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from glaurung.tools.build_flirt_library import (
    PROLOGUE_LEN,
    SCHEMA_VERSION_MASKED,
    build_library_from_archive,
)

REPO = Path(__file__).resolve().parents[2]
ARCHIVE = REPO / "tests/fixtures/flirt/armtc/newlib_subset.thumb-v7e-m-fp-hard.a"

sys.path.insert(0, str(REPO / "tools"))
import harvest_armtc  # ty: ignore[unresolved-import]  # added above


@pytest.fixture(scope="module")
def library() -> dict:
    assert ARCHIVE.is_file(), (
        f"{ARCHIVE} is committed, not generated; its absence means the fixtures "
        "tree was pruned. See tests/fixtures/flirt/armtc/README.md to rebuild."
    )
    return build_library_from_archive(
        ARCHIVE,
        library_name="newlib",
        version="4.3.0",
        variant="arm-gnu-13.2.1-thumb-v7e-m+fp-hard",
        arch="armv7",
    )


def test_the_archive_yields_three_signatures(library: dict) -> None:
    """tolower, toupper and memset -- one function each, nothing dropped."""
    assert library["schema_version"] == SCHEMA_VERSION_MASKED
    assert library["prologue_len"] == PROLOGUE_LEN
    assert library["library"] == {
        "name": "newlib",
        "version": "4.3.0",
        "variant": "arm-gnu-13.2.1-thumb-v7e-m+fp-hard",
        "arch": "armv7",
    }
    names = sorted(e["name"] for e in library["entries"])
    assert names == ["memset", "tolower", "toupper"]
    assert library["stats"]["dropped_ambiguous"] == 0


def _entry(library: dict, name: str) -> dict:
    return next(e for e in library["entries"] if e["name"] == name)


def test_tolower_and_toupper_are_masked_by_a_relocation_inside_the_pattern(
    library: dict,
) -> None:
    """The Thumb-2 case this fixture exists for: a relocation at offset 16,
    not only variant bytes past the function's own end.

    `tolower`/`toupper` are each 20 bytes long, so bytes [20, 32) are variant
    for the ordinary "past the end of the function" reason
    (`src/flirt/archive.rs`) -- that alone would be 12 variant bytes. Both
    entries mask 16, so 4 more bytes inside the *live* function body are
    variant: the `MOVW`/`MOVT` halves of the `R_ARM_ABS32` relocation loading
    `_ctype_`.
    """
    for name in ("tolower", "toupper"):
        entry = _entry(library, name)
        assert entry["function_len"] == 20, name
        mask = bytes.fromhex(entry["mask_hex"])
        assert len(mask) == PROLOGUE_LEN
        variant_bytes = sum(1 for b in mask if b == 0)
        assert variant_bytes == 16, (
            f"{name}: expected 16 variant bytes, got {variant_bytes}"
        )
        # The tail (past byte 20) is unconditionally variant; the relocation
        # inside the body accounts for the other 4.
        tail_variant = sum(1 for b in mask[20:] if b == 0)
        assert tail_variant == 12, name
        body_variant = sum(1 for b in mask[:20] if b == 0)
        assert body_variant == 4, (
            f"{name}: expected the MOVW/MOVT relocation to mask 4 bytes inside "
            f"the function body, got {body_variant}"
        )


def test_tolower_and_toupper_reference_ctype_without_colliding(library: dict) -> None:
    """Both reference the same symbol but are not ambiguous.

    They share a `_ctype_` reference at the same offset, yet their *fixed*
    bytes differ (the `'a'`..`'z'` vs `'A'`..`'Z'` range-check immediates are
    not masked), so the ambiguity check -- keyed on the masked pattern, not
    the reference list -- correctly keeps both as distinct entries.
    """
    tolower = _entry(library, "tolower")
    toupper = _entry(library, "toupper")
    assert tolower["prologue_hex"] != toupper["prologue_hex"]
    for entry in (tolower, toupper):
        assert entry["refs"] == [{"offset": 16, "name": "_ctype_"}]


def test_memset_is_relocation_free_and_crc_bearing(library: dict) -> None:
    """The control: no relocation in its pattern, so the CRC over what
    follows is what a real relink can still rely on."""
    memset = _entry(library, "memset")
    assert memset["mask_hex"] == "ff" * PROLOGUE_LEN
    assert memset["crc_len"] > 0
    assert isinstance(memset["crc16"], int)
    assert memset["refs"] == []


def test_the_build_is_deterministic(library: dict) -> None:
    again = build_library_from_archive(
        ARCHIVE,
        library_name="newlib",
        version="4.3.0",
        variant="arm-gnu-13.2.1-thumb-v7e-m+fp-hard",
        arch="armv7",
    )
    assert json.dumps(again, sort_keys=True) == json.dumps(library, sort_keys=True)


def test_harvest_armtc_reads_the_real_toolchain_identity() -> None:
    """Integration check against the live NAS toolchain, gated and skipped
    loudly when `GLAURUNG_ARMTC` is not set -- this box's toolchain root is
    not something CI or another machine can be expected to have.
    """
    root = os.environ.get("GLAURUNG_ARMTC")
    if not root:
        pytest.skip("GLAURUNG_ARMTC not set; skipping the live toolchain check")

    identity = harvest_armtc.toolchain_identity(Path(root))
    assert identity["gcc_version"], identity
    assert identity["newlib_version"], identity
    assert Path(identity["license_file"]).is_file()
