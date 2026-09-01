"""`samples/` carries the same bytes more than once, and must not carry more.

The measurement
---------------

75 groups of byte-identical files, **22.4 MB** of redundant content. The
largest single pair is `hello-rust-debug` at 4.5 MB, present under both
`platforms/linux/amd64/rust/` and `platforms/linux/amd64/export/rust/`.

This corrects `docs/test-inventory/findings.md`, which recorded "18.8 MB, 85
byte-identical pairs between `samples/binaries/linux/amd64/export/` and the
legacy tree". That legacy tree **no longer exists** -- the count is stale and
the location was wrong. The duplication that remains is between the `export/`
subtree and its siblings under `platforms/linux/amd64/`, and it is larger than
recorded, not smaller.

Why this ratchets rather than deletes
-------------------------------------

Of the 75 groups, 6 have every copy referenced by literal path and would need
repointing. The other 123 redundant copies are referenced by no literal path --
which is **not** proof they are unused: much of the suite globs over
`samples/**` rather than naming files, so deleting them would silently shrink
test populations instead of failing. A corpus deletion of that size wants a
deliberate decision about which tree is canonical, not a sweep.

So this pins the current state. New duplication fails; the existing 22.4 MB is
recorded as accepted with its inventory, and the number only ever comes down.
"""

from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLES = ROOT / "samples"
BASELINE = ROOT / "tests" / "sample_duplication_baseline.json"

#: Files below this are pointer stubs, READMEs and trivia; hashing them adds
#: runtime and noise without adding duplication that costs anything.
MIN_BYTES = 1024


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def duplicate_groups() -> dict[str, list[str]]:
    by_hash: dict[str, list[str]] = collections.defaultdict(list)
    for p in SAMPLES.rglob("*"):
        if p.is_file() and p.stat().st_size >= MIN_BYTES:
            by_hash[digest(p)].append(str(p.relative_to(ROOT)))
    return {h: sorted(v) for h, v in by_hash.items() if len(v) > 1}


def redundant_bytes(groups: dict[str, list[str]]) -> int:
    """Bytes that would be reclaimed if each group kept exactly one copy."""
    total = 0
    for paths in groups.values():
        size = (ROOT / paths[0]).stat().st_size
        total += size * (len(paths) - 1)
    return total


@pytest.fixture(scope="module")
def measured() -> dict[str, list[str]]:
    if not SAMPLES.is_dir():
        pytest.skip("samples/ absent")
    groups = duplicate_groups()
    if not groups:
        pytest.skip("no files of substance present (unfetched LFS checkout?)")
    return groups


def test_the_baseline_exists():
    assert BASELINE.is_file(), (
        f"{BASELINE.name} is missing. Regenerate with "
        "`uv run python tools/gen_sample_duplication_baseline.py`."
    )


def test_no_new_duplicate_groups(measured):
    """The ratchet. A new byte-identical pair must be deliberate."""
    recorded = json.loads(BASELINE.read_text())
    assert len(measured) <= recorded["groups"], (
        f"duplicate groups {recorded['groups']} -> {len(measured)}. Some file "
        "was added that already exists byte-for-byte elsewhere under samples/. "
        "Reference the existing path instead, or regenerate the baseline if "
        "the new copy is genuinely needed."
    )


def test_redundant_bytes_do_not_grow(measured):
    recorded = json.loads(BASELINE.read_text())
    now = redundant_bytes(measured)
    assert now <= recorded["redundant_bytes"], (
        f"redundant bytes {recorded['redundant_bytes']:,} -> {now:,} "
        f"(+{now - recorded['redundant_bytes']:,}). Every byte here is stored "
        "twice in git LFS and fetched twice by CI."
    )


def test_the_baseline_is_not_stale_in_the_direction_that_matters(measured):
    """If duplication has been REDUCED, the baseline must be tightened.

    A ratchet that silently tolerates improvement stops measuring: the next
    regression is compared against a number nobody meant.
    """
    recorded = json.loads(BASELINE.read_text())
    now = redundant_bytes(measured)
    assert now >= recorded["redundant_bytes"] - 1024, (
        f"duplication dropped {recorded['redundant_bytes']:,} -> {now:,}. "
        "Good -- now regenerate the baseline so the gain is locked in: "
        "`uv run python tools/gen_sample_duplication_baseline.py`."
    )


def test_the_largest_group_is_still_the_one_we_think_it_is(measured):
    """A named landmark, so the report stays legible as the corpus changes."""
    largest = max(measured.values(), key=lambda ps: (ROOT / ps[0]).stat().st_size)
    assert any("hello-rust-debug" in p for p in largest), (
        f"largest duplicate group is now {largest}; update this landmark and "
        "the module docstring."
    )
