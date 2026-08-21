"""A binary larger than the read cap must not be analysed as if it were smaller.

`max_read_bytes` used to default to 10 MB on ten path-taking entry points while
`max_file_size` — the actual guard — was 100 MB. A 13 MB image was therefore not
rejected; it was *truncated to its first 10 MB* and analysed as though that were
the whole file. `analyze_functions_path` returned **one** function for a Rust
shared object with 715 `FUNC` symbols, in 8 ms, with no error, no warning, and
`hit_timeout` false.

Raising the cap on the same file: **633 functions, 1,176 seeds**.

The address-mapping entry points had the same default, which is worse than
missing functions — `va_to_file_offset_path`, `elf_got_map_path` and
`pe_iat_map_path` would return confidently wrong answers for any address past
the first 10 MB.

This is the regression test for that whole class. It asserts *behaviour on a
real oversized binary*, not the value of a constant, because a constant test
would pass while any single call site still passed a smaller explicit cap.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"

#: Anything comfortably past the old 10 MB cap. The Rust fixtures link the whole
#: standard library and land around 13 MB, which is why they exposed this.
OVERSIZED_MIN = 11 * 1024 * 1024


def _an_oversized_binary() -> Path | None:
    """The first built fixture larger than the old cap, if any exist."""
    if not BUILD.is_dir():
        return None
    for path in sorted(BUILD.glob("*.so")):
        if path.stat().st_size > OVERSIZED_MIN:
            return path
    return None


@pytest.fixture(scope="module")
def oversized() -> Path:
    path = _an_oversized_binary()
    if path is None:
        pytest.skip(
            f"no built fixture over {OVERSIZED_MIN // (1024 * 1024)} MB; "
            "the Rust lanes produce them (uv run python tools/dectest.py @o0)"
        )
    return path


def test_discovery_reads_past_the_old_ten_megabyte_cap(oversized):
    """The default must analyse the whole file, not its first 10 MB.

    One function from a multi-megabyte image is the signature of the truncation
    bug: the entry point is found and nothing else, because every other seed
    lived beyond the cut.
    """
    import glaurung

    functions, _cg = glaurung.analysis.analyze_functions_path(str(oversized))
    assert len(functions) > 1, (
        f"{oversized.name} is {oversized.stat().st_size / 1e6:.1f} MB and "
        f"discovery returned {len(functions)} function(s). That is the shape of "
        "a silent read truncation — check max_read_bytes against max_file_size."
    )


def test_the_default_matches_what_an_explicit_full_read_finds(oversized):
    """Calling with the default must equal calling with an explicit full cap.

    This is the assertion that cannot be satisfied by a truncating default: if
    the two disagree, the default is dropping part of the image.
    """
    import glaurung

    default_fns, _ = glaurung.analysis.analyze_functions_path(str(oversized))
    explicit_fns, _ = glaurung.analysis.analyze_functions_path(
        str(oversized), 104_857_600, 104_857_600
    )
    assert len(default_fns) == len(explicit_fns), (
        f"default read found {len(default_fns)} functions, an explicit 100 MB "
        f"read found {len(explicit_fns)} — the default is truncating "
        f"{oversized.name} ({oversized.stat().st_size / 1e6:.1f} MB)."
    )


def test_no_path_entry_point_caps_reads_below_the_file_size_guard():
    """`max_read_bytes` below `max_file_size` can only ever truncate silently.

    The file-size guard is what protects against an oversized input; a smaller
    read cap does not add safety, it just means the bytes past it are missing
    with nothing said. Checked as source text because these are PyO3 defaults
    with no runtime accessor.
    """
    bindings = (ROOT / "src" / "python_bindings" / "analysis.rs").read_text()
    offenders = [
        line.strip()[:120]
        for line in bindings.splitlines()
        if "max_read_bytes=10_485_760" in line
    ]
    assert not offenders, (
        "these entry points still cap reads at 10 MB while accepting files up "
        f"to 100 MB, so they truncate in silence:\n  " + "\n  ".join(offenders)
    )
