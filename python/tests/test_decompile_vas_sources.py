"""`--vas` accepts an inline list, a file, or stdin — and all three agree.

WHY THIS EXISTS. `--vas` took targets only as an argv string, so every caller
inherited `ARG_MAX`. DecBench's own adapter for us carries the consequence:

    # Above this many targets we skip the (command-line-length-bounded) --vas
    # form and decompile the whole binary, then narrow.
    _MAX_VAS_INLINE = 400        # decbench/decompilers/raw/glaurung_raw.py

Above 400 targets it stops asking us for specific functions and switches to
whole-binary mode. That is a *different code path answering the same question*,
and on a full-corpus run 55 of 803 binaries cross it — so those binaries were
scored through one route and the other 748 through another. The valve is also
far more conservative than the real bound: 400 hex VAs is ~3.6 KB against an
`ARG_MAX` of 2 MB, which would admit roughly 233,000 of them.

`@FILE` and `-` remove the bound rather than raising it, so no caller has to
split a target set, cap it, or switch strategies on target count — and the
downstream valve can be deleted rather than retuned.

These tests pin the property that makes that safe: the three sources are
interchangeable, not merely all functional.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/decompiler_fixtures/build/03_loop_shapes-gcc-O0.so"


def _run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "glaurung.cli", "decompile", *args],
        capture_output=True,
        text=True,
        input=stdin,
        cwd=ROOT,
        timeout=300,
    )


@pytest.fixture(scope="module")
def targets() -> str:
    """Three real entry VAs from the fixture, as the CLI reports them."""
    if not FIXTURE.exists():
        pytest.skip(f"fixture not built: {FIXTURE}")
    done = _run(
        [str(FIXTURE), "--all", "--limit", "4", "--style", "decbench", "--no-color"]
    )
    assert done.returncode == 0, done.stderr
    vas = [
        line.rsplit("@", 1)[1].strip()
        for line in done.stdout.splitlines()
        if line.startswith("// glaurung:") and "@ 0x" in line
    ][:3]
    assert len(vas) == 3, f"expected 3 entry VAs, parsed {vas!r}"
    return ",".join(vas)


def test_the_three_sources_produce_byte_identical_output(targets, tmp_path) -> None:
    """Interchangeable, not merely all functional.

    A caller switching to `@FILE` to escape ARG_MAX must not be switching to a
    different answer -- which is exactly the property the downstream valve
    fails, since it swaps `--vas` for whole-binary mode above 400 targets.
    """
    listing = tmp_path / "targets.txt"
    listing.write_text("\n".join(targets.split(",")) + "\n")

    inline = _run([str(FIXTURE), "--vas", targets, "--format", "json"])
    from_file = _run([str(FIXTURE), "--vas", f"@{listing}", "--format", "json"])
    from_stdin = _run([str(FIXTURE), "--vas", "-", "--format", "json"], stdin=targets)

    for label, done in (
        ("inline", inline),
        ("@file", from_file),
        ("stdin", from_stdin),
    ):
        assert done.returncode == 0, f"{label}: {done.stderr}"
    assert len(json.loads(inline.stdout)) == 3
    assert inline.stdout == from_file.stdout
    assert inline.stdout == from_stdin.stdout


def test_a_file_may_use_one_va_per_line_and_carry_comments(targets, tmp_path) -> None:
    """A generated target file should be able to record its own provenance.

    Otherwise the provenance lives in a second file that can drift from the
    addresses it describes.
    """
    listing = tmp_path / "targets.txt"
    listing.write_text(
        "# generated from DWARF low_pc\n"
        + "".join(f"{va}   # a function\n" for va in targets.split(","))
        + "\n# trailing comment\n"
    )
    done = _run([str(FIXTURE), "--vas", f"@{listing}", "--format", "json"])
    assert done.returncode == 0, done.stderr
    assert len(json.loads(done.stdout)) == 3


def test_errors_name_the_file_rather_than_the_flag(tmp_path) -> None:
    """`invalid VA in --vas` is not actionable when a harness generated the list.

    The message has to name the source so the caller knows which artifact to fix.
    """
    bad = tmp_path / "bad.txt"
    bad.write_text("0x1000\nnonsense\n")
    done = _run([str(FIXTURE), "--vas", f"@{bad}", "--format", "json"])
    assert done.returncode != 0
    said = done.stdout + done.stderr
    assert "nonsense" in said
    assert str(bad) in said

    missing = _run([str(FIXTURE), "--vas", "@/nonexistent/targets.txt"])
    assert missing.returncode != 0
    assert "/nonexistent/targets.txt" in missing.stdout + missing.stderr

    empty = tmp_path / "empty.txt"
    empty.write_text("# only a comment\n")
    done = _run([str(FIXTURE), "--vas", f"@{empty}", "--format", "json"])
    assert done.returncode != 0
    assert str(empty) in done.stdout + done.stderr


def test_a_target_set_far_past_the_downstream_valve_runs_in_one_pass() -> None:
    """The point of the feature: no cap, no split, no strategy switch.

    559 targets is 40% past `_MAX_VAS_INLINE`, the threshold that would
    otherwise divert this binary to whole-binary mode.
    """
    fixture = (
        ROOT / "tests/decompiler_fixtures/build/167_rust_trait_objects-rustc-O2.so"
    )
    if not fixture.exists():
        pytest.skip(f"fixture not built: {fixture}")
    import glaurung as g

    funcs, _ = g.analysis.analyze_functions_path(str(fixture))
    vas = [int(f.entry_point.value) for f in funcs]
    assert len(vas) > 400, f"fixture no longer exceeds the valve: {len(vas)} targets"

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        listing = Path(td) / "targets.txt"
        listing.write_text("\n".join(hex(v) for v in vas) + "\n")
        done = _run([str(fixture), "--vas", f"@{listing}", "--format", "json"])
    assert done.returncode == 0, done.stderr
    assert len(json.loads(done.stdout)) == len(vas)
