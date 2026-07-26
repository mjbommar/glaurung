"""The heavy gate must not be able to pass while its metric lane is absent.

This is a regression test for a specific, expensive failure. `scripts/decbench-local-gate.sh`
lane 3 is the only lane that scores GED / type_match / byte_match. It used to print

    SKIPPED: DECBENCH_DIR is not set.
    ...
    Skipping is a gap, not a pass.

and then exit 0. The DecBench checkout had been made inside a per-session scratchpad,
so `DECBENCH_DIR` came up unset on a later session, lane 3 skipped on every run, and a
session's worth of semantic changes regressed ~25 of 56 metric cells — `matrix:gcc:O0`
from 3.0 to 15.0 — while the gate stayed green and the changes were reported as having
"no regressions".

The note was accurate and prominent. It was read, quoted in a design document, and
ignored anyway. So the note is not the fix: the exit code is.

These tests only inspect the script's control flow. They deliberately do NOT run the
gate — lane 3 alone takes ~37 minutes, since each of the 56 cells spawns a Joern JVM
to compute a graph edit distance.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
GATE = ROOT / "scripts" / "decbench-local-gate.sh"


def _text() -> str:
    assert GATE.is_file(), f"gate script missing: {GATE}"
    return GATE.read_text()


def test_a_missing_metric_lane_sets_the_failure_flag():
    """The absent-checkout branch must set `fail=1`, not merely narrate."""
    text = _text()
    # The branch that handles a missing DECBENCH_DIR, up to the `elif`.
    m = re.search(r'if \[ ! -d "\$DECBENCH_DIR" \];(.*?)^elif ', text, re.S | re.M)
    assert m, "expected a `[ ! -d $DECBENCH_DIR ]` guard on lane 3"
    branch = m.group(1)
    assert "fail=1" in branch, (
        "a missing metric lane must set fail=1. Printing a warning and exiting 0 is "
        "what let ~25 cells regress behind a green gate:\n" + branch
    )


def test_the_waiver_is_explicit_and_reported_in_the_final_line():
    """A deliberate waiver is allowed; a silent one is not.

    The old note appeared mid-output, where it scrolled past several hundred lines of
    pytest before the summary. If metrics are waived, the LAST line has to say so,
    because that is the line a human actually reads.
    """
    text = _text()
    assert "GLAURUNG_ALLOW_NO_METRICS" in text, (
        "there must be an explicit opt-out, so that skipping is a decision rather "
        "than an accident"
    )
    final = re.search(r'if \[ -n "\$waived" \]; then\s*\n\s*echo "([^"]+)"', text)
    assert final, "expected a distinct final line for the waived case"
    msg = final.group(1)
    for token in ("WITHOUT METRICS", "waived"):
        assert token in msg, (
            f"the final line must make an unmeasured pass unmistakable; {token!r} "
            f"missing from {msg!r}"
        )


def test_the_success_line_does_not_claim_more_than_it_ran():
    """The old success line was `passed (see any SKIPPED notes above)`.

    That reads as a pass and buries the caveat in a parenthetical pointing at output
    the reader has already scrolled past. The unqualified success line must only be
    reachable when all three lanes actually ran.
    """
    text = _text()
    assert "see any SKIPPED notes above" not in text, (
        "the old hedged success line is back; a pass must not carry a caveat that "
        "points at earlier output"
    )
    assert 'echo "HEAVY GATE: passed (all three lanes ran)"' in text, (
        "the unqualified pass must state that all three lanes ran"
    )


def test_decbench_dir_defaults_so_the_normal_path_needs_no_setup():
    """The failure mode was an unset variable, so the default is part of the fix.

    Requiring every caller to remember an environment variable is what produced the
    gap. The durable checkout path is defaulted; an explicit DECBENCH_DIR still wins.
    """
    text = _text()
    assert re.search(r':\s*"\$\{DECBENCH_DIR:=', text), (
        "DECBENCH_DIR must have a default (`:= `), not be left unset"
    )
    assert "export" in text and "DECBENCH_DIR" in text, (
        "DECBENCH_DIR must be exported so tools/decbench_matrix.py sees it"
    )
