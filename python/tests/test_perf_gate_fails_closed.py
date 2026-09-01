"""The perf gate must not report success when it measured nothing comparable.

R6 increments A and G, and the reason G could not come first: scheduling a
fail-open gate manufactures assurance rather than providing it.

Three states used to `return 0` — indistinguishable, to any caller, from "no
regression":

* **P1** no baseline on disk;
* **P3** baseline and current run in different units (the wall-clock fallback
  on a host without usable `perf`, which is every GitHub runner —
  `kernel.perf_event_paranoid` blocks instruction counting);
* **P2** fewer references measured than the baseline records, because
  comparison iterates only current results, so a reference that failed to
  measure simply vanishes from the comparison.

That last one is the sharpest: measure one of three references and the gate
passes on a third of the evidence.

The contract now
----------------

Exit **3** means *this run is not evidence* — distinct from 0 (compared, no
regression) and 1 (compared, regression found). A developer bootstrapping a
baseline still gets a clear message; CI treats any non-zero as a failure, so
an unsupported runner is visibly not evidence rather than a pass.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
GATE = ROOT / "tools" / "perf_gate.py"

#: `--check` is not a real flag; the gate compares by default. Kept as a named
#: constant so the tests read as the contract rather than as invocations.
NOT_EVIDENCE = 3


def run_gate(tmp_baseline: Path | None, *extra: str) -> subprocess.CompletedProcess:
    """Invoke the gate with `PERF_BASELINE` pointed at a scratch file."""
    env = {**dict(**__import__("os").environ)}
    if tmp_baseline is not None:
        env["GLAURUNG_PERF_BASELINE"] = str(tmp_baseline)
    return subprocess.run(
        [sys.executable, str(GATE), "--allow-stale-build", *extra],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        timeout=1800,
        check=False,
    )


def test_the_gate_honours_an_overridable_baseline_path(tmp_path):
    """The tests below need to point the gate at a scratch baseline.

    Without this the only way to exercise the missing-baseline path would be to
    delete the committed one, which is not a thing a test may do.
    """
    text = GATE.read_text()
    assert "GLAURUNG_PERF_BASELINE" in text, (
        "perf_gate.py must let the baseline path be overridden by "
        "GLAURUNG_PERF_BASELINE so its failure states are testable without "
        "touching the committed baseline"
    )


def test_a_missing_baseline_is_not_a_pass(tmp_path):
    """P1. Absence of evidence is not evidence of no regression."""
    proc = run_gate(tmp_path / "absent.json")
    assert proc.returncode == NOT_EVIDENCE, (
        f"exit {proc.returncode}; a missing baseline used to return 0, which "
        f"is indistinguishable from a pass.\n{proc.stderr[-600:]}"
    )


def test_an_incomparable_unit_is_not_a_pass(tmp_path):
    """P3. The wall-clock fallback cannot be compared to instruction counts."""
    baseline = tmp_path / "wrong_unit.json"
    baseline.write_text(
        json.dumps(
            {
                "unit": "definitely-not-the-current-unit",
                "runs": 1,
                "measures": {"anything": 1},
            }
        )
    )
    proc = run_gate(baseline)
    assert proc.returncode == NOT_EVIDENCE, (
        f"exit {proc.returncode}; a unit mismatch used to print "
        f"'not comparable, skipping the gate' and return 0.\n{proc.stderr[-600:]}"
    )


def test_a_partial_measurement_is_not_a_pass(tmp_path):
    """P2. Measuring a subset of the references is not measuring them."""
    committed = json.loads((ROOT / "bench" / "perf_baseline.json").read_text())
    inflated = dict(committed)
    inflated["measures"] = {
        **committed["measures"],
        "a-reference-this-run-cannot-have-measured": 1,
    }
    baseline = tmp_path / "extra_reference.json"
    baseline.write_text(json.dumps(inflated))
    proc = run_gate(baseline)
    assert proc.returncode != 0, (
        f"exit 0 while the baseline records a reference this run did not "
        f"measure. Comparison iterates current results, so a reference that "
        f"failed to measure vanishes instead of failing.\n{proc.stderr[-600:]}"
    )
