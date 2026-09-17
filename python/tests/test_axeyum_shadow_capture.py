#!/usr/bin/env python3
"""Fail-closed tests for the shadow-split capture tier (solver-034).

A scripted stand-in for the ``ioctlance`` capture binary writes what the real
publisher writes -- content-addressed scripts, ``shadow-splits.tsv``,
``nondecisions.tsv``, ``disagreements/`` + ``disagreements.tsv``, ``malformed/``
+ ``malformed.tsv`` -- and prints the run summary lines the tool parses, so the
tier's three verdicts are checked without a solver or a driver on the machine:

* a split z3 decides and Axeyum does not is a **new row**, not a failure;
* a both-decided disagreement is a failure;
* a malformed export is a failure of the exporter;
* a run that prints no evidence line is a failure however it exited.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[2] / "tools" / "axeyum"
CAPTURE = TOOLS / "shadow_capture.py"
VERDICTS = TOOLS / "split_verdicts.py"

GOOD_SAT = b"(set-logic QF_BV)\n(declare-const x (_ BitVec 8))\n(assert (= x #x01))\n(check-sat)\n(get-model)\n"
GOOD_UNSAT = b"(set-logic QF_BV)\n; UNSAT\n(assert false)\n(check-sat)\n(get-model)\n"
NEW_SAT = b"(set-logic QF_BV)\n(declare-const y (_ BitVec 8))\n(assert (= y #x02))\n(check-sat)\n(get-model)\n"
BAD = b"(set-logic QF_BV)\n; MALFORMED\n(assert ((_ extract 63 8) #b0))\n(check-sat)\n"

FAKE_Z3 = """#!/bin/sh
if [ "$1" = "--version" ]; then echo "fake z3 0.0"; exit 0; fi
f="$2"
if grep -q MALFORMED "$f"; then echo '(error "line 3 column 9: invalid extract application")'
elif grep -q UNSAT "$f"; then echo unsat; echo '(error "line 4 column 10: model is not available")'
elif grep -q UNKNOWN "$f"; then echo unknown
else echo sat; echo '((x #x01))'
fi
"""

# The stand-in for a `solver-z3,solver-axeyum` ioctlance. FAKE_MODE (passed
# through --env) selects what it publishes; every mode prints the summary
# lines except `silent`.
FAKE_IOCTLANCE = f"""#!{sys.executable}
import hashlib, os, sys
from pathlib import Path
mode = os.environ.get("FAKE_MODE", "split")
out = Path(os.environ["GLAURUNG_DUMP_SHADOW_SPLITS"])
ceiling = os.environ.get("IOCTLANCE_SOLVE_SECS")
assert os.environ.get("GLAURUNG_FAIR_SHADOW") == "1", "fair shadow must be set"
assert "GLAURUNG_SHADOW_DIFF" not in os.environ, "inherited GLAURUNG_* must be stripped"
def publish(sub, payload, index, row):
    d = out / sub if sub else out
    d.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256(payload).hexdigest()
    (d / (h + ".smt2")).write_bytes(payload)
    with (out / index).open("a") as f:
        f.write(h + "\\t" + row + "\\n")
    return h
if mode == "silent":
    sys.exit(0)
if mode == "crash":
    print("[symbolic] boom", file=sys.stderr)
    sys.exit(3)
disagree = 0
if mode in ("split", "malformed", "disagree"):
    h = publish("", {NEW_SAT!r}, "shadow-splits.tsv", "sat\\tunknown")
    with (out / "nondecisions.tsv").open("a") as f:
        f.write(h + "\\taxeyum\\twall-timeout\\n")
if mode == "malformed":
    publish("malformed", {BAD!r}, "malformed.tsv", "sat\\terror\\tline 3 column 9: invalid extract application")
if mode == "disagree":
    publish("disagreements", {GOOD_UNSAT!r}, "disagreements.tsv", "unsat\\tsat")
    disagree = 1
queries = 0 if mode == "zero" else 10
print("[symbolic] 1.0s  raw=0 high-confidence=0 suppressed=0 (x)  analyzed=1/2", file=sys.stderr)
print("[shadow-diff] queries=%d agree=%d disagree=%d | SAME-STREAM z3=1.0ms axeyum=2.0ms speedup=0.5x" % (queries, queries - disagree, disagree), file=sys.stderr)
print("[model-choice] both-sat=5 different-model=1 | z3-unknown=0 axeyum-unknown=1 unknown-split=1", file=sys.stderr)
print("[axeyum-warm] checks=10 exact=1 prefix-roots=2 added=3 popped=4 resets=0 paths-created=1 paths-closed=1 paths-live=0 paths-peak=1 path-cap-fallbacks=0 assertion-cap-fallbacks=0 max-live-paths=9 max-assertions-per-path=512", file=sys.stderr)
print("ceiling=%s" % ceiling, file=sys.stderr)
"""


class ShadowCaptureTierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.top = Path(self.temporary.name)
        self.repo = self.top / "repo"
        (self.repo / ".git").mkdir(parents=True)
        (self.repo / "Cargo.lock").write_text(
            'name = "axeyum-solver"\nsource = "git+https://github.com/mjbommar/axeyum.git?rev=8df853252cdf49c9a27ba71c6ce62fdd1c485dfc#8df853252cdf49c9a27ba71c6ce62fdd1c485dfc"\n'
        )
        self.root = self.repo / "tests" / "corpora" / "axeyum-qfbv" / "shadow-splits"
        self.root.mkdir(parents=True)
        self.driver = self.top / "sqfs-intel-DptfDevGen.sys"
        self.driver.write_bytes(b"MZ fake driver")
        self.binary = self.top / "fake-ioctlance"
        self.binary.write_text(FAKE_IOCTLANCE, encoding="utf-8")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IEXEC)
        self.z3 = self.top / "fake-z3"
        self.z3.write_text(FAKE_Z3, encoding="utf-8")
        self.z3.chmod(self.z3.stat().st_mode | stat.S_IEXEC)
        # The pinned capture: one row, Axeyum decided it.
        self.pinned = self.root / "tcpip-60s-d60ed0f"
        self.pinned.mkdir()
        pinned_hash = hashlib.sha256(GOOD_SAT).hexdigest()
        (self.pinned / f"{pinned_hash}.smt2").write_bytes(GOOD_SAT)
        (self.pinned / "shadow-splits.tsv").write_text(f"{pinned_hash}\tunknown\tsat\n")
        (self.root / "verdicts.tsv").write_text(
            "# axeyum: pinned fixture\n# columns: capture\tsha256\tz3\taxeyum\n"
            f"tcpip-60s-d60ed0f\t{pinned_hash}\tsat\tsat\n"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def capture(self, mode: str, *extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "GLAURUNG_SHADOW_DIFF": "1",
        }
        return subprocess.run(
            [
                sys.executable,
                str(CAPTURE),
                "--binary",
                str(self.binary),
                "--root",
                str(self.root),
                "--driver",
                str(self.driver),
                "--ceiling",
                "60",
                "--revision",
                "0123456789abcdef",
                "--env",
                f"FAKE_MODE={mode}",
                "--log-dir",
                str(self.top / "logs"),
                "--report",
                str(self.top / "report.json"),
                *extra,
            ],
            check=False,
            text=True,
            capture_output=True,
            env=env,
        )

    def verdicts(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VERDICTS),
                str(self.root),
                "--z3",
                str(self.z3),
                "--jobs",
                "2",
                *extra,
            ],
            check=False,
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_a_split_z3_decides_and_axeyum_does_not_is_a_new_row_not_a_failure(
        self,
    ) -> None:
        result = self.capture("split")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        capture = self.root / "dptfdevgen-60s-0123456"
        self.assertTrue(capture.is_dir(), result.stdout)
        new_hash = hashlib.sha256(NEW_SAT).hexdigest()
        self.assertTrue((capture / f"{new_hash}.smt2").is_file())
        summary = json.loads((capture / "summary-v1.json").read_text())
        self.assertEqual(summary["distinct_queries"], 1)
        index = json.loads((capture / "capture-index-v1.json").read_text())
        self.assertEqual(index["files"][0]["expected"], "sat")
        meta = json.loads((capture / "capture-v1.json").read_text())
        self.assertEqual(meta["schema"], "glaurung-shadow-split-capture-v1")
        self.assertEqual(meta["producer"]["glaurung_revision"], "0123456789abcdef")
        self.assertEqual(
            meta["producer"]["axeyum_revision"],
            "8df853252cdf49c9a27ba71c6ce62fdd1c485dfc",
        )
        self.assertEqual(
            meta["driver"]["sha256"], hashlib.sha256(b"MZ fake driver").hexdigest()
        )
        self.assertEqual(meta["policy"]["solver_seconds_per_function"], 60)
        self.assertEqual(meta["run"]["queries"], 10)
        self.assertEqual(meta["nondecision_reasons"], {"axeyum:wall-timeout": 1})
        self.assertIn("reasons {'axeyum:wall-timeout': 1}", result.stdout)
        report = json.loads((self.top / "report.json").read_text())
        self.assertEqual(report["drivers"][0]["run"]["split_occurrences"], 1)
        # The gate then reports the new row by name and still exits 0.
        gate = self.verdicts()
        self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)
        self.assertIn(
            f"NEW: dptfdevgen-60s-0123456/{new_hash}\tz3 sat\taxeyum unmeasured",
            gate.stdout,
        )
        self.assertIn("new rows: 1 (1 axeyum undecided", gate.stdout)
        rows = [
            l.split("\t")
            for l in (self.root / "verdicts.tsv").read_text().splitlines()
            if not l.startswith("#")
        ]
        self.assertEqual(len(rows), 2)

    def test_a_both_decided_disagreement_fails_and_names_the_bytes(self) -> None:
        result = self.capture("disagree")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("DISAGREEMENT", result.stderr)
        self.assertIn("z3 unsat, axeyum sat", result.stderr)
        bad = hashlib.sha256(GOOD_UNSAT).hexdigest()
        self.assertTrue(
            (
                self.root / "dptfdevgen-60s-0123456" / "disagreements" / f"{bad}.smt2"
            ).is_file()
        )

    def test_a_malformed_export_fails_as_the_exporters_defect(self) -> None:
        result = self.capture("malformed")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MALFORMED export", result.stderr)
        self.assertIn("invalid extract application", result.stderr)
        self.assertIn("solver-016", result.stderr)

    def test_a_run_without_the_evidence_line_fails_whatever_its_exit_status(
        self,
    ) -> None:
        result = self.capture("silent")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not evidence", result.stderr)
        self.assertFalse((self.root / "dptfdevgen-60s-0123456").exists())
        result = self.capture("zero")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("queries=0", result.stderr)

    def test_a_crashed_driver_run_fails_with_its_exit_code(self) -> None:
        result = self.capture("crash")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("exited 3", result.stderr)

    def test_no_split_creates_no_capture_directory(self) -> None:
        result = self.capture("none")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no split; no capture directory created", result.stdout)
        self.assertFalse((self.root / "dptfdevgen-60s-0123456").exists())

    def test_an_existing_capture_directory_is_refused(self) -> None:
        (self.root / "dptfdevgen-60s-0123456").mkdir()
        result = self.capture("split")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("exists", result.stderr)

    def test_the_driver_token_can_be_named(self) -> None:
        result = self.capture("none", "--driver", f"dptf={self.driver}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("dptf: ", result.stdout)


if __name__ == "__main__":
    unittest.main()
