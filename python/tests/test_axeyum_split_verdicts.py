#!/usr/bin/env python3
"""Fail-closed tests for split_verdicts.py, against a scripted stand-in for z3.

The stand-in answers by script content, so the tool's classification, the
prune, the ``verdicts.tsv`` it writes and its exit status are all checked
without a solver on the machine.
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


SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "axeyum" / "split_verdicts.py"

FAKE_Z3 = """#!/bin/sh
# Answers like z3 -T:N <file> would for the fixture scripts below.
if [ "$1" = "--version" ]; then
  echo "fake z3 0.0"
  exit 0
fi
f="$2"
if grep -q MALFORMED "$f"; then
  echo '(error "line 3 column 9: invalid extract application")'
elif grep -q UNSAT "$f"; then
  echo unsat
  echo '(error "line 4 column 10: model is not available")'
elif grep -q UNKNOWN "$f"; then
  echo unknown
else
  echo sat
  echo '((x #x01))'
fi
"""

GOOD_SAT = b"(set-logic QF_BV)\n(declare-const x (_ BitVec 8))\n(assert (= x #x01))\n(check-sat)\n(get-model)\n"
GOOD_UNSAT = b"(set-logic QF_BV)\n; UNSAT\n(assert false)\n(check-sat)\n(get-model)\n"
BAD = b"(set-logic QF_BV)\n; MALFORMED\n(assert ((_ extract 63 8) #b0))\n(check-sat)\n"
UNDECIDED = b"(set-logic QF_BV)\n; UNKNOWN\n(assert true)\n(check-sat)\n"


class SplitVerdictsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.z3 = self.root / "fake-z3"
        self.z3.write_text(FAKE_Z3, encoding="utf-8")
        self.z3.chmod(self.z3.stat().st_mode | stat.S_IEXEC)
        self.splits = self.root / "shadow-splits"
        self.splits.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_capture(
        self, name: str, rows: list[tuple[bytes, str, str]], sidecars: bool = True
    ) -> Path:
        capture = self.splits / name
        capture.mkdir()
        index = []
        for payload, z3_class, axeyum_class in rows:
            content_hash = hashlib.sha256(payload).hexdigest()
            (capture / f"{content_hash}.smt2").write_bytes(payload)
            index.append(f"{content_hash}\t{z3_class}\t{axeyum_class}\n")
        (capture / "shadow-splits.tsv").write_text("".join(index), encoding="utf-8")
        if sidecars:
            files = [
                {"path": f"{hashlib.sha256(p).hexdigest()}.smt2", "expected": "sat"}
                for p, _, _ in rows
            ]
            (capture / "manifest-v1.json").write_text(
                json.dumps({"name": name, "files": files}), encoding="utf-8"
            )
            (capture / "capture-index-v1.json").write_text(
                json.dumps(
                    {"version": 1, "name": name, "source": "test", "files": files}
                ),
                encoding="utf-8",
            )
            (capture / "capture-v1.json").write_text(
                json.dumps({"schema": "glaurung-shadow-split-capture-v1"}),
                encoding="utf-8",
            )
        return capture

    def run_tool(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.splits),
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

    @staticmethod
    def rows(path: Path) -> list[list[str]]:
        return [
            line.split("\t")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]

    def test_clean_corpus_writes_verdicts_and_exits_zero(self) -> None:
        self.make_capture(
            "drv-60s-abc",
            [(GOOD_SAT, "unknown", "sat"), (GOOD_UNSAT, "unsat", "unknown")],
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.rows(self.splits / "verdicts.tsv")
        self.assertEqual(len(rows), 2)
        self.assertEqual({row[2] for row in rows}, {"sat", "unsat"})
        self.assertEqual({row[3] for row in rows}, {"unmeasured"})

    def test_malformed_script_fails_the_gate_without_prune(self) -> None:
        self.make_capture(
            "drv-60s-abc", [(GOOD_SAT, "unknown", "sat"), (BAD, "sat", "error")]
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 malformed scripts z3 rejects", result.stderr)
        self.assertIn("invalid extract application", result.stderr)

    def test_undecided_script_fails_the_gate(self) -> None:
        self.make_capture(
            "drv-60s-abc", [(GOOD_SAT, "unknown", "sat"), (UNDECIDED, "unknown", "sat")]
        )
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("z3 unknown", result.stderr)

    def test_prune_moves_malformed_and_regenerates_sidecars(self) -> None:
        capture = self.make_capture(
            "drv-60s-abc",
            [
                (GOOD_SAT, "unknown", "sat"),
                (BAD, "sat", "error"),
                (GOOD_UNSAT, "unsat", "unknown"),
            ],
        )
        destination = self.root / "malformed"
        result = self.run_tool("--prune-to", str(destination))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bad_hash = hashlib.sha256(BAD).hexdigest()
        self.assertFalse((capture / f"{bad_hash}.smt2").exists())
        moved = destination / "drv-60s-abc"
        self.assertTrue((moved / f"{bad_hash}.smt2").is_file())
        self.assertEqual(
            (moved / "shadow-splits.tsv").read_text(encoding="utf-8"),
            f"{bad_hash}\tsat\terror\n",
        )
        malformed_rows = self.rows(moved / "malformed.tsv")
        self.assertEqual(malformed_rows[0][0], bad_hash)
        self.assertIn("invalid extract application", malformed_rows[0][1])
        # Live capture: index, sidecars and summary now describe two scripts.
        self.assertEqual(
            len((capture / "shadow-splits.tsv").read_text().splitlines()), 2
        )
        summary = json.loads((capture / "summary-v1.json").read_text())
        self.assertEqual(summary["distinct_queries"], 2)
        self.assertEqual(
            len(json.loads((capture / "manifest-v1.json").read_text())["files"]), 2
        )
        self.assertEqual(
            len(json.loads((capture / "capture-index-v1.json").read_text())["files"]), 2
        )
        pruned = json.loads((capture / "capture-v1.json").read_text())["pruned"]
        self.assertEqual(pruned["malformed_scripts"], 1)
        # The pruned tree passes the gate.
        self.assertEqual(self.run_tool().returncode, 0)

    def test_axeyum_results_fill_the_column_and_opposition_fails(self) -> None:
        self.make_capture(
            "drv-60s-abc",
            [(GOOD_SAT, "unknown", "sat"), (GOOD_UNSAT, "unsat", "unknown")],
        )
        sat_hash = hashlib.sha256(GOOD_SAT).hexdigest()
        unsat_hash = hashlib.sha256(GOOD_UNSAT).hexdigest()
        results = self.root / "axeyum.tsv"
        results.write_text(
            f"drv-60s-abc\t{sat_hash}\tsat\t12\ndrv-60s-abc\t{unsat_hash}\tunsat\t3\n"
        )
        result = self.run_tool(
            "--axeyum-results", str(results), "--axeyum-note", "fixture"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = {row[1]: row[3] for row in self.rows(self.splits / "verdicts.tsv")}
        self.assertEqual(rows, {sat_hash: "sat", unsat_hash: "unsat"})
        self.assertIn("# axeyum: fixture", (self.splits / "verdicts.tsv").read_text())
        # An Axeyum verdict opposing z3's is a failure, and is still recorded.
        results.write_text(f"drv-60s-abc\t{sat_hash}\tunsat\t12\n")
        result = self.run_tool("--axeyum-results", str(results))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("z3 sat but axeyum unsat", result.stderr)

    def test_a_pinned_decided_row_measured_undecided_is_a_regression(self) -> None:
        self.make_capture(
            "drv-60s-abc",
            [(GOOD_SAT, "unknown", "sat"), (GOOD_UNSAT, "unsat", "unknown")],
        )
        sat_hash = hashlib.sha256(GOOD_SAT).hexdigest()
        unsat_hash = hashlib.sha256(GOOD_UNSAT).hexdigest()
        results = self.root / "axeyum.tsv"
        results.write_text(
            f"drv-60s-abc\t{sat_hash}\tsat\t12\ndrv-60s-abc\t{unsat_hash}\tunsat\t3\n"
        )
        self.assertEqual(self.run_tool("--axeyum-results", str(results)).returncode, 0)
        # The floor is the committed decided column; losing one is a failure.
        results.write_text(
            f"drv-60s-abc\t{sat_hash}\tsat\t12\ndrv-60s-abc\t{unsat_hash}\tunknown:WallTimeout\t30000\n"
        )
        result = self.run_tool("--axeyum-results", str(results))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            f"drv-60s-abc/{unsat_hash}: REGRESSION pinned axeyum unsat (z3 unsat), now unknown:WallTimeout",
            result.stderr,
        )
        # The regressed verdict is recorded, so the file names what was measured.
        rows = {row[1]: row[3] for row in self.rows(self.splits / "verdicts.tsv")}
        self.assertEqual(rows[unsat_hash], "unknown:WallTimeout")

    def test_a_new_undecided_row_is_reported_not_failed_and_a_decided_one_is_promoted(
        self,
    ) -> None:
        self.make_capture("drv-60s-abc", [(GOOD_SAT, "unknown", "sat")])
        sat_hash = hashlib.sha256(GOOD_SAT).hexdigest()
        results = self.root / "axeyum.tsv"
        results.write_text(f"drv-60s-abc\t{sat_hash}\tsat\t12\n")
        self.assertEqual(self.run_tool("--axeyum-results", str(results)).returncode, 0)
        # A second capture lands a script with no committed row.
        self.make_capture("drv-60s-def", [(GOOD_UNSAT, "unsat", "unknown")])
        unsat_hash = hashlib.sha256(GOOD_UNSAT).hexdigest()
        results.write_text(
            f"drv-60s-abc\t{sat_hash}\tsat\t12\ndrv-60s-def\t{unsat_hash}\tunknown:WallTimeout\t30000\n"
        )
        result = self.run_tool("--axeyum-results", str(results))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"NEW: drv-60s-def/{unsat_hash}\tz3 unsat\taxeyum unknown:WallTimeout",
            result.stdout,
        )
        self.assertIn(
            "new rows: 1 (1 axeyum undecided: capability gaps, not failures)",
            result.stdout,
        )
        # Not in the floor: a later run that still cannot decide it is not a regression...
        result = self.run_tool("--axeyum-results", str(results))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("new rows: 0", result.stdout)
        # ...and one that decides it promotes it into the floor.
        results.write_text(
            f"drv-60s-abc\t{sat_hash}\tsat\t12\ndrv-60s-def\t{unsat_hash}\tunsat\t40\n"
        )
        result = self.run_tool("--axeyum-results", str(results))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"PROMOTED: drv-60s-def/{unsat_hash}\tz3 unsat\taxeyum unsat (was unknown:WallTimeout)",
            result.stdout,
        )
        rows = {row[1]: row[3] for row in self.rows(self.splits / "verdicts.tsv")}
        self.assertEqual(rows[unsat_hash], "unsat")
        # Now it IS in the floor.
        results.write_text(
            f"drv-60s-abc\t{sat_hash}\tsat\t12\ndrv-60s-def\t{unsat_hash}\tunknown:Other\t40\n"
        )
        result = self.run_tool("--axeyum-results", str(results))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REGRESSION", result.stderr)

    def test_check_mode_detects_drift_and_writes_nothing(self) -> None:
        self.make_capture("drv-60s-abc", [(GOOD_SAT, "unknown", "sat")])
        self.assertEqual(self.run_tool().returncode, 0)
        verdicts = self.splits / "verdicts.tsv"
        before = verdicts.read_text()
        self.assertEqual(self.run_tool("--check").returncode, 0)
        verdicts.write_text(before.replace("\tsat\tunmeasured", "\tunsat\tunmeasured"))
        result = self.run_tool("--check")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("verdicts.tsv says z3 unsat, z3 now says sat", result.stderr)
        self.assertNotEqual(
            verdicts.read_text(), before, "--check must not rewrite the file"
        )


if __name__ == "__main__":
    unittest.main()
