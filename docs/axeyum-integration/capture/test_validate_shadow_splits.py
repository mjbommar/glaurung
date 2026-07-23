#!/usr/bin/env python3
"""Focused fail-closed tests for validate_shadow_splits.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("validate_shadow_splits.py")


class ValidateShadowSplitsTests(unittest.TestCase):
    def make_capture(
        self,
        root: Path,
        rows: list[tuple[bytes, str, str]],
    ) -> Path:
        capture = root / "capture"
        capture.mkdir()
        index = []
        for payload, z3_class, axeyum_class in rows:
            content_hash = hashlib.sha256(payload).hexdigest()
            (capture / f"{content_hash}.smt2").write_bytes(payload)
            index.append(f"{content_hash}\t{z3_class}\t{axeyum_class}\n")
        (capture / "shadow-splits.tsv").write_text("".join(index), encoding="utf-8")
        return capture

    def run_validator(
        self, capture: Path, *extra: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(capture), *extra],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_validates_complete_split_inventory_and_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = self.make_capture(
                root,
                [
                    (
                        b"(set-logic QF_BV)\n(assert true)\n(check-sat)\n",
                        "sat",
                        "error",
                    ),
                    (
                        b"(set-logic QF_BV)\n(assert false)\n(check-sat)\n",
                        "unknown",
                        "unsat",
                    ),
                ],
            )
            summary_path = root / "summary.json"
            result = self.run_validator(capture, "--summary-out", str(summary_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["schema"], "glaurung-shadow-split-summary-v1")
            self.assertEqual(summary["distinct_queries"], 2)
            self.assertEqual(
                summary["class_pairs"], {"sat/error": 1, "unknown/unsat": 1}
            )
            self.assertEqual(summary["decided_by"], {"axeyum": 1, "z3": 1})
            self.assertEqual(
                summary["content_bytes"],
                sum(path.stat().st_size for path in capture.glob("*.smt2")),
            )

    def test_emits_hash_free_diagnostic_capture_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = self.make_capture(
                root,
                [
                    (b"(check-sat)\n", "sat", "error"),
                    (b"(assert false)\n(check-sat)\n", "unknown", "unsat"),
                    (b"(assert true)\n(check-sat)\n", "unsat", "unknown"),
                ],
            )
            capture_index = root / "capture-index-v1.json"
            result = self.run_validator(
                capture,
                "--capture-index-out",
                str(capture_index),
                "--source",
                "test revisions and policy",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            index = json.loads(capture_index.read_text(encoding="utf-8"))
            self.assertEqual(index["logic"], "QF_BV")
            self.assertEqual(len(index["files"]), 3)
            self.assertNotIn("content_hash", index["files"][0])
            self.assertEqual(
                {row["expected"] for row in index["files"]}, {"sat", "unsat"}
            )
            self.assertEqual(
                {row["family"] for row in index["files"]},
                {"shadow-axeyum-decided", "shadow-z3-decided"},
            )
            self.assertEqual(
                sum("representative" in row["tiers"] for row in index["files"]),
                3,
            )
            error_rows = [
                row for row in index["files"] if "axeyum-error" in row["tiers"]
            ]
            self.assertEqual(len(error_rows), 1)
            self.assertIn("axeyum-error-representative", error_rows[0]["tiers"])

    def test_requires_source_for_capture_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = self.make_capture(root, [(b"(check-sat)\n", "sat", "error")])
            result = self.run_validator(
                capture, "--capture-index-out", str(root / "capture-index-v1.json")
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--source", result.stderr)

    def test_rejects_filename_content_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = self.make_capture(root, [(b"(check-sat)\n", "sat", "error")])
            next(capture.glob("*.smt2")).write_bytes(b"changed\n")
            result = self.run_validator(capture)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("content hash mismatch", result.stderr)

    def test_rejects_orphaned_script(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = self.make_capture(root, [(b"(check-sat)\n", "sat", "error")])
            orphan = b"(check-sat) ; orphan\n"
            (capture / f"{hashlib.sha256(orphan).hexdigest()}.smt2").write_bytes(orphan)
            result = self.run_validator(capture)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unindexed scripts", result.stderr)

    def test_rejects_pair_without_exactly_one_decided_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for z3_class, axeyum_class in (("sat", "unsat"), ("unknown", "error")):
                with self.subTest(z3_class=z3_class, axeyum_class=axeyum_class):
                    capture = self.make_capture(
                        root, [(b"(check-sat)\n", z3_class, axeyum_class)]
                    )
                    result = self.run_validator(capture)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("exactly one decided backend", result.stderr)
                    for child in capture.iterdir():
                        child.unlink()
                    capture.rmdir()

    def test_rejects_duplicate_or_conflicting_hash_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = self.make_capture(root, [(b"(check-sat)\n", "sat", "error")])
            row = (capture / "shadow-splits.tsv").read_text(encoding="utf-8")
            with (capture / "shadow-splits.tsv").open("a", encoding="utf-8") as index:
                index.write(row)
            result = self.run_validator(capture)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate hash row", result.stderr)

            content_hash = row.split("\t", 1)[0]
            (capture / "shadow-splits.tsv").write_text(
                row + f"{content_hash}\tunsat\tunknown\n", encoding="utf-8"
            )
            result = self.run_validator(capture)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("conflicting hash row", result.stderr)


if __name__ == "__main__":
    unittest.main()
