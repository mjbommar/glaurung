#!/usr/bin/env python3
"""Focused fail-closed tests for build_corpus.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build_corpus.py")


class BuildCorpusTests(unittest.TestCase):
    def make_raw(self, root: Path, payloads: list[tuple[bytes, str]]) -> Path:
        raw = root / "raw"
        raw.mkdir()
        rows = []
        for payload, verdict in payloads:
            query_hash = hashlib.sha256(payload).hexdigest()
            (raw / f"{query_hash}.smt2").write_bytes(payload)
            rows.append(f"{query_hash}\t{verdict}\n")
        (raw / "index.tsv").write_text("".join(rows), encoding="utf-8")
        return raw

    def run_builder(self, raw: Path, out: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(raw),
                str(out),
                "2",
                "--source",
                "test revision; driver fixture",
            ],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_emits_hash_free_reconciled_capture_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = self.make_raw(
                root,
                [
                    (b"(set-logic QF_BV)\n(assert true)\n(check-sat)\n", "sat"),
                    (b"(set-logic QF_BV)\n(assert false)\n(check-sat)\n", "unsat"),
                ],
            )
            result = self.run_builder(raw, root / "out")
            self.assertEqual(result.returncode, 0, result.stderr)
            capture = json.loads((root / "out" / "capture-index-v1.json").read_text())
            self.assertEqual(len(capture["files"]), 2)
            self.assertNotIn("content_hash", capture["files"][0])
            self.assertIn("zero exclusions", capture["source"])

    def test_rejects_conflicting_duplicate_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = self.make_raw(root, [(b"(check-sat)\n", "sat")])
            query_hash = next(raw.glob("*.smt2")).stem
            with (raw / "index.tsv").open("a", encoding="utf-8") as index:
                index.write(f"{query_hash}\tunsat\n")
            result = self.run_builder(raw, root / "out")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("verdict conflict", result.stderr)

    def test_rejects_filename_content_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = self.make_raw(root, [(b"(check-sat)\n", "sat")])
            next(raw.glob("*.smt2")).write_bytes(b"changed\n")
            result = self.run_builder(raw, root / "out")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("content hash mismatch", result.stderr)

    def test_rejects_unindexed_script(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = self.make_raw(root, [(b"(check-sat)\n", "sat")])
            payload = b"(check-sat) ; orphan\n"
            (raw / f"{hashlib.sha256(payload).hexdigest()}.smt2").write_bytes(payload)
            result = self.run_builder(raw, root / "out")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unindexed scripts", result.stderr)


if __name__ == "__main__":
    unittest.main()
