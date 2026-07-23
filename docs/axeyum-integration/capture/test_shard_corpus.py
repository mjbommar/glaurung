#!/usr/bin/env python3
"""Focused tests for deterministic physical corpus shards."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from shard_corpus import build_shards


class ShardCorpusTests(unittest.TestCase):
    def make_pack(self, root: Path, count: int = 128) -> Path:
        pack = root / "full"
        (pack / "queries").mkdir(parents=True)
        files = []
        for index in range(count):
            payload = f"(set-info :status sat)\n; {index}\n(check-sat)\n".encode()
            query_hash = hashlib.sha256(payload).hexdigest()
            relative = f"queries/{query_hash}.smt2"
            (pack / relative).write_bytes(payload)
            files.append(
                {
                    "path": relative,
                    "expected": "sat",
                    "family": "fixture",
                    "tiers": ["full"],
                }
            )
        capture = {
            "version": 1,
            "name": "fixture",
            "source": "test fixture",
            "logic": "QF_BV",
            "files": sorted(files, key=lambda row: row["path"]),
        }
        (pack / "capture-index-v1.json").write_text(json.dumps(capture) + "\n")
        return pack

    def test_shards_are_deterministic_disjoint_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = self.make_pack(root)
            shard_set = build_shards(pack, root / "shards", 4)
            paths = []
            for shard in shard_set["shards"]:
                directory = root / "shards" / shard["directory"]
                capture = json.loads((directory / "capture-index-v1.json").read_text())
                self.assertEqual({row["tiers"][0] for row in capture["files"]}, {shard["tier"]})
                paths.extend(row["path"] for row in capture["files"])
            self.assertEqual(len(paths), len(set(paths)))
            self.assertEqual(len(paths), shard_set["files"])

    def test_rejects_non_hash_free_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = self.make_pack(root)
            path = pack / "capture-index-v1.json"
            capture = json.loads(path.read_text())
            capture["files"][0]["content_hash"] = "sha256:" + "0" * 64
            path.write_text(json.dumps(capture) + "\n")
            with self.assertRaisesRegex(ValueError, "hash-free"):
                build_shards(pack, root / "shards", 4)


if __name__ == "__main__":
    unittest.main()
