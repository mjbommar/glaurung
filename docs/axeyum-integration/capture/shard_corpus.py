#!/usr/bin/env python3
"""Partition one strict full capture-index pack into physical process shards."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil


HASH_RE = re.compile(r"[0-9a-f]{64}")


def materialize(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def load_capture_index(pack: Path) -> tuple[dict[str, object], bytes]:
    index_path = pack / "capture-index-v1.json"
    payload = index_path.read_bytes()
    value = json.loads(payload)
    if not isinstance(value, dict) or set(value) != {"version", "name", "source", "logic", "files"}:
        raise ValueError("capture index root must contain exactly version/name/source/logic/files")
    if value["version"] != 1 or value["logic"] != "QF_BV":
        raise ValueError("capture index must be manifest-v1 QF_BV")
    if not isinstance(value["name"], str) or not value["name"].strip():
        raise ValueError("capture index name must be non-empty")
    if not isinstance(value["source"], str) or not value["source"].strip():
        raise ValueError("capture index source must be non-empty")
    if not isinstance(value["files"], list) or not value["files"]:
        raise ValueError("capture index files must be a non-empty array")

    seen: set[str] = set()
    for index, row in enumerate(value["files"]):
        if not isinstance(row, dict) or set(row) != {"path", "expected", "family", "tiers"}:
            raise ValueError(f"files[{index}] must be a hash-free capture-index entry")
        path = row["path"]
        if not isinstance(path, str):
            raise ValueError(f"files[{index}].path must be a string")
        pure = PurePosixPath(path)
        if pure.parts != ("queries", pure.name) or pure.suffix != ".smt2":
            raise ValueError(f"files[{index}].path is not normalized queries/HASH.smt2: {path}")
        if HASH_RE.fullmatch(pure.stem) is None:
            raise ValueError(f"files[{index}].path does not carry a lowercase SHA-256: {path}")
        if path in seen:
            raise ValueError(f"duplicate capture-index path: {path}")
        seen.add(path)
        if row["expected"] not in {"sat", "unsat"}:
            raise ValueError(f"files[{index}].expected must be sat or unsat")
        if not isinstance(row["family"], str) or not row["family"]:
            raise ValueError(f"files[{index}].family must be non-empty")
        if row["tiers"] != ["full"]:
            raise ValueError(f"files[{index}] must belong only to the full tier")

    disk = {
        path.relative_to(pack).as_posix()
        for path in (pack / "queries").glob("*.smt2")
    }
    if disk != seen:
        missing = sorted(seen - disk)
        unlisted = sorted(disk - seen)
        raise ValueError(f"capture-index membership mismatch: missing={missing} unlisted={unlisted}")
    return value, payload


def build_shards(pack: Path, out: Path, shard_count: int) -> dict[str, object]:
    if shard_count < 2:
        raise ValueError("--shards must be at least 2")
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"output directory must be absent or empty: {out}")
    capture, capture_bytes = load_capture_index(pack)
    buckets: list[list[dict[str, object]]] = [[] for _ in range(shard_count)]
    for row in capture["files"]:
        query_hash = PurePosixPath(row["path"]).stem
        shard = int(query_hash[:16], 16) % shard_count
        buckets[shard].append(row)
    if any(not bucket for bucket in buckets):
        raise ValueError("deterministic partition produced an empty shard")

    width = max(2, len(str(shard_count - 1)))
    source_digest = hashlib.sha256(capture_bytes).hexdigest()
    shard_records = []
    out.mkdir(parents=True, exist_ok=True)
    for shard, rows in enumerate(buckets):
        tier = f"full-shard-{shard:0{width}d}-of-{shard_count:0{width}d}"
        directory = out / tier
        queries = directory / "queries"
        queries.mkdir(parents=True)
        files = []
        for row in rows:
            materialize(pack / row["path"], directory / row["path"])
            files.append({**row, "tiers": [tier]})
        shard_index = {
            "version": 1,
            "name": f"{capture['name']}-{tier}",
            "source": (
                f"{capture['source']}; deterministic sha256-prefix modulo {shard_count} "
                f"process partition; {tier}; parent_capture_index_sha256={source_digest}"
            ),
            "logic": capture["logic"],
            "files": files,
        }
        shard_bytes = (json.dumps(shard_index, indent=2) + "\n").encode()
        (directory / "capture-index-v1.json").write_bytes(shard_bytes)
        shard_records.append(
            {
                "directory": tier,
                "tier": tier,
                "files": len(files),
                "capture_index_sha256": hashlib.sha256(shard_bytes).hexdigest(),
            }
        )

    shard_set = {
        "schema": "glaurung-qfbv-shard-set-v1",
        "partition": "u64::from_be_bytes(sha256[0:8]) modulo shard_count",
        "parent_capture_index_sha256": source_digest,
        "files": len(capture["files"]),
        "shard_count": shard_count,
        "shards": shard_records,
    }
    (out / "shard-set-v1.json").write_text(
        json.dumps(shard_set, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"materialized process shards: files={shard_set['files']} "
        f"shards={shard_count} output={out}"
    )
    print("shard sizes:", " ".join(str(len(bucket)) for bucket in buckets))
    return shard_set


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack", type=Path, help="strict full capture-index pack")
    parser.add_argument("out", type=Path, help="absent or empty shard-set directory")
    parser.add_argument("--shards", type=int, default=4)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        build_shards(args.pack, args.out, args.shards)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"shard_corpus.py: ERROR: {error}") from error


if __name__ == "__main__":
    main()
