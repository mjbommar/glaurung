#!/usr/bin/env python3
"""Build one strict Axeyum capture-index pack from a raw Glaurung dump.

The raw producer owns trusted verdicts. This script validates raw byte identity,
deduplicates repeated index observations, rejects conflicts, classifies queries,
and emits a hash-free capture index. Axeyum's manifest generator must perform
the separate trust-boundary hashing step.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil


HASH_RE = re.compile(r"[0-9a-f]{64}")


def classify(text: str) -> str:
    if text.count("(assert") == 0:
        return "trivial"
    has_extract = "extract" in text
    has_concat = "concat" in text
    if has_extract and has_concat:
        return "register-slice"
    if has_extract or has_concat:
        return "slice-partial"
    if "bvmul" in text or "bvadd" in text:
        return "arithmetic"
    if any(op in text for op in ("bvult", "bvule", "bvslt", "bvsle")):
        return "comparison"
    return "mixed"


def size_bucket(size: int) -> str:
    if size < 500:
        return "xs"
    if size < 4_000:
        return "s"
    if size < 20_000:
        return "m"
    if size < 80_000:
        return "l"
    return "xl"


def load_raw(raw: Path) -> tuple[list[dict[str, object]], dict[str, int]]:
    index = raw / "index.tsv"
    if not index.is_file():
        raise ValueError(f"missing raw capture index: {index}")

    verdicts: dict[str, str] = {}
    duplicate_rows = 0
    lines = index.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError("raw capture index is empty")
    for line_number, line in enumerate(lines, 1):
        fields = line.split("\t")
        if len(fields) != 2:
            raise ValueError(f"index.tsv:{line_number}: expected HASH<TAB>VERDICT")
        query_hash, verdict = fields
        if HASH_RE.fullmatch(query_hash) is None:
            raise ValueError(f"index.tsv:{line_number}: invalid lowercase SHA-256")
        if verdict not in {"sat", "unsat"}:
            raise ValueError(f"index.tsv:{line_number}: invalid verdict {verdict!r}")
        previous = verdicts.get(query_hash)
        if previous is not None:
            duplicate_rows += 1
            if previous != verdict:
                raise ValueError(
                    f"index.tsv:{line_number}: verdict conflict for {query_hash}: "
                    f"{previous} vs {verdict}"
                )
        verdicts[query_hash] = verdict

    scripts = {path.stem: path for path in raw.glob("*.smt2")}
    missing = sorted(set(verdicts) - set(scripts))
    orphaned = sorted(set(scripts) - set(verdicts))
    if missing:
        raise ValueError(f"index references {len(missing)} missing scripts; first={missing[0]}")
    if orphaned:
        raise ValueError(f"raw directory has {len(orphaned)} unindexed scripts; first={orphaned[0]}")

    rows: list[dict[str, object]] = []
    for query_hash in sorted(verdicts):
        path = scripts[query_hash]
        payload = path.read_bytes()
        actual_hash = hashlib.sha256(payload).hexdigest()
        if actual_hash != query_hash:
            raise ValueError(
                f"content hash mismatch for {path.name}: expected {query_hash}, got {actual_hash}"
            )
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"query is not UTF-8: {path.name}: {error}") from error
        rows.append(
            {
                "hash": query_hash,
                "path": path,
                "size": len(payload),
                "expected": verdicts[query_hash],
                "family": classify(text),
                "bucket": size_bucket(len(payload)),
            }
        )

    return rows, {
        "index_rows": len(lines),
        "unique_queries": len(rows),
        "duplicate_rows": duplicate_rows,
    }


def representative_hashes(rows: list[dict[str, object]], per_bucket: int) -> set[str]:
    buckets: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        buckets[(row["family"], row["expected"], row["bucket"])].append(row)

    selected: set[str] = set()
    for key in sorted(buckets):
        items = sorted(buckets[key], key=lambda row: str(row["hash"]))
        step = max(1, len(items) // per_bucket)
        selected.update(str(row["hash"]) for row in items[::step][:per_bucket])
    return selected


def materialize(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def build(args: argparse.Namespace) -> dict[str, int]:
    if args.rep_per_bucket <= 0:
        raise ValueError("rep_per_bucket must be positive")
    if not args.source.strip():
        raise ValueError("--source must be non-empty and identify revision plus drivers")
    if args.out.exists() and any(args.out.iterdir()):
        raise ValueError(f"output directory must be absent or empty: {args.out}")

    rows, stats = load_raw(args.raw)
    representative = representative_hashes(rows, args.rep_per_bucket)
    selected = rows if args.tier == "full" else [row for row in rows if row["hash"] in representative]
    if not selected:
        raise ValueError(f"tier {args.tier!r} selected no queries")

    queries = args.out / "queries"
    queries.mkdir(parents=True, exist_ok=True)
    files = []
    for row in selected:
        query_hash = str(row["hash"])
        relative = f"queries/{query_hash}.smt2"
        materialize(Path(row["path"]), args.out / relative)
        files.append(
            {
                "path": relative,
                "expected": row["expected"],
                "family": row["family"],
                "tiers": [args.tier],
            }
        )

    source = (
        f"{args.source}; strict raw reconciliation: {stats['index_rows']} index rows, "
        f"{stats['unique_queries']} unique hashes, {stats['duplicate_rows']} duplicate rows, "
        "zero verdict conflicts, zero exclusions"
    )
    capture_index = {
        "version": 1,
        "name": args.name,
        "source": source,
        "logic": "QF_BV",
        "files": files,
    }
    (args.out / "capture-index-v1.json").write_text(
        json.dumps(capture_index, indent=2) + "\n", encoding="utf-8"
    )

    families = Counter(str(row["family"]) for row in selected)
    verdicts = Counter(str(row["expected"]) for row in selected)
    print(
        f"validated raw capture: rows={stats['index_rows']} "
        f"unique={stats['unique_queries']} duplicates={stats['duplicate_rows']} conflicts=0"
    )
    print(f"materialized tier={args.tier} queries={len(selected)} output={args.out}")
    print("families:", " ".join(f"{key}={families[key]}" for key in sorted(families)))
    print("verdicts:", " ".join(f"{key}={verdicts[key]}" for key in sorted(verdicts)))
    return {**stats, "selected_queries": len(selected)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path, help="raw directory containing index.tsv and HASH.smt2")
    parser.add_argument("out", type=Path, help="new or empty capture-index pack directory")
    parser.add_argument("rep_per_bucket", type=int, nargs="?", default=6)
    parser.add_argument("--tier", choices=("representative", "full"), default="representative")
    parser.add_argument("--name", default="glaurung-qfbv-corrected-v2")
    parser.add_argument("--source", required=True, help="producer revision and exact driver set")
    return parser.parse_args()


def main() -> None:
    try:
        build(parse_args())
    except (OSError, ValueError) as error:
        raise SystemExit(f"build_corpus.py: ERROR: {error}") from error


if __name__ == "__main__":
    main()
