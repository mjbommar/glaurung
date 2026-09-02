#!/usr/bin/env python3
"""Validate an exact Glaurung Z3/Axeyum shadow-split capture.

The producer records only queries for which exactly one backend decides. This
consumer independently verifies the stable result classes, complete script
inventory, filename/content SHA-256 identity, and UTF-8 query bytes before the
capture is used for diagnosis or converted into an Axeyum benchmark pack.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import sys


HASH_RE = re.compile(r"[0-9a-f]{64}")
DECIDED = frozenset(("sat", "unsat"))
NONDECIDED = frozenset(("unknown", "error"))
CLASSES = DECIDED | NONDECIDED


def load_index(root: Path) -> dict[str, tuple[str, str]]:
    index = root / "shadow-splits.tsv"
    if not index.is_file():
        raise ValueError(f"missing shadow split index: {index}")
    lines = index.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError("shadow-splits.tsv is empty")

    rows: dict[str, tuple[str, str]] = {}
    for line_number, line in enumerate(lines, 1):
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(
                f"shadow-splits.tsv:{line_number}: expected "
                "HASH<TAB>Z3_CLASS<TAB>AXEYUM_CLASS"
            )
        content_hash, z3_class, axeyum_class = fields
        if HASH_RE.fullmatch(content_hash) is None:
            raise ValueError(
                f"shadow-splits.tsv:{line_number}: invalid lowercase SHA-256"
            )
        if z3_class not in CLASSES or axeyum_class not in CLASSES:
            raise ValueError(
                f"shadow-splits.tsv:{line_number}: invalid result classes "
                f"{z3_class!r}/{axeyum_class!r}"
            )
        z3_decided = z3_class in DECIDED
        axeyum_decided = axeyum_class in DECIDED
        if z3_decided == axeyum_decided:
            raise ValueError(
                f"shadow-splits.tsv:{line_number}: exactly one decided backend "
                f"required, got {z3_class}/{axeyum_class}"
            )
        pair = (z3_class, axeyum_class)
        previous = rows.get(content_hash)
        if previous is not None:
            kind = "duplicate" if previous == pair else "conflicting"
            raise ValueError(
                f"shadow-splits.tsv:{line_number}: {kind} hash row for "
                f"{content_hash}: {previous[0]}/{previous[1]} vs "
                f"{z3_class}/{axeyum_class}"
            )
        rows[content_hash] = pair
    return rows


def validate_script(path: Path, expected_hash: str) -> int:
    payload = path.read_bytes()
    actual_hash = hashlib.sha256(payload).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(
            f"content hash mismatch for {path.name}: expected {expected_hash}, "
            f"got {actual_hash}"
        )
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"query is not UTF-8: {path.name}: {error}") from error
    return len(payload)


def validate_capture(
    root: Path, jobs: int
) -> tuple[dict[str, object], dict[str, tuple[str, str]], dict[str, int]]:
    if jobs <= 0:
        raise ValueError("--jobs must be positive")
    rows = load_index(root)
    scripts = {path.stem: path for path in root.glob("*.smt2")}
    missing = sorted(set(rows) - set(scripts))
    orphaned = sorted(set(scripts) - set(rows))
    if missing:
        raise ValueError(
            f"index references {len(missing)} missing scripts; first={missing[0]}"
        )
    if orphaned:
        raise ValueError(
            f"capture has {len(orphaned)} unindexed scripts; first={orphaned[0]}"
        )

    hashes = sorted(rows)
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        size_values = list(
            executor.map(
                lambda content_hash: validate_script(
                    scripts[content_hash], content_hash
                ),
                hashes,
            )
        )
    sizes = dict(zip(hashes, size_values, strict=True))

    class_pairs = Counter(f"{rows[key][0]}/{rows[key][1]}" for key in hashes)
    decided_by = Counter(
        "z3" if rows[key][0] in DECIDED else "axeyum" for key in hashes
    )
    summary = {
        "schema": "glaurung-shadow-split-summary-v1",
        "distinct_queries": len(rows),
        "content_bytes": sum(sizes.values()),
        "class_pairs": dict(sorted(class_pairs.items())),
        "decided_by": dict(sorted(decided_by.items())),
    }
    return summary, rows, sizes


def validate(root: Path, jobs: int) -> dict[str, object]:
    summary, _, _ = validate_capture(root, jobs)
    return summary


def build_capture_index(
    rows: dict[str, tuple[str, str]],
    sizes: dict[str, int],
    name: str,
    source: str,
) -> dict[str, object]:
    if not name.strip():
        raise ValueError("--name must be non-empty")
    if not source.strip():
        raise ValueError("--source is required with --capture-index-out")

    representative: set[str] = set()
    for pair in sorted(set(rows.values())):
        matching = (
            content_hash for content_hash, value in rows.items() if value == pair
        )
        representative.add(min(matching, key=lambda key: (sizes[key], key)))

    files = []
    for content_hash in sorted(rows):
        z3_class, axeyum_class = rows[content_hash]
        z3_decided = z3_class in DECIDED
        tiers = ["diagnostic"]
        tiers.append("z3-decided" if z3_decided else "axeyum-decided")
        if axeyum_class == "error":
            tiers.append("axeyum-error")
        if content_hash in representative:
            tiers.append("representative")
            if axeyum_class == "error":
                tiers.append("axeyum-error-representative")
        files.append(
            {
                "path": f"{content_hash}.smt2",
                "expected": z3_class if z3_decided else axeyum_class,
                "family": (
                    "shadow-z3-decided" if z3_decided else "shadow-axeyum-decided"
                ),
                "tiers": tiers,
            }
        )
    return {
        "version": 1,
        "name": name,
        "source": source,
        "logic": "QF_BV",
        "files": files,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--capture-index-out", type=Path)
    parser.add_argument("--name", default="glaurung-shadow-splits-v1")
    parser.add_argument("--source")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        summary, rows, sizes = validate_capture(args.capture, args.jobs)
        rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if args.summary_out is not None:
            args.summary_out.write_text(rendered, encoding="utf-8")
        if args.capture_index_out is not None:
            capture_index = build_capture_index(
                rows, sizes, args.name, args.source if args.source is not None else ""
            )
            args.capture_index_out.write_text(
                json.dumps(capture_index, indent=2) + "\n", encoding="utf-8"
            )
        print(rendered, end="")
    except (OSError, ValueError) as error:
        print(f"validate_shadow_splits.py: ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
