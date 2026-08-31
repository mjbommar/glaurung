#!/usr/bin/env python3
"""Deterministically merge disjoint DecBench ``function_results.json`` shards."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


HEADER_FIELDS = (
    "schema_version",
    "decompilers",
    "decompiler_versions",
    "metrics",
    "perfect_values",
    "dataset_presets",
)


def _group_key(group: dict[str, Any]) -> tuple[str, str, str]:
    return (str(group["opt_level"]), str(group["project"]), str(group["binary"]))


def _sample_key(sample: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(sample["opt_level"]),
        str(sample["project"]),
        str(sample["binary"]),
        str(sample["function"]),
        str(sample.get("difficulty") or ""),
    )


def merge_shards(shards: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Merge already-loaded, disjoint shard documents.

    Aggregate compile rates are deliberately discarded and recomputed from the
    per-function ``compiles`` flags. Duplicate immutable function keys are fatal.
    """
    documents = list(shards)
    if not documents:
        raise ValueError("no shards supplied")
    first = documents[0]
    for index, shard in enumerate(documents[1:], start=1):
        for field in HEADER_FIELDS:
            if shard.get(field) != first.get(field):
                raise ValueError(f"shard {index} has incompatible {field}")

    groups: list[dict[str, Any]] = []
    function_keys: set[tuple[str, str, str, str]] = set()
    compile_true: Counter[str] = Counter()
    compile_total: Counter[str] = Counter()
    samples: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    hardest: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}

    for shard in documents:
        for group in shard.get("groups", []):
            group_key = _group_key(group)
            for record in group.get("functions", []):
                key = (*group_key, str(record["function"]))
                if key in function_keys:
                    raise ValueError(f"duplicate function key: {key!r}")
                function_keys.add(key)
                for decompiler, outcome in (record.get("compiles") or {}).items():
                    compile_total[decompiler] += 1
                    if outcome is True:
                        compile_true[decompiler] += 1
            groups.append(group)
        for sample in shard.get("samples", []):
            samples.setdefault(_sample_key(sample), sample)
        for entry in shard.get("hardest", []):
            key = (
                str(entry["metric"]),
                str(entry["decompiler"]),
                str(entry["opt_level"]),
                str(entry["project"]),
                str(entry["binary"]),
                str(entry["function"]),
            )
            hardest.setdefault(key, entry)

    groups.sort(key=_group_key)
    # Each shard retained its local top 15. The global top 15 must therefore be
    # in their union; select it again using the benchmark's distance ordering.
    hardest_buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in hardest.values():
        hardest_buckets.setdefault((entry["metric"], entry["decompiler"]), []).append(entry)
    merged_hardest: list[dict[str, Any]] = []
    for bucket in sorted(hardest_buckets):
        entries = hardest_buckets[bucket]
        entries.sort(
            key=lambda e: (
                abs(float(e["value"]) - float(e["perfect_value"])),
                float(e["value"]),
                _sample_key(e),
            ),
            reverse=True,
        )
        merged_hardest.extend(entries[:15])

    # With one decompiler, DecBench's ordinary sample selection is its stable
    # fallback: the first 100 publishable functions with code. Every shard kept
    # at least its first 100, so that global prefix is present in this union.
    merged_samples = [samples[key] for key in sorted(samples)[:100]]
    compile_rates = {
        decompiler: compile_true[decompiler] / total
        for decompiler, total in sorted(compile_total.items())
        if total
    }
    return {
        **{field: first[field] for field in HEADER_FIELDS},
        "groups": groups,
        "hardest": merged_hardest,
        "samples": merged_samples,
        "compile_rates": compile_rates,
        "dataset_info": first.get("dataset_info") or {},
        "cost_info": first.get("cost_info") or {},
        "history": first.get("history") or [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard_root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    paths = sorted(args.shard_root.glob("*/function_results.json"))
    merged = merge_shards([json.loads(path.read_text()) for path in paths])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(merged, indent=2) + "\n")
    print(
        f"merged {len(paths)} shards, {len(merged['groups'])} groups -> {args.output}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
