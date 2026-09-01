"""Tests for the deterministic DecBench submission shard merger."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "tools" / "decbench_merge_shards.py"
SPEC = importlib.util.spec_from_file_location("decbench_merge_shards", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
merge_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(merge_module)


def _shard(binary: str, function: str, compiles: bool) -> dict:
    column = "glaurung-test"
    return {
        "schema_version": 2,
        "decompilers": [column],
        "decompiler_versions": {column: "abc123"},
        "metrics": ["ged", "type_match", "byte_match"],
        "perfect_values": {"ged": 0.0, "type_match": 1.0, "byte_match": 1.0},
        "groups": [
            {
                "project": "p",
                "opt_level": "O0",
                "binary": binary,
                "labels": [],
                "arch": "x86-64",
                "functions": [
                    {
                        "function": function,
                        "values": {column: {"byte_match": 1.0}},
                        "perfects": {column: {"byte_match": True}},
                        "distances": {column: {"byte_match": 0.0}},
                        "decompiled": {column: True},
                        "compiles": {column: compiles},
                        "labels": [],
                        "datasets": ["unoptimized"],
                    }
                ],
            }
        ],
        "dataset_presets": [{"name": "unoptimized"}],
        "hardest": [],
        "samples": [],
        "compile_rates": {column: float(compiles)},
        "dataset_info": {},
        "cost_info": {},
        "history": [],
    }


def test_merge_is_sorted_and_recomputes_compile_rate() -> None:
    merged = merge_module.merge_shards(
        [_shard("z", "last", False), _shard("a", "first", True)]
    )

    assert [group["binary"] for group in merged["groups"]] == ["a", "z"]
    assert merged["compile_rates"] == {"glaurung-test": 0.5}


def test_merge_rejects_duplicate_function_keys() -> None:
    with pytest.raises(ValueError, match="duplicate function key"):
        merge_module.merge_shards(
            [_shard("a", "same", True), _shard("a", "same", True)]
        )


def test_merge_rejects_incompatible_headers() -> None:
    left = _shard("a", "one", True)
    right = _shard("b", "two", True)
    right["perfect_values"] = {"ged": 1.0}

    with pytest.raises(ValueError, match="perfect_values"):
        merge_module.merge_shards([left, right])
