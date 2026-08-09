"""Contracts for the curated DecBench one-edit type defect corpus."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "decbench_scoreboard" / "type-distance-one-9c25fcb.json"


def test_type_distance_one_corpus_is_complete_and_owner_grouped() -> None:
    """Pin all 29 one-edit failures and their semantic ownership."""
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    defects = payload["defects"]

    assert payload["schema_version"] == 1
    assert payload["glaurung_revision"] == "9c25fcb860fb433b59bb24b3f880e8ae3a38a972"
    assert payload["source_type_overlay_sha256"] == (
        "4cbb9613344bf365df9cc6c8e72993a62eb1d14a360576daa89736d991cf596c"
    )
    assert len(defects) == 29
    assert len({defect["key"] for defect in defects}) == 29
    assert all(defect["distance"] == 1 for defect in defects)
    assert all(defect["evidence_owner"] for defect in defects)
    assert all(defect["mismatch"] for defect in defects)
    assert Counter(defect["failure_cluster"] for defect in defects) == {
        "pointer_category": 20,
        "missing_local_identity": 6,
        "integer_width": 2,
        "missing_parameter": 1,
    }
    assert payload["fresh_validation"] == {
        "metric": "official TypeMatchMetric cache_version 5 with caching disabled",
        "scope": "all 29 functions, address-scoped from their real official binaries",
        "parent_revision": "acc3e241cf1314312b18acd165d766bd8ab6ed34",
        "parent_perfect": 13,
        "current_perfect": 27,
        "current_open": 2,
        "glaurung_side_resolved": 29,
        "metric_false_negatives": 2,
    }
    metric_false_negatives = {
        defect["key"]
        for defect in defects
        if defect["status"] == "metric_false_negative"
    }
    assert metric_false_negatives == {
        "coreutils::O0::pr::balance",
        "libselinux::O0::libselinux.so::get_class_cache_entry_name",
    }
    assert all(
        defect.get("metric_evidence")
        for defect in defects
        if defect["status"] == "metric_false_negative"
    )
    assert Counter(defect["status"] for defect in defects) == {
        "verified_fixed": 27,
        "metric_false_negative": 2,
    }
