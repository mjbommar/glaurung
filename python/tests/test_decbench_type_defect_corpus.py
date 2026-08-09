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
    assert [
        defect["key"] for defect in defects if defect["status"] == "verified_fixed"
    ] == ["chibios::O2-noinline::ch::nvicEnableVector"]
