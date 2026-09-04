"""Real-fixture contracts for the structure-v2 corpus comparison."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import structure_v2_compare as S  # ty: ignore[unresolved-import]  # added above


def test_mixed_real_batch_counts_verified_output_and_local_decline() -> None:
    """A refused loop must not erase a verified sibling from measurement."""
    binary = BUILD / "03_loop_shapes-gcc-O0.so"
    if not binary.is_file():
        pytest.skip("real decompiler fixture matrix is absent")
    exports = D.exported_functions(str(binary))
    rows = [
        {"obj": binary.name, "fn": "for_sum", "va": exports["for_sum"]},
        {
            "obj": binary.name,
            "fn": "dowhile_recompute",
            "va": exports["dowhile_recompute"],
        },
    ]

    result = S.compare_object(binary.name, rows)

    by_name = {function["fn"]: function for function in result["functions"]}
    assert by_name["for_sum"]["shadow_gotos"] is not None
    assert by_name["dowhile_recompute"]["status"] == "shadow_declined"
    assert by_name["dowhile_recompute"]["shadow_gotos"] is None


def test_reviewed_shadow_regression_keeps_raw_status_and_adds_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact reviewed row is classified without rewriting its raw result."""
    outputs = iter(
        [
            {4352: "void duff_copy(void) { goto L_tail; L_tail: return; }"},
            {
                4352: (
                    "void duff_copy(void) {\n"
                    "switch (count) {\ncase 0: goto L_tail;\n}\n"
                    "L_tail:\nreturn;\n}\n"
                )
            },
        ]
    )
    monkeypatch.setattr(S, "_decompile", lambda *_args: next(outputs))

    result = S.compare_object(
        "102_duffs_device-gcc-O2.so",
        [{"fn": "duff_copy", "va": 4352}],
    )

    row = result["functions"][0]
    assert row["status"] == "unchanged"
    assert row["classification"] is None

    # Make the production form strictly smaller: the classification applies,
    # but the raw status remains visible as a regression.
    outputs = iter(
        [
            {4352: "void duff_copy(void) { return; }"},
            {
                4352: (
                    "void duff_copy(void) {\n"
                    "switch (count) {\ncase 0: goto L_tail;\n}\n"
                    "L_tail:\nreturn;\n}\n"
                )
            },
        ]
    )
    result = S.compare_object(
        "102_duffs_device-gcc-O2.so",
        [{"fn": "duff_copy", "va": 4352}],
    )
    row = result["functions"][0]
    assert row["status"] == "regressed"
    assert row["classification"] == "accepted_honest_goto"
    assert row["classification_property"] == (
        "verified_switch_suffix_entry_shared_region"
    )


@pytest.mark.parametrize(
    "name,text",
    [
        ("unreviewed.so", "switch (x) { case 0: goto L; }\nL:\nreturn;"),
        ("102_duffs_device-gcc-O2.so", "goto L_tail;\nL_tail:\nreturn;"),
        ("102_duffs_device-gcc-O2.so", "switch (x) { case 0: goto L_missing; }"),
    ],
)
def test_shadow_honest_goto_classification_fails_closed(name: str, text: str) -> None:
    assert S._honest_goto_property(name, "duff_copy", "regressed", text) is None


def test_report_separates_raw_and_classified_regressions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reviewed = {
        "object": "102_duffs_device-gcc-O2.so",
        "requested": 1,
        "production_seconds": 0.1,
        "shadow_seconds": 0.2,
        "functions": [
            {
                "fn": "duff_copy",
                "va": 4352,
                "status": "regressed",
                "classification": "accepted_honest_goto",
                "classification_property": "verified_switch_suffix_entry_shared_region",
                "production_gotos": 4,
                "shadow_gotos": 8,
                "production_bytes": 100,
                "shadow_bytes": 200,
            }
        ],
    }
    monkeypatch.setattr(S, "compare_object", lambda *_args: reviewed)

    report = S.build_report({"102_duffs_device-gcc-O2.so": [{}]}, jobs=1)

    assert report["status_counts"]["regressed"] == 1
    assert report["classification_counts"] == {
        "accepted_honest_goto": 1,
        "unexplained_regression": 0,
    }
