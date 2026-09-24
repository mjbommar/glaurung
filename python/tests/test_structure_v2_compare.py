"""Real-fixture contracts for the structure-v2 corpus comparison."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # added above
import structure_v2_compare as S  # added above


def test_structure_axis_compares_both_outputs_on_one_source_denominator() -> None:
    source = S.metrics.skeletons("int f(int x) { if (x) return 1; return 0; }")["f"]

    cell = S._structure_cell(
        source,
        "int f(int x) { goto out; out: return 0; }",
        "int f(int x) { if (x) return 1; return 0; }",
        "f",
    )

    assert cell["status"] == "scored"
    assert cell["shadow_distance"] == 0
    assert cell["production_distance"] > cell["shadow_distance"]
    assert cell["movement"] == "improved"


def test_structure_axis_keeps_a_shadow_decline_out_of_the_distance_denominator() -> (
    None
):
    source = S.metrics.skeletons("int f(void) { return 0; }")["f"]

    assert S._structure_cell(source, "int f(void) { return 0; }", None, "f") == {
        "status": "shadow_declined",
        "source_nodes": len(source),
    }


def test_mixed_real_batch_counts_verified_output_and_local_decline() -> None:
    """A refused loop must not erase a verified sibling from measurement."""
    binary = BUILD / "03_loop_shapes-clang-O0.so"
    if not binary.is_file():
        pytest.skip("real decompiler fixture matrix is absent")
    exports = D.exported_functions(str(binary))
    rows = [
        {
            "obj": binary.name,
            "fn": "loop_early_return",
            "va": exports["loop_early_return"],
        },
        {
            "obj": binary.name,
            "fn": "while_prefix",
            "va": exports["while_prefix"],
        },
    ]

    result = S.compare_object(binary.name, rows)

    by_name = {function["fn"]: function for function in result["functions"]}
    assert by_name["loop_early_return"]["shadow_gotos"] is not None
    assert by_name["while_prefix"]["status"] == "shadow_declined"
    assert by_name["while_prefix"]["shadow_gotos"] is None


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


def test_report_aggregates_only_jointly_scored_structure_cells(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = {
        "object": "fixture.so",
        "requested": 2,
        "production_seconds": 0.1,
        "shadow_seconds": 0.2,
        "functions": [
            {
                "fn": "scored",
                "status": "improved",
                "classification": None,
                "production_gotos": 2,
                "shadow_gotos": 1,
                "production_bytes": 20,
                "shadow_bytes": 15,
                "structure": {
                    "status": "scored",
                    "production_distance": 7,
                    "shadow_distance": 3,
                    "movement": "improved",
                },
            },
            {
                "fn": "declined",
                "status": "shadow_declined",
                "classification": None,
                "production_gotos": 1,
                "shadow_gotos": None,
                "production_bytes": 10,
                "shadow_bytes": None,
                "structure": {"status": "shadow_declined"},
            },
        ],
    }
    monkeypatch.setattr(S, "compare_object", lambda *_args: result)

    report = S.build_report({"fixture.so": [{}, {}]}, jobs=1)

    assert report["structure_axis"]["status_counts"]["scored"] == 1
    assert report["structure_axis"]["status_counts"]["shadow_declined"] == 1
    assert report["structure_axis"]["movement_counts"] == {
        "improved": 1,
        "unchanged": 0,
        "regressed": 0,
    }
    assert report["structure_axis"]["production_distance_total"] == 7
    assert report["structure_axis"]["shadow_distance_total"] == 3
