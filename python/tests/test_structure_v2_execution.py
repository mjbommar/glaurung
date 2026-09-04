"""Fail-closed contracts for the structure-v2 execution comparison."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import structure_v2_execution as E  # ty: ignore[unresolved-import]  # added above


def _comparison(revision: str = "abc") -> dict:
    return {
        "revision": revision,
        "results": [
            {
                "object": "154_wide_switch-clang-O2.so",
                "functions": [
                    {
                        "fn": "wide154_dense_effects",
                        "status": "regressed",
                        "shadow_gotos": 32,
                    },
                    {
                        "fn": "wide154_sparse_switch",
                        "status": "shadow_declined",
                        "shadow_gotos": None,
                    },
                ],
            }
        ],
    }


def test_targets_include_only_observed_shadow_candidates() -> None:
    assert E.execution_targets(_comparison()) == [
        {
            "object": "154_wide_switch-clang-O2.so",
            "fixture": "154_wide_switch",
            "compiler": "clang",
            "opt": "O2",
            "functions": ["wide154_dense_effects"],
        }
    ]


def test_unrecognized_object_name_fails_closed() -> None:
    comparison = _comparison()
    comparison["results"][0]["object"] = "mystery.so"
    with pytest.raises(ValueError, match="unrecognized fixture object"):
        E.execution_targets(comparison)


def test_report_rejects_a_stale_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(E, "_revision", lambda: "current")
    with pytest.raises(ValueError, match="comparison revision"):
        E.build_report(_comparison("stale"), jobs=1, fuzz=1)


def test_report_separates_improvement_from_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(E, "_revision", lambda: "abc")

    def fake_execute(target: dict, _fuzz: int) -> dict:
        return {
            **{key: target[key] for key in ("object", "fixture", "compiler", "opt")},
            "production_seconds": 1.0,
            "shadow_seconds": 2.0,
            "functions": [
                {
                    "fn": "better",
                    "comparison": "improved",
                    "production_status": "fail",
                    "shadow_status": "pass",
                    "production_detail": "wrong result",
                    "shadow_detail": "34 cases",
                },
                {
                    "fn": "worse",
                    "comparison": "regressed",
                    "production_status": "pass",
                    "shadow_status": "fail",
                    "production_detail": "34 cases",
                    "shadow_detail": "wrong result",
                },
            ],
        }

    monkeypatch.setattr(E, "execute_target", fake_execute)
    report = E.build_report(_comparison(), jobs=1, fuzz=12)

    assert report["candidate_functions"] == 2
    assert report["comparison_counts"]["improved"] == 1
    assert report["comparison_counts"]["regressed"] == 1
    assert report["infrastructure_findings"] == 0


def test_internal_function_is_visible_but_not_an_infrastructure_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(E, "_source", lambda _fixture: Path("fixture.c"))
    monkeypatch.setattr(E.D, "exported_functions", lambda _path: {})
    monkeypatch.setattr(
        E.D,
        "run",
        lambda **_kwargs: pytest.fail("an uncallable function must not be executed"),
    )
    target = E.execution_targets(_comparison())[0]

    result = E.execute_target(target, fuzz=1)

    assert result["functions"] == [
        {
            "fn": "wide154_dense_effects",
            "comparison": "not_executable",
            "production_status": "not_executable",
            "shadow_status": "not_executable",
            "production_detail": "function is not dynamically exported",
            "shadow_detail": "function is not dynamically exported",
        }
    ]
