"""Tests for deterministic decompiler output canaries."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools/decompiler_output_canaries.py"
BASELINE = ROOT / "tests/decompiler_output_canaries/baseline.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("decompiler_output_canaries", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def canary_module():
    return _load_tool()


def test_real_function_capture_is_deterministic_and_health_attributed(canary_module):
    binary = (
        ROOT
        / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
    )

    first = canary_module.capture_function(binary, "main", 0x2549)
    second = canary_module.capture_function(binary, "main", 0x2549)

    assert first == second
    assert first["label"] == "main"
    assert first["entry_va"] == "0x2549"
    assert len(first["output_sha256"]) == 64
    assert first["output_bytes"] > 0
    assert first["health"]["statements"] > 0
    assert first["health"]["uncovered_cfg_edges"] == 0
    assert first["health"]["invented_cfg_edges"] == 0
    assert first["health_event_count"] >= 20


def test_manifest_parser_rejects_unknown_fields_and_unpinned_inputs(
    canary_module, tmp_path
):
    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps(
            {
                "schema": "glaurung-output-canaries-v1",
                "cases": [
                    {
                        "name": "bad",
                        "kind": "external",
                        "path": "bin.elf",
                        "functions": [{"label": "f", "entry_va": "0x1"}],
                        "surprise": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(canary_module.CanaryError, match="fields"):
        canary_module.load_manifest(invalid)


def test_report_comparison_names_the_exact_changed_function(canary_module):
    expected = {
        "schema": "glaurung-output-canary-report-v1",
        "cases": [{"name": "x", "functions": [{"label": "f", "output_bytes": 10}]}],
    }
    current = json.loads(json.dumps(expected))
    current["cases"][0]["functions"][0]["output_bytes"] = 11

    differences = canary_module.compare_reports(current, expected)

    assert differences == ["x:f output_bytes: 10 -> 11"]


def test_checked_baseline_covers_every_named_canary_and_real_function():
    report = json.loads(BASELINE.read_text(encoding="utf-8"))

    assert report["git"] == {
        "dirty": False,
        "revision": "6a3252bdc03fea3ad9a8a898bdd39735460fb852",
    }
    expected_functions = {
        "copy_reg": ["copy_reg"],
        "yyparse": ["yyparse"],
        "console_getc": ["console_getc"],
        "statdb_write": ["statdb_write"],
        "arith-gcc-O0": ["addmul", "shifts", "signs"],
        "recursion-gcc-O2": ["ackermann", "fib"],
        "linkedlist-clang-O0": ["list_find", "list_sum"],
    }
    assert {
        case["name"]: [function["label"] for function in case["functions"]]
        for case in report["cases"]
    } == expected_functions
    for case in report["cases"]:
        assert case["provenance"]["binary_sha256"]
        for function in case["functions"]:
            assert function["output_sha256"]
            assert function["health_event_count"] >= 20
            assert function["health"]["uncovered_cfg_edges"] == 0
            assert function["health"]["invented_cfg_edges"] == 0
