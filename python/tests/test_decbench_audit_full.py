"""Fail-closed tests for the full-corpus DecBench score audit."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "decbench_audit_full.py"
COMPARE_TOOL = ROOT / "tools" / "decbench_compare_full.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("decbench_audit_full", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_compare_tool():
    spec = importlib.util.spec_from_file_location("decbench_compare_full", COMPARE_TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def audit_module():
    return _load_tool()


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    tree = tmp_path / "tree"
    functions = [
        {"opt": "O0", "project": "p", "binary": "a", "function": "both"},
        {"opt": "O0", "project": "p", "binary": "a", "function": "old_only"},
        {"opt": "O0", "project": "p", "binary": "a", "function": "new_only"},
        {"opt": "O0", "project": "p", "binary": "a", "function": "neither"},
    ]
    tree.mkdir()
    (tree / "sample_set_manifest.json").write_text(
        json.dumps({"functions": functions}), encoding="utf-8"
    )
    provenance = {
        "repo": "noelo-lab/decbench-dataset",
        "revision": "dataset-sha",
        "config": "full",
        "binary_count": 1,
        "function_count": 4,
    }
    (tree / "decbench_dataset_provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    published = {
        "decompilers": ["old"],
        "decompiler_versions": {"old": "1"},
        "metrics": ["ged", "byte_match"],
        "perfect_values": {"ged": 0.0, "byte_match": 1.0},
        "groups": [
            {
                "opt_level": "O0",
                "project": "p",
                "binary": "a",
                "functions": [
                    {"function": "both", "values": {"old": {"ged": 0.0}}},
                    {"function": "old_only", "values": {"old": {"ged": 1.0}}},
                    {"function": "new_only", "values": {}},
                    {"function": "neither", "values": {}},
                ],
            }
        ],
    }
    published_path = tmp_path / "published.json"
    published_path.write_text(json.dumps(published), encoding="utf-8")
    evaluated = tree / "O0" / "p" / "evaluated"
    evaluated.mkdir(parents=True)
    decompiled = tree / "O0" / "p" / "decompiled"
    decompiled.mkdir()
    (decompiled / "new_a.c").write_text(
        "// Function: both @ 0x1000\nlong both(void) { return 0; }\n\n"
        "// Function: new_only @ 0x1010\nlong new_only(void) { return 0; }\n",
        encoding="utf-8",
    )
    (evaluated / "a.toml").write_text(
        "\n".join(
            [
                'binary = "a"',
                '"new.ged.functions.both" = 2.0',
                '"new.byte_match.functions.both" = 1.0',
                '"new.byte_match.functions.new_only" = 1.0',
                "",
            ]
        ),
        encoding="utf-8",
    )
    return tree, published_path, tmp_path


def test_merged_shared_denominator_expands_for_newly_measurable_functions(
    audit_module, tmp_path: Path
):
    tree, published, _ = _inputs(tmp_path)

    report = audit_module.audit(tree, published, "new")

    assert report["universe"] == {
        "manifest_functions": 4,
        "decompiled_functions": 2,
        "decompiled_without_metrics": 0,
        "published_measurable": 2,
        "new_scored": 2,
        "new_only_measurable": 1,
        "published_only_measurable": 1,
        "merged_measurable": 3,
    }
    assert report["scores"]["new"]["union"] == {
        "perfect": 2,
        "denominator": 3,
    }
    assert report["scores"]["old"]["union"] == {
        "perfect": 1,
        "denominator": 3,
    }


def test_new_column_replaces_same_named_published_column(audit_module, tmp_path: Path):
    tree, published, _ = _inputs(tmp_path)
    data = json.loads(published.read_text(encoding="utf-8"))
    data["decompilers"] = ["new"]
    for function in data["groups"][0]["functions"]:
        if "old" in function["values"]:
            function["values"]["new"] = function["values"].pop("old")
    published.write_text(json.dumps(data), encoding="utf-8")

    report = audit_module.audit(tree, published, "new")

    assert list(report["scores"]) == ["new"]
    assert report["scores"]["new"]["union"]["perfect"] == 2


def test_evaluated_function_outside_manifest_fails_closed(audit_module, tmp_path: Path):
    tree, published, _ = _inputs(tmp_path)
    result = tree / "O0" / "p" / "evaluated" / "a.toml"
    result.write_text(
        result.read_text(encoding="utf-8")
        + '"new.ged.functions.not_in_manifest" = 0.0\n',
        encoding="utf-8",
    )

    with pytest.raises(audit_module.AuditError, match="outside manifest"):
        audit_module.audit(tree, published, "new")


def test_missing_or_empty_binary_result_fails_closed(audit_module, tmp_path: Path):
    tree, published, _ = _inputs(tmp_path)
    result = tree / "O0" / "p" / "evaluated" / "a.toml"
    result.unlink()
    with pytest.raises(audit_module.AuditError, match="evaluated binary set"):
        audit_module.audit(tree, published, "new")

    result.write_text('binary = "a"\n', encoding="utf-8")
    with pytest.raises(audit_module.AuditError, match="no function metrics"):
        audit_module.audit(tree, published, "new")


def test_evaluation_cannot_name_a_function_absent_from_decompiled_artifact(
    audit_module, tmp_path: Path
):
    tree, published, _ = _inputs(tmp_path)
    artifact = tree / "O0" / "p" / "decompiled" / "new_a.c"
    artifact.write_text(
        "// Function: both @ 0x1000\nlong both(void) { return 0; }\n",
        encoding="utf-8",
    )

    with pytest.raises(audit_module.AuditError, match="evaluated/artifact function"):
        audit_module.audit(tree, published, "new")


def test_manifest_and_published_universes_must_match(audit_module, tmp_path: Path):
    tree, published, _ = _inputs(tmp_path)
    data = json.loads(published.read_text(encoding="utf-8"))
    data["groups"][0]["functions"].pop()
    published.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(audit_module.AuditError, match="published/manifest universe"):
        audit_module.audit(tree, published, "new")


def test_report_is_byte_deterministic(audit_module, tmp_path: Path):
    tree, published, _ = _inputs(tmp_path)
    report = audit_module.audit(tree, published, "new")

    assert audit_module.render_json(report) == audit_module.render_json(report)
    assert audit_module.render_json(report).endswith("\n")


def test_legacy_compare_does_not_claim_a_fixed_leaderboard_denominator_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    _tree, published, _ = _inputs(tmp_path)
    compare = _load_compare_tool()
    monkeypatch.setattr(
        "sys.argv",
        [
            str(COMPARE_TOOL),
            str(published),
            "--published",
            str(published),
            "--column",
            "old",
        ],
    )

    assert compare.main() == 0
    output = capsys.readouterr().out
    assert "LEADERBOARD-EQUIVALENT" not in output
    assert "decbench_audit_full.py" in output
