from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_runner_artifact_promotion_plan import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    return MemoryContext(file_path=str(path), artifact=artifact)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_clean_ghidra_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    artifact_dir = tmp_path / "artifacts"
    _write_json(
        artifact_dir / "runner-artifact-review.json",
        {
            "claim_level": "windows_runner_artifact_review_not_finding",
            "mode": "ghidra_parity",
            "artifact_dir": str(artifact_dir),
            "review_ready": True,
            "promotion_ready": True,
            "promotable_artifacts": [
                "glaurung_vs_ghidra_vendor_windows_30_refresh.json",
                "glaurung_vs_ghidra_vendor_windows_30_refresh.md",
            ],
            "blockers": [],
            "warnings": [],
        },
    )
    _write_json(
        artifact_dir / "glaurung_vs_ghidra_vendor_windows_30_refresh.json",
        {"summary": {"missing_count": 1}, "files": []},
    )
    (artifact_dir / "glaurung_vs_ghidra_vendor_windows_30_refresh.md").write_text(
        "# refreshed\n",
        encoding="utf-8",
    )
    docs_root = tmp_path / "docs" / "windows-port"
    docs_root.mkdir(parents=True)
    return artifact_dir, docs_root


def test_windows_runner_artifact_promotion_plan_maps_ghidra_refresh_to_docs(
    tmp_path: Path,
) -> None:
    artifact_dir, docs_root = _write_clean_ghidra_artifacts(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            artifact_dir=str(artifact_dir),
            review_path=str(artifact_dir / "runner-artifact-review.json"),
            docs_root=str(docs_root),
        ),
    )

    assert result.claim_level == "runner_artifact_promotion_plan_not_finding"
    assert result.promotion_allowed is True
    assert result.action_count == 2
    destinations = {Path(action.destination_path).name for action in result.actions}
    assert "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json" in destinations
    assert "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.md" in destinations
    assert all(action.operation == "copy" for action in result.actions)
    assert all(action.source_sha256 for action in result.actions)
    assert result.evidence_bundle.coverage.validation_ready is True


def test_windows_runner_artifact_promotion_plan_refuses_blocked_review(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifacts"
    _write_json(
        artifact_dir / "runner-artifact-review.json",
        {
            "claim_level": "windows_runner_artifact_review_not_finding",
            "mode": "target_pipeline",
            "artifact_dir": str(artifact_dir),
            "review_ready": True,
            "promotion_ready": False,
            "promotable_artifacts": [],
            "blockers": ["preflight blocked: project cache missing"],
            "warnings": [],
        },
    )
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            artifact_dir=str(artifact_dir),
            review_path=str(artifact_dir / "runner-artifact-review.json"),
            docs_root=str(tmp_path / "docs" / "windows-port"),
        ),
    )

    assert result.promotion_allowed is False
    assert result.action_count == 0
    assert "runner artifact review is not promotion-ready" in result.blockers


def test_windows_runner_artifact_promotion_plan_maps_target_pipeline_artifacts(
    tmp_path: Path,
) -> None:
    artifact_dir = tmp_path / "artifacts"
    _write_json(
        artifact_dir / "runner-artifact-review.json",
        {
            "claim_level": "windows_runner_artifact_review_not_finding",
            "mode": "target_pipeline",
            "artifact_dir": str(artifact_dir),
            "review_ready": True,
            "promotion_ready": True,
            "promotable_artifacts": [
                "pipeline-export.json",
                "evidence-export.json",
                "target-pipeline.json",
                "candidate-packets.json",
                "evidence-review.md",
            ],
            "blockers": [],
            "warnings": [],
        },
    )
    for name in (
        "pipeline-export.json",
        "evidence-export.json",
        "target-pipeline.json",
        "candidate-packets.json",
    ):
        _write_json(
            artifact_dir / name,
            {"claim_level": "target_pipeline_artifact_not_finding", "name": name},
        )
    (artifact_dir / "evidence-review.md").write_text(
        "# evidence review\n",
        encoding="utf-8",
    )
    docs_root = tmp_path / "docs" / "windows-port"
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            artifact_dir=str(artifact_dir),
            review_path=str(artifact_dir / "runner-artifact-review.json"),
            docs_root=str(docs_root),
        ),
    )

    assert result.promotion_allowed is True
    assert result.action_count == 5
    assert {
        Path(action.destination_path).parent.name for action in result.actions
    } == {"runner-artifacts"}
    assert {Path(action.destination_path).name for action in result.actions} == {
        "pipeline-export.json",
        "evidence-export.json",
        "target-pipeline.json",
        "candidate-packets.json",
        "evidence-review.md",
    }


def test_windows_runner_artifact_promotion_plan_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    artifact_dir, docs_root = _write_clean_ghidra_artifacts(tmp_path)

    rc = GlaurungCLI().run(
        [
            "windows",
            "runner-artifact-promotion-plan",
            "--artifact-dir",
            str(artifact_dir),
            "--review-path",
            str(artifact_dir / "runner-artifact-review.json"),
            "--docs-root",
            str(docs_root),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["promotion_allowed"] is True
    assert output["action_count"] == 2


def test_memory_agent_registers_windows_runner_artifact_promotion_plan() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_runner_artifact_promotion_plan" in agent._function_toolset.tools
