from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_runner_artifact_review import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    return MemoryContext(file_path=str(path), artifact=artifact)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_windows_runner_artifact_review_accepts_clean_high_volume_run(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    _write_json(
        artifacts / "preflight.json",
        {
            "claim_level": "high_volume_preflight_not_analysis",
            "ready": True,
            "target_count": 2,
            "ready_target_count": 2,
            "blocked_target_count": 0,
            "blockers": [],
            "warnings": [],
        },
    )
    _write_json(
        artifacts / "target-pipeline.json",
        {
            "claim_level": "target_pipeline_not_finding",
            "candidate_count": 3,
            "planned_count": 3,
            "evidence_review_count": 3,
            "blocker_work_item_count": 0,
            "blockers": [],
        },
    )
    _write_json(
        artifacts / "blocker-worklist.json",
        {
            "claim_level": "target_pipeline_blocker_worklist_not_finding",
            "blocker_work_item_count": 0,
            "work_items": [],
        },
    )
    _write_json(
        artifacts / "blocker-task-plan.json",
        {
            "claim_level": "pipeline_blocker_task_plan_not_finding",
            "task_count": 0,
            "tasks": [],
        },
    )
    _write_json(
        artifacts / "pipeline-export.json",
        {
            "claim_level": "target_pipeline_export_manifest_not_finding",
            "candidate_count": 3,
            "ready_fanout_count": 2,
            "generated_artifacts": ["candidate-packets.json"],
        },
    )
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(artifact_dir=str(artifacts), mode="target_pipeline"),
    )

    assert result.claim_level == "windows_runner_artifact_review_not_finding"
    assert result.mode == "target_pipeline"
    assert result.review_ready is True
    assert result.promotion_ready is True
    assert result.preflight_ready is True
    assert result.candidate_count == 3
    assert result.blocker_work_item_count == 0
    assert result.task_count == 0
    assert result.blockers == []
    assert "pipeline-export.json" in result.promotable_artifacts
    assert result.evidence_bundle.coverage.validation_ready is True


def test_windows_runner_artifact_review_reports_blocked_preflight(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    _write_json(
        artifacts / "preflight.json",
        {
            "claim_level": "high_volume_preflight_not_analysis",
            "ready": False,
            "target_count": 2,
            "ready_target_count": 1,
            "blocked_target_count": 1,
            "blockers": ["project cache missing for target app"],
            "warnings": [],
        },
    )
    _write_json(
        artifacts / "preflight-task-plan.json",
        {
            "claim_level": "pipeline_blocker_task_plan_not_finding",
            "task_count": 1,
            "tasks": [
                {
                    "rank": 1,
                    "kind": "project_cache_refresh",
                    "source_kind": "preflight",
                    "title": "Build .glaurung project cache for app",
                    "priority": 100,
                    "target_ids": ["app"],
                    "candidate_ids": [],
                    "stages": [],
                    "blocker_count": 1,
                    "blockers": ["project cache missing for target app"],
                    "required_artifacts": [".glaurung project cache"],
                    "next_tool_name": "windows_bootstrap_project_facts",
                    "next_tool_args": {"target_id": "app"},
                    "commands": [],
                    "reason_codes": ["preflight_project_cache_missing"],
                }
            ],
        },
    )
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(artifact_dir=str(artifacts), mode="target_pipeline"),
    )

    assert result.review_ready is True
    assert result.promotion_ready is False
    assert result.preflight_ready is False
    assert result.task_count == 1
    assert "preflight blocked: project cache missing for target app" in result.blockers
    assert "target-pipeline.json missing after blocked preflight" in result.warnings
    assert result.next_actions[0].startswith("Run windows_bootstrap_project_facts")
    assert result.evidence_bundle.coverage.validation_ready is False


def test_windows_runner_artifact_review_accepts_clean_ghidra_refresh(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    _write_json(
        artifacts / "corpus-guard.json",
        {
            "claim_level": "corpus_guard_not_finding",
            "drift_guard_passed": True,
            "fixture_count": 30,
            "manifest_drift_count": 0,
            "unaccepted_manifest_drift_count": 0,
        },
    )
    _write_json(
        artifacts / "glaurung_vs_ghidra_vendor_windows_30_refresh.json",
        {"files": [], "summary": {"missing_count": 0, "extra_count": 0}},
    )
    (artifacts / "glaurung_vs_ghidra_vendor_windows_30_refresh.md").write_text(
        "# refreshed parity\n",
        encoding="utf-8",
    )
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(artifact_dir=str(artifacts), mode="ghidra_parity"),
    )

    assert result.review_ready is True
    assert result.promotion_ready is True
    assert result.blockers == []
    assert "glaurung_vs_ghidra_vendor_windows_30_refresh.json" in result.promotable_artifacts
    assert "glaurung_vs_ghidra_vendor_windows_30_refresh.md" in result.promotable_artifacts


def test_windows_runner_artifact_review_cli_json(tmp_path: Path, capsys) -> None:
    artifacts = tmp_path / "artifacts"
    _write_json(
        artifacts / "preflight.json",
        {
            "claim_level": "high_volume_preflight_not_analysis",
            "ready": True,
            "target_count": 1,
            "ready_target_count": 1,
            "blocked_target_count": 0,
            "blockers": [],
        },
    )
    _write_json(
        artifacts / "target-pipeline.json",
        {
            "claim_level": "target_pipeline_not_finding",
            "candidate_count": 1,
            "blocker_work_item_count": 0,
            "blockers": [],
        },
    )
    _write_json(
        artifacts / "blocker-task-plan.json",
        {"claim_level": "pipeline_blocker_task_plan_not_finding", "task_count": 0, "tasks": []},
    )

    rc = GlaurungCLI().run(
        [
            "windows",
            "runner-artifact-review",
            "--artifact-dir",
            str(artifacts),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["promotion_ready"] is True
    assert output["candidate_count"] == 1


def test_memory_agent_registers_windows_runner_artifact_review() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_runner_artifact_review" in agent._function_toolset.tools
