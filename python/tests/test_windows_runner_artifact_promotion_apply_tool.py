from __future__ import annotations

import hashlib
import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_runner_artifact_promotion_apply import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    return MemoryContext(file_path=str(path), artifact=artifact)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_plan(tmp_path: Path, *, source_body: bytes = b"fresh") -> tuple[Path, Path, Path]:
    source = tmp_path / "artifacts" / "refresh.json"
    destination = tmp_path / "docs" / "windows-port" / "baseline.json"
    source.parent.mkdir(parents=True)
    source.write_bytes(source_body)
    plan = tmp_path / "promotion-plan.json"
    plan.write_text(
        json.dumps(
            {
                "claim_level": "runner_artifact_promotion_plan_not_finding",
                "promotion_allowed": True,
                "action_count": 1,
                "actions": [
                    {
                        "operation": "copy",
                        "source_artifact": "refresh.json",
                        "source_path": str(source),
                        "destination_path": str(destination),
                        "source_sha256": _sha256(source),
                        "destination_exists": False,
                        "command": f"cp {source} {destination}",
                        "reason_codes": ["artifact_baseline_promotion"],
                    }
                ],
                "blockers": [],
                "warnings": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return plan, source, destination


def test_windows_runner_artifact_promotion_apply_dry_run_verifies_hash(
    tmp_path: Path,
) -> None:
    plan, source, destination = _write_plan(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(plan_path=str(plan)),
    )

    assert result.claim_level == "runner_artifact_promotion_apply_not_finding"
    assert result.apply_requested is False
    assert result.verification_passed is True
    assert result.baseline_commit_ready is False
    assert result.applied_count == 0
    assert result.changed_destination_count == 1
    assert destination.exists() is False
    action = result.actions[0]
    assert action.source_path == str(source)
    assert action.destination_path == str(destination)
    assert action.source_hash_verified is True
    assert action.destination_would_change is True
    assert action.status == "dry_run"
    assert result.evidence_bundle.coverage.validation_ready is False


def test_windows_runner_artifact_promotion_apply_writes_output_path(
    tmp_path: Path,
) -> None:
    plan, _source, destination = _write_plan(tmp_path)
    output_path = tmp_path / "apply-result.json"
    review_markdown_path = tmp_path / "apply-review.md"
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            plan_path=str(plan),
            output_path=str(output_path),
            review_markdown_path=str(review_markdown_path),
        ),
    )

    assert result.output_path == str(output_path)
    assert result.review_markdown_path == str(review_markdown_path)
    assert destination.exists() is False
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["claim_level"] == "runner_artifact_promotion_apply_not_finding"
    assert payload["verification_passed"] is True
    assert payload["baseline_commit_ready"] is False
    assert payload["applied_count"] == 0
    assert payload["changed_destination_count"] == 1
    assert payload["actions"][0]["status"] == "dry_run"
    markdown = review_markdown_path.read_text(encoding="utf-8")
    assert "Baseline Commit Ready: no" in markdown
    assert "Rerun with `--apply-changes`" in markdown


def test_windows_runner_artifact_promotion_apply_copies_when_requested(
    tmp_path: Path,
) -> None:
    plan, source, destination = _write_plan(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(plan_path=str(plan), apply_changes=True),
    )

    assert result.apply_requested is True
    assert result.verification_passed is True
    assert result.baseline_commit_ready is True
    assert result.applied_count == 1
    assert destination.read_bytes() == source.read_bytes()
    action = result.actions[0]
    assert action.status == "applied"
    assert action.destination_sha256_after == _sha256(source)
    assert result.evidence_bundle.coverage.validation_ready is True


def test_windows_runner_artifact_promotion_apply_refuses_hash_mismatch(
    tmp_path: Path,
) -> None:
    plan, source, destination = _write_plan(tmp_path)
    source.write_bytes(b"tampered")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(plan_path=str(plan), apply_changes=True),
    )

    assert result.verification_passed is False
    assert result.baseline_commit_ready is False
    assert result.applied_count == 0
    assert destination.exists() is False
    assert any("source sha256 mismatch" in blocker for blocker in result.blockers)
    assert result.actions[0].status == "blocked"


def test_windows_runner_artifact_promotion_apply_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    plan, _source, _destination = _write_plan(tmp_path)

    rc = GlaurungCLI().run(
        [
            "windows",
            "runner-artifact-promotion-apply",
                "--plan-path",
                str(plan),
                "--review-markdown-path",
                str(tmp_path / "review.md"),
                "--format",
                "json",
            ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["verification_passed"] is True
    assert output["apply_requested"] is False
    assert output["review_markdown_path"] == str(tmp_path / "review.md")


def test_memory_agent_registers_windows_runner_artifact_promotion_apply() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_runner_artifact_promotion_apply" in agent._function_toolset.tools
