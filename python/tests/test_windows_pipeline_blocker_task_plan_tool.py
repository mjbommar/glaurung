from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.agents.windows_target_pipeline import (
    WindowsTargetPipelineBlockerWorkItem,
    WindowsTargetPipelineBlockerWorklist,
)
from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_high_volume_preflight import (
    build_tool as build_preflight_tool,
)
from glaurung.llm.tools.windows_pipeline_blocker_task_plan import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    return MemoryContext(file_path=str(path), artifact=artifact)


def _write_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-build-corpus.yaml"
    manifest.write_text(
        """
- id: driver
  filename: driver.sys
  binary_kind: driver
  priority: high
  scan_roles: [ioctl_dispatch]
  surfaces: [ioctl]
  architectures: [x64]
  corpus_globs: ["windows-10-x64/driver.sys"]
  project_globs: ["windows-10-x64/driver.glaurung"]
- id: missing_project
  filename: app.dll
  binary_kind: dll
  priority: medium
  scan_roles: [com_server]
  surfaces: [local_service]
  architectures: [x64]
  corpus_globs: ["apps/app.dll"]
  project_globs: ["apps/app.glaurung"]
""",
        encoding="utf-8",
    )
    return manifest


def _write_metadata(tmp_path: Path) -> None:
    for name in [
        "pe-sinks.yaml",
        "pe-sources.yaml",
        "pe-gates.yaml",
        "pe-project-facts.yaml",
        "pe-validation-inventory.yaml",
        "pe-ghidra-delta.yaml",
    ]:
        (tmp_path / name).write_text("[]\n", encoding="utf-8")


def _write_preflight(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    corpus = tmp_path / "binaries"
    projects = tmp_path / "projects"
    (corpus / "windows-10-x64").mkdir(parents=True)
    (projects / "windows-10-x64").mkdir(parents=True)
    (corpus / "windows-10-x64" / "driver.sys").write_bytes(b"MZdriver")
    (projects / "windows-10-x64" / "driver.glaurung").write_bytes(b"sqlite")
    (corpus / "apps").mkdir(parents=True)
    (corpus / "apps" / "app.dll").write_bytes(b"MZapp")
    _write_metadata(tmp_path)
    manifest = _write_manifest(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_preflight_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            build_corpus_manifest=str(manifest),
            corpus_root=str(corpus),
            project_root=str(projects),
            metadata_root=str(tmp_path),
            max_targets=4,
        ),
    )
    path = tmp_path / "preflight.json"
    path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path, manifest, corpus, projects


def _write_blocker_worklist(tmp_path: Path) -> Path:
    worklist = WindowsTargetPipelineBlockerWorklist(
        blocker_work_item_count=1,
        work_items=[
            WindowsTargetPipelineBlockerWorkItem(
                rank=1,
                kind="symbol_similarity",
                blocker="missing BSim similarity manifest for patch pair",
                count=2,
                candidate_ids=["candidate-a", "candidate-b"],
                target_ids=["driver"],
                stages=["patch_diff"],
                required_artifact="PDB/symbol-server/BSim identity manifest",
                next_action="Extract PDB/symbol-server/BSim identity data.",
                reason_codes=["similarity_missing"],
            )
        ],
        tool_sequence=["windows_target_pipeline"],
    )
    path = tmp_path / "blocker-worklist.json"
    path.write_text(
        json.dumps(worklist.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def test_windows_pipeline_blocker_task_plan_turns_artifacts_into_tasks(
    tmp_path: Path,
) -> None:
    preflight_path, manifest, corpus, projects = _write_preflight(tmp_path)
    blocker_worklist = _write_blocker_worklist(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            preflight_path=str(preflight_path),
            blocker_worklist_path=str(blocker_worklist),
            build_corpus_manifest=str(manifest),
            corpus_root=str(corpus),
            project_root=str(projects),
            metadata_root=str(tmp_path),
            max_tasks=8,
        ),
    )

    assert result.claim_level == "pipeline_blocker_task_plan_not_finding"
    assert result.task_count == 2
    project_task = next(item for item in result.tasks if item.kind == "project_cache_refresh")
    assert project_task.source_kind == "preflight"
    assert project_task.target_ids == ["missing_project"]
    assert project_task.next_tool_name == "windows_bootstrap_project_facts"
    assert project_task.next_tool_args["pe_path"].endswith("apps/app.dll")
    assert project_task.next_tool_args["project_path"].endswith("apps/app.glaurung")
    assert project_task.next_tool_args["project_facts_output_path"] == str(
        tmp_path / "pe-project-facts.yaml"
    )
    assert project_task.next_tool_args["project_fact_id"] == "missing_project_unknown"
    assert project_task.next_tool_args["binary_filename"] == "app.dll"
    assert project_task.next_tool_args["architecture"] == "x64"
    assert "project cache missing for target missing_project" in project_task.blockers
    assert "windows_bootstrap_project_facts" in project_task.reason_codes
    assert project_task.commands[0].startswith(
        "uv run glaurung windows bootstrap-project-facts"
    )
    assert "--project-facts-output-path" in project_task.commands[0]
    assert "--project-fact-id missing_project_unknown" in project_task.commands[0]
    similarity_task = next(
        item for item in result.tasks if item.kind == "symbol_similarity_extract"
    )
    assert similarity_task.source_kind == "target_pipeline"
    assert similarity_task.candidate_ids == ["candidate-a", "candidate-b"]
    assert similarity_task.next_tool_name == "windows_symbol_similarity_extraction_plan"
    assert result.evidence_bundle.coverage.validation_ready is False


def test_windows_pipeline_blocker_task_plan_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    preflight_path, manifest, corpus, projects = _write_preflight(tmp_path)

    rc = GlaurungCLI().run(
        [
            "windows",
            "blocker-task-plan",
            "--preflight-path",
            str(preflight_path),
            "--build-corpus-manifest",
            str(manifest),
            "--corpus-root",
            str(corpus),
            "--project-root",
            str(projects),
            "--metadata-root",
            str(tmp_path),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["task_count"] == 1
    assert output["tasks"][0]["kind"] == "project_cache_refresh"
    assert output["tasks"][0]["next_tool_name"] == "windows_bootstrap_project_facts"
    assert output["tasks"][0]["next_tool_args"]["project_facts_output_path"] == str(
        tmp_path / "pe-project-facts.yaml"
    )


def test_memory_agent_registers_windows_pipeline_blocker_task_plan() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_pipeline_blocker_task_plan" in agent._function_toolset.tools
