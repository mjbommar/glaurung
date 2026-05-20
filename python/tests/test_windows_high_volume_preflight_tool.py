from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_high_volume_preflight import build_tool


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
  notes: Synthetic high-volume target.
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


def _write_metadata(tmp_path: Path, names: list[str]) -> None:
    for name in names:
        (tmp_path / name).write_text("[]\n", encoding="utf-8")


def test_windows_high_volume_preflight_reports_ready_and_blocked_targets(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "binaries"
    projects = tmp_path / "projects"
    (corpus / "windows-10-x64").mkdir(parents=True)
    (projects / "windows-10-x64").mkdir(parents=True)
    (corpus / "windows-10-x64" / "driver.sys").write_bytes(b"MZdriver")
    (projects / "windows-10-x64" / "driver.glaurung").write_bytes(b"sqlite")
    (corpus / "apps").mkdir(parents=True)
    (corpus / "apps" / "app.dll").write_bytes(b"MZapp")
    _write_metadata(
        tmp_path,
        [
            "pe-sinks.yaml",
            "pe-sources.yaml",
            "pe-gates.yaml",
            "pe-project-facts.yaml",
            "pe-validation-inventory.yaml",
            "pe-ghidra-delta.yaml",
            "pe-vulnerability-seeds.yaml",
        ],
    )

    tool = build_tool()
    ctx = _ctx(tmp_path)
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            build_corpus_manifest=str(_write_manifest(tmp_path)),
            corpus_root=str(corpus),
            project_root=str(projects),
            metadata_root=str(tmp_path),
            max_targets=4,
            require_ghidra=False,
            require_bsim=False,
        ),
    )

    assert result.claim_level == "high_volume_preflight_not_analysis"
    assert result.ready is False
    assert result.target_count == 2
    assert result.ready_target_count == 1
    assert result.blocked_target_count == 1
    assert result.metadata_ready is True
    assert result.optional_metadata_ready is False
    assert any(item.target_id == "driver" and item.ready for item in result.targets)
    missing = next(item for item in result.targets if item.target_id == "missing_project")
    assert missing.corpus_match_count == 1
    assert missing.project_match_count == 0
    assert "project cache missing for target missing_project" in missing.blockers
    assert any("pe-operation-classification-backlog.yaml" in item for item in result.warnings)
    assert result.high_volume_command
    assert "--blocker-worklist-path" in result.high_volume_command
    assert result.evidence_bundle.coverage.validation_ready is False


def test_windows_high_volume_preflight_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    corpus = tmp_path / "binaries"
    projects = tmp_path / "projects"
    (corpus / "windows-10-x64").mkdir(parents=True)
    (projects / "windows-10-x64").mkdir(parents=True)
    (corpus / "windows-10-x64" / "driver.sys").write_bytes(b"MZdriver")
    (projects / "windows-10-x64" / "driver.glaurung").write_bytes(b"sqlite")
    _write_metadata(
        tmp_path,
        [
            "pe-sinks.yaml",
            "pe-sources.yaml",
            "pe-gates.yaml",
            "pe-project-facts.yaml",
            "pe-validation-inventory.yaml",
            "pe-ghidra-delta.yaml",
        ],
    )

    rc = GlaurungCLI().run(
        [
            "windows",
            "high-volume-preflight",
            "--build-corpus-manifest",
            str(_write_manifest(tmp_path)),
            "--corpus-root",
            str(corpus),
            "--project-root",
            str(projects),
            "--metadata-root",
            str(tmp_path),
            "--target-id",
            "driver",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ready"] is True
    assert output["target_count"] == 1
    assert output["ready_target_count"] == 1
    assert output["blockers"] == []
    assert "glaurung windows target-pipeline" in output["high_volume_command"]


def test_memory_agent_registers_windows_high_volume_preflight() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_high_volume_preflight" in agent._function_toolset.tools
