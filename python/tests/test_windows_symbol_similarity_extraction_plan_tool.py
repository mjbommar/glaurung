from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.context import MemoryContext
from glaurung.llm.tools.windows_symbol_similarity_extraction_plan import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    return MemoryContext(file_path=str(path), artifact=artifact)


def _write_pair(tmp_path: Path) -> tuple[Path, Path]:
    a = tmp_path / "driver-old.sys"
    b = tmp_path / "driver-new.sys"
    a.write_bytes(b"MZold")
    b.write_bytes(b"MZnew")
    return a, b


def test_windows_symbol_similarity_extraction_plan_writes_runner_script(
    tmp_path: Path,
) -> None:
    a, b = _write_pair(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()
    script_path = tmp_path / "extract-symbol-similarity.sh"

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            target_id="driver",
            component="driver.sys",
            build_label_a="old",
            build_label_b="new",
            pdb_identity_path=str(tmp_path / "pe-identity-manifest.yaml"),
            symbol_cache_root=str(tmp_path / "symbols"),
            ghidra_project_dir=str(tmp_path / "ghidra"),
            artifact_dir=str(tmp_path / "artifacts"),
            output_script_path=str(script_path),
            require_external_tools=False,
        ),
    )

    assert result.claim_level == "symbol_similarity_extraction_plan_not_analysis"
    assert result.ready_to_execute is True
    assert result.similarity_manifest_path.endswith("external-similarity.yaml")
    assert result.identity_output_path.endswith("function-identities.yaml")
    assert result.output_script_path == str(script_path)
    script = script_path.read_text(encoding="utf-8")
    assert "analyzeHeadless" in script
    assert "windows_patch_function_identity_extract" in script
    assert result.identity_extract_args["binary_a"] == str(a)
    assert result.identity_extract_args["binary_b"] == str(b)
    assert (
        result.identity_extract_args["external_similarity_manifest_path"]
        == result.similarity_manifest_path
    )
    assert (
        result.identity_extract_args["pdb_identity_manifest"]["identity_path"]
        == str(tmp_path / "pe-identity-manifest.yaml")
    )
    assert result.evidence_bundle.coverage.validation_ready is False


def test_windows_symbol_similarity_extraction_plan_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    a, b = _write_pair(tmp_path)

    rc = GlaurungCLI().run(
        [
            "windows",
            "symbol-similarity-plan",
            "--binary-a",
            str(a),
            "--binary-b",
            str(b),
            "--target-id",
            "driver",
            "--component",
            "driver.sys",
            "--artifact-dir",
            str(tmp_path / "artifacts"),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ready_to_execute"] is True
    assert output["identity_extract_args"]["binary_a"] == str(a)
    assert output["steps"][-1]["next_tool_name"] == "windows_patch_function_identity_extract"


def test_memory_agent_registers_windows_symbol_similarity_extraction_plan() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_symbol_similarity_extraction_plan" in agent._function_toolset.tools
