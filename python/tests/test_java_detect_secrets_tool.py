from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _compile_secret_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "SecretFixture.java").write_text(
        """
public class SecretFixture {
    public String openAiKey() {
        return "sk-test_1234567890abcdefghijklmnopqrstuvwxyz";
    }

    public String githubToken() {
        return "github_pat_11ABCDEFGH0123456789abcdefghijklmnopqrstuvwxyz";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(out),
            str(src / "SecretFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    resource = tmp_path / "secrets.properties"
    resource.write_text(
        "service.token=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
        "safe.value=not-secret\n",
        encoding="utf-8",
    )
    jar_path = tmp_path / "secrets.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    with zipfile.ZipFile(jar_path, "a") as zf:
        zf.write(resource, "config/secrets.properties")
    return jar_path


def test_java_detect_secrets_redacts_class_and_resource_candidates(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_detect_secrets import build_tool

    jar = _compile_secret_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.candidate_count >= 3
    assert result.summary_by_category["openai_api_key"] >= 1
    assert result.summary_by_category["github_token"] >= 2
    assert all(candidate.value is None for candidate in result.candidates)
    assert all(candidate.redacted_value_hash for candidate in result.candidates)
    assert {
        "class_string",
        "resource_text",
    } <= {candidate.source_type for candidate in result.candidates}
    assert not any("not-secret" in candidate.context for candidate in result.candidates)
    assert any(n.kind == NodeKind.java_secret for n in ctx.kb.nodes())


def test_java_detect_secrets_ignores_non_zip_inputs(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_detect_secrets import build_tool

    sample = tmp_path / "native.bin"
    sample.write_bytes(b"\x7fELFnot-a-jar")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(sample)))

    assert result.candidate_count == 0
    assert result.stop_reasons == ["input_not_zip"]


def test_memory_agent_registers_java_detect_secrets() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_detect_secrets" in agent._function_toolset.tools
