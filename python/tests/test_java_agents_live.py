"""Live-API smoke tests for Java pydantic-ai agents.

These tests hit a configured provider and are intentionally gated. Run with:

    GLAURUNG_LIVE_LLM=1 uv run pytest python/tests/test_java_agents_live.py -q

They verify the real provider path, focused tool registration, profile
pre-seeding, and structured pydantic output on a tiny generated JAR.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import warnings
from pathlib import Path

import pytest


LIVE = os.environ.get("GLAURUNG_LIVE_LLM") == "1"


def _has_credentials() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
    )


pytestmark = pytest.mark.skipif(
    not (LIVE and _has_credentials()),
    reason="live LLM test - set GLAURUNG_LIVE_LLM=1 and provide a model key",
)


def _compile_live_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")

    src = tmp_path / "src" / "app"
    out = tmp_path / "classes"
    src.mkdir(parents=True)
    out.mkdir()
    source = src / "LiveJavaAgentFixture.java"
    source.write_text(
        """
package app;

import java.nio.file.Files;
import java.nio.file.Path;

public final class LiveJavaAgentFixture {
    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            runCommand(args[0]);
        }
    }

    public static String runCommand(String command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        return new String(process.getInputStream().readAllBytes());
    }

    public static void writeMarker(Path root) throws Exception {
        Files.writeString(root.resolve("marker.txt"), System.getenv("JAVA_HOME"));
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "live-java-agent-fixture.jar"
    subprocess.run(
        [
            "jar",
            "--create",
            "--file",
            str(jar_path),
            "--main-class",
            "app.LiveJavaAgentFixture",
            "-C",
            str(out),
            ".",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_live_java_security_agent_returns_structured_tool_backed_assessment(
    tmp_path: Path,
) -> None:
    from glaurung.llm.agents.java import (
        JavaSecurityAssessment,
    )
    from glaurung.llm.agents.java_runner import run_java_security_analysis
    from glaurung.llm.config import get_config

    jar_path = _compile_live_fixture(tmp_path)

    cfg = get_config()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = run_java_security_analysis(
            jar_path,
            model=cfg.preferred_model(),
            prompt=(
                "Analyze this JAR for evidence-backed Java security behavior. "
                "Use java_risk_report before making findings."
            ),
        )
    output = result.assessment

    assert isinstance(output, JavaSecurityAssessment)
    assert output.confidence >= 0.2
    assert any(category == "process" for category in output.risky_categories)
    assert any(
        finding.class_name == "app/LiveJavaAgentFixture"
        and finding.method_name == "runCommand"
        for finding in output.findings
    )

    assert result.tool_calls[0].tool == "java_agent_context"
    assert result.tool_calls[0].args["profile"] == "security"
    assert "java_risk_report" in {call.tool for call in result.tool_calls}
    assert not any(
        "dict` fields are not supported by Anthropic" in str(item.message)
        for item in caught
    )
