from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from _pytest.capture import CaptureFixture

from glaurung import cli


def _security_fixture_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")

    src = tmp_path / "src" / "app"
    out = tmp_path / "classes"
    src.mkdir(parents=True)
    out.mkdir()
    source = src / "RunnerFixture.java"
    source.write_text(
        """
package app;

public final class RunnerFixture {
    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            runCommand(args[0]);
        }
    }

    public static void runCommand(String command) throws Exception {
        new ProcessBuilder(command).start();
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
    jar = tmp_path / "runner-fixture.jar"
    subprocess.run(
        [
            "jar",
            "--create",
            "--file",
            str(jar),
            "--main-class",
            "app.RunnerFixture",
            "-C",
            str(out),
            ".",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar


def test_run_java_security_analysis_returns_tool_backed_result(tmp_path: Path) -> None:
    from glaurung.llm.agents.java_runner import run_java_security_analysis

    jar = _security_fixture_jar(tmp_path)

    result = run_java_security_analysis(
        str(jar),
        model="test",
        max_classes=16,
        max_findings=16,
    )

    assert result.profile == "security"
    assert result.context.profile == "security"
    assert result.assessment_type == "JavaSecurityAssessment"
    assert result.tool_call_count >= 1
    assert result.tool_calls[0].tool == "java_agent_context"
    assert result.tool_calls[0].seeded is True
    assert "java_risk_report" in {call.tool for call in result.tool_calls}


def test_java_security_cli_outputs_json(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    jar = _security_fixture_jar(tmp_path)

    rc = cli.main(
        [
            "java",
            "security",
            str(jar),
            "--model",
            "test",
            "--max-classes",
            "16",
            "--max-findings",
            "16",
            "--json",
        ]
    )

    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["profile"] == "security"
    assert data["context"]["profile"] == "security"
    assert data["assessment_type"] == "JavaSecurityAssessment"
    assert data["tool_call_count"] >= 1

    rc = cli.main(
        [
            "java",
            "--json",
            "security",
            str(jar),
            "--model",
            "test",
            "--max-classes",
            "16",
            "--max-findings",
            "16",
        ]
    )

    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["profile"] == "security"
