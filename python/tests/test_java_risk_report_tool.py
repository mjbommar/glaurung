from __future__ import annotations

import shutil
import subprocess
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


def _compile_risk_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "RiskFixture.java").write_text(
        """
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

public class RiskFixture {
    public static void main(String[] args) {
        System.getProperty("network.endpoint");
    }

    public static void telemetry(Path root) throws Exception {
        if (Boolean.getBoolean("telemetry.enabled")) {
            Files.writeString(root.resolve("telemetry.log"), "enabled");
        }
    }

    public static void connect() throws Exception {
        URL url = new URL(System.getProperty("network.endpoint"));
        url.openConnection().connect();
    }

    public static String token() {
        return "api_key=ZXCVBNmasdf1234TOKENxx";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "RiskFixture.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "risk-fixture.jar"
    subprocess.run(
        [
            "jar",
            "--create",
            "--file",
            str(jar_path),
            "--main-class",
            "RiskFixture",
            "-C",
            str(out),
            ".",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_java_risk_report_ranks_configured_behavior_and_secrets(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_risk_report import build_tool

    jar = _compile_risk_jar(tmp_path)
    config = tmp_path / "config"
    config.mkdir()
    (config / "app.properties").write_text(
        "\n".join(
            [
                "telemetry.enabled=false",
                "network.endpoint=https://example.invalid",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            config_roots=[str(config)],
            max_findings=64,
            max_risk_items=32,
        ),
    )

    assert result.archive_path == str(jar)
    assert result.risk_item_count >= 3
    assert result.sensitive_finding_count >= 3
    assert result.secret_candidate_count >= 1
    assert result.entrypoint_count >= 1
    assert result.summary_by_category["filesystem"] >= 1
    assert result.summary_by_category["network"] >= 1
    assert any(
        item.category == "filesystem"
        and item.config_state == "configured_disabled"
        and item.matched_config_keys == ["telemetry.enabled"]
        for item in result.risk_items
    )
    assert any(
        item.category == "network"
        and item.config_state == "configured_unknown"
        and item.matched_config_keys == ["network.endpoint"]
        for item in result.risk_items
    )
    assert any(item.kind == "secret" for item in result.risk_items)
    assert any(
        n.kind == NodeKind.java_risk_finding
        and n.props.get("tool") == "java_risk_report"
        for n in ctx.kb.nodes()
    )


def test_memory_agent_registers_java_risk_report() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_risk_report" in agent._function_toolset.tools
