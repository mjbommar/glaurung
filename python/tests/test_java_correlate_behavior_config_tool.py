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


def _compile_config_fixture(tmp_path: Path) -> tuple[Path, Path]:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    config_root = tmp_path / "config"
    src.mkdir()
    out.mkdir()
    config_root.mkdir()
    (src / "ConfigFixture.java").write_text(
        """
import java.nio.file.Files;
import java.nio.file.Path;

public class ConfigFixture {
    public void telemetry(Path path) throws Exception {
        boolean enabled = Boolean.getBoolean("telemetry.enabled");
        if (enabled) {
            Files.writeString(path.resolve("telemetry.log"), "enabled");
        }
    }

    public void networkFlag() {
        String host = System.getProperty("network.endpoint");
        if (host != null) {
            System.getenv("NETWORK_TOKEN");
        }
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
            str(src / "ConfigFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "config-fixture.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    (config_root / "app.properties").write_text(
        "telemetry.enabled=false\nnetwork.endpoint=https://example.invalid\n",
        encoding="utf-8",
    )
    return jar_path, config_root


def test_java_correlate_behavior_config_reports_config_states(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_correlate_behavior_config import build_tool

    jar, config_root = _compile_config_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), config_roots=[str(config_root)]),
    )

    assert result.finding_count >= 2
    assert result.correlation_count >= 2
    assert result.summary_by_state["configured_disabled"] >= 1
    assert result.summary_by_state["configured_unknown"] >= 1
    telemetry = next(
        correlation
        for correlation in result.correlations
        if correlation.finding.category == "filesystem"
    )
    assert telemetry.config_state == "configured_disabled"
    assert telemetry.matched_config_keys == ["telemetry.enabled"]
    assert telemetry.matched_constants == ["telemetry.enabled"]
    network = next(
        correlation
        for correlation in result.correlations
        if "network.endpoint" in correlation.matched_config_keys
    )
    assert network.config_state == "configured_unknown"
    assert any(n.kind == NodeKind.java_config_correlation for n in ctx.kb.nodes())


def test_java_correlate_behavior_config_returns_capability_only_without_config(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_correlate_behavior_config import build_tool

    jar, _config_root = _compile_config_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.correlation_count >= 1
    assert result.summary_by_state["capability_only"] >= 1
    assert all(
        correlation.config_state == "capability_only"
        for correlation in result.correlations
    )


def test_memory_agent_registers_java_correlate_behavior_config() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_correlate_behavior_config" in agent._function_toolset.tools
