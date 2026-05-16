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


def _compile_jar(tmp_path: Path, source: str, main_class: str = "app.Main") -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java agent-context fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    package_dir = src / "app"
    package_dir.mkdir()
    java_path = package_dir / "Main.java"
    java_path.write_text(source.strip() + "\n", encoding="utf-8")
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(java_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "app.jar"
    manifest = f"Manifest-Version: 1.0\nMain-Class: {main_class}\n\n"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        for class_file in sorted(out.rglob("*.class")):
            zf.write(class_file, class_file.relative_to(out).as_posix())
    return jar


def test_java_agent_context_triage_profile_builds_runbook(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_agent_context import build_tool

    jar = _compile_jar(
        tmp_path,
        """
package app;

public class Main {
    public static void main(String[] args) {
        System.out.println("hello");
    }
}
""",
    )
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), profile="triage", max_classes=16),
    )

    assert result.is_java_archive is True
    assert result.archive is not None
    assert result.archive.class_count == 1
    assert result.entrypoints is not None
    assert result.entrypoints.entrypoint_count >= 1
    assert "java_view_class" in result.recommended_next_tools
    assert any("Start with" in step for step in result.runbook)
    assert any(
        node.kind == NodeKind.java_agent_context
        and node.props.get("tool") == "java_agent_context"
        for node in ctx.kb.nodes()
    )


def test_java_agent_context_security_profile_summarizes_risk(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_agent_context import build_tool

    jar = _compile_jar(
        tmp_path,
        """
package app;

public class Main {
    public void run(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }
}
""",
    )
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            profile="security",
            max_classes=16,
            max_findings=16,
        ),
    )

    assert result.security is not None
    assert result.security.sensitive_finding_count >= 1
    assert result.security.risk_item_count >= 1
    assert result.security.highest_severity in {"high", "critical"}
    assert "java_trace_to_sink" in result.recommended_next_tools
    assert any("process" in line.lower() for line in result.summary_lines)


def test_memory_agent_registers_java_agent_context() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_agent_context" in agent._function_toolset.tools
