from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import glaurung as g
from glaurung.java import run_jvm_tool
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _fixture_jar(tmp_path: Path) -> tuple[Path, Path]:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java decompiler fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    source_path = src / "Main.java"
    source_path.write_text(
        """
package app;

public class Main {
    public static final String FIELD_CONST = "field-constant";

    public String value() {
        return "method-constant";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(source_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "decompile-fixture.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "Main.class", "app/Main.class")
    return jar, source_path


def test_jvm_helper_bytecode_summary_uses_asm(tmp_path: Path) -> None:
    jar, _source_path = _fixture_jar(tmp_path)

    result = run_jvm_tool(
        ["bytecode", "--jar", str(jar), "--class", "app.Main"],
        timeout_seconds=60,
    )

    assert result["success"] is True
    assert result["class_name"] == "app/Main"
    assert result["field_count"] == 1
    assert result["method_count"] >= 2
    assert result["helper_jar"].endswith("glaurung-jvm-tools-0.1.0-all.jar")


def test_java_decompile_class_cfr_returns_source_and_ast(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_decompile_class import build_tool

    jar, _source_path = _fixture_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), class_name="app.Main", engine="cfr"),
    )

    assert result.success is True
    assert result.engine == "cfr"
    assert result.class_name == "app/Main"
    assert result.source is not None
    assert "class Main" in result.source
    assert "field-constant" in result.source
    assert result.ast["parse_success"] is True
    assert result.ast["package_name"] == "app"
    assert result.decompile_node_id is not None
    assert any(
        node.kind == NodeKind.java_decompile_unit
        and node.props.get("tool") == "java_decompile_class"
        for node in ctx.kb.nodes()
    )


def test_java_parse_decompiled_source_reports_ast(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_parse_decompiled_source import build_tool

    _jar, source_path = _fixture_jar(tmp_path)
    ctx = _ctx(source_path)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(source_path=str(source_path)))

    assert result.success is True
    assert result.ast["parse_success"] is True
    assert result.ast["package_name"] == "app"
    assert result.parse_node_id is not None


def test_memory_agent_registers_java_decompiler_tools() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_decompile_class" in agent._function_toolset.tools
    assert "java_parse_decompiled_source" in agent._function_toolset.tools
