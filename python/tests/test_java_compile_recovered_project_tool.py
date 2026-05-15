from __future__ import annotations

import shutil
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


def _write_project(root: Path, source: str, *, name: str = "Main.java") -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java compile fixture")
    src = root / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    source_path = src / name
    source_path.write_text(source.strip() + "\n", encoding="utf-8")
    return source_path


def test_java_compile_recovered_project_javac_success(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_compile_recovered_project import build_tool

    project = tmp_path / "project"
    source_path = _write_project(
        project,
        """
package app;

public class Main {
    public static void main(String[] args) {
        System.out.println("hello");
    }
}
""",
    )
    (project / "javac.args").write_text(
        "--release\n17\n-d\nbuild/classes\n@sources.txt\n",
        encoding="utf-8",
    )
    ctx = _ctx(source_path)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(source_project_root=str(project)))

    assert result.success is True
    assert result.exit_code == 0
    assert result.selected_build_tool == "javac"
    assert result.diagnostic_count == 0
    assert (project / "build" / "classes" / "app" / "Main.class").is_file()
    assert (
        (project / "sources.txt")
        .read_text(encoding="utf-8")
        .strip()
        .endswith("src/main/java/app/Main.java")
    )
    assert any(
        node.kind == NodeKind.java_compile_result
        and node.props.get("tool") == "java_compile_recovered_project"
        for node in ctx.kb.nodes()
    )


def test_java_compile_recovered_project_parses_missing_dependency(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_compile_recovered_project import build_tool

    project = tmp_path / "project"
    source_path = _write_project(
        project,
        """
package app;

import missing.DoesNotExist;

public class Broken {
    private DoesNotExist value;
}
""",
        name="Broken.java",
    )
    ctx = _ctx(source_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(project), java_release=17),
    )

    assert result.success is False
    assert result.exit_code != 0
    assert result.diagnostic_count >= 1
    assert any(
        diagnostic.category == "missing_classpath_dependency"
        for diagnostic in result.diagnostics
    )
    assert any(
        "missing.DoesNotExist" in diagnostic.message
        for diagnostic in result.diagnostics
    )


def test_java_compile_recovered_project_missing_root(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_compile_recovered_project import build_tool

    sample = tmp_path / "sample.txt"
    sample.write_text("sample\n", encoding="utf-8")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(tmp_path / "missing")),
    )

    assert result.success is False
    assert result.selected_build_tool == "unknown"
    assert result.stop_reasons == ["source_project_root_missing"]


def test_memory_agent_registers_java_compile_recovered_project() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_compile_recovered_project" in agent._function_toolset.tools
