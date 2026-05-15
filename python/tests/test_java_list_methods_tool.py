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


def _compile_source(tmp_path: Path, source: str) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java method fixture")
    src = tmp_path / "src"
    classes = tmp_path / "classes"
    src.mkdir()
    classes.mkdir()
    source_path = src / "Main.java"
    source_path.write_text(source.strip() + "\n", encoding="utf-8")
    subprocess.run(
        ["javac", "--release", "17", "-d", str(classes), str(source_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "methods.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar), "-C", str(classes), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar


def test_java_list_methods_filters_and_records_kb_nodes(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_methods import build_tool

    jar = _compile_source(
        tmp_path,
        """
package app;

public class Main {
    public String value() {
        return "hello";
    }

    private int helper(int count) {
        return count + 1;
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
            class_filter="app.Main",
            name_filter="value",
            include_constructors=False,
        ),
    )

    assert result.truncated is False
    assert result.matched_method_count == 1
    method = result.methods[0]
    assert method.class_name == "app/Main"
    assert method.name == "value"
    assert method.descriptor == "()Ljava/lang/String;"
    assert method.code_length is not None and method.code_length > 0
    assert any(
        node.kind == NodeKind.java_method
        and node.props.get("tool") == "java_list_methods"
        and node.props.get("name") == "value"
        for node in ctx.kb.nodes()
    )


def test_java_list_methods_can_return_annotation_descriptors(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_methods import build_tool

    jar = _compile_source(
        tmp_path,
        """
package app;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@interface Marker {}

public class Main {
    @Marker
    public void annotated() {}
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
            name_filter="annotated",
            include_annotations=True,
        ),
    )

    assert result.matched_method_count == 1
    assert result.methods[0].annotation_descriptors == ["Lapp/Marker;"]


def test_java_list_methods_respects_limit(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_methods import build_tool

    jar = _compile_source(
        tmp_path,
        """
package app;

public class Main {
    public void a() {}
    public void b() {}
}
""",
    )
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), limit=1))

    assert result.matched_method_count == 1
    assert result.truncated is True
    assert result.stop_reasons == ["limit"]


def test_memory_agent_registers_java_list_methods() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_list_methods" in agent._function_toolset.tools
