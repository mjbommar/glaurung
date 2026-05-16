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


def _compile_source(
    tmp_path: Path,
    source: str,
    javac_args: list[str] | None = None,
) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java method fixture")
    src = tmp_path / "src"
    classes = tmp_path / "classes"
    src.mkdir()
    classes.mkdir()
    source_path = src / "Main.java"
    source_path.write_text(source.strip() + "\n", encoding="utf-8")
    subprocess.run(
        [
            "javac",
            *(javac_args or []),
            "--release",
            "17",
            "-d",
            str(classes),
            str(source_path),
        ],
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
    assert method.parameter_types == []
    assert method.parameter_count == 0
    assert method.return_type == "java.lang.String"
    assert method.code_length is not None and method.code_length > 0
    assert method.source_file == "Main.java"
    assert method.line_number_count >= 1
    assert method.first_line is not None
    assert method.last_line is not None
    assert any(
        node.kind == NodeKind.java_method
        and node.props.get("tool") == "java_list_methods"
        and node.props.get("name") == "value"
        and node.props.get("source_file") == "Main.java"
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


def test_java_list_methods_decodes_complex_method_descriptors(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_methods import build_tool

    jar = _compile_source(
        tmp_path,
        """
package app;

import java.util.List;

public class Main {
    public int combine(String[] names, int[][] scores, List<String> labels) {
        return names.length + scores.length + labels.size();
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
            name_filter="combine",
            include_constructors=False,
        ),
    )

    assert result.matched_method_count == 1
    method = result.methods[0]
    assert method.descriptor == "([Ljava/lang/String;[[ILjava/util/List;)I"
    assert method.parameter_types == [
        "java.lang.String[]",
        "int[][]",
        "java.util.List",
    ]
    assert method.parameter_count == 3
    assert method.return_type == "int"
    assert method.descriptor_error is None
    assert method.generic_signature == (
        "([Ljava/lang/String;[[ILjava/util/List<Ljava/lang/String;>;)I"
    )


def test_java_list_methods_reports_parameter_metadata_and_annotation_defaults(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_methods import build_tool

    jar = _compile_source(
        tmp_path,
        """
package app;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.METHOD})
@interface ParamTag {
    String value() default "fallback";
}

public class Main {
    public void handle(@ParamTag("path") String path, int count) {}
}
""",
        javac_args=["-parameters"],
    )
    ctx = _ctx(jar)
    tool = build_tool()

    handle_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_filter="app.Main",
            name_filter="handle",
            include_constructors=False,
        ),
    )
    default_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_filter="app.ParamTag",
            name_filter="value",
            include_constructors=False,
        ),
    )

    assert handle_result.matched_method_count == 1
    handle = handle_result.methods[0]
    assert handle.method_parameter_names == ["path", "count"]
    assert handle.method_parameter_count == 2
    assert handle.parameter_annotation_count == 1
    assert handle.has_annotation_default is False

    assert default_result.matched_method_count == 1
    default = default_result.methods[0]
    assert default.has_annotation_default is True
    assert default.annotation_default == {
        "tag": "s",
        "kind": "const",
        "value": "fallback",
    }


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
