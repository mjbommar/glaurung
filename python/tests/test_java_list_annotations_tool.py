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


def _compile_annotation_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java annotation fixture")
    src = tmp_path / "src"
    classes = tmp_path / "classes"
    app = src / "app"
    app.mkdir(parents=True)
    classes.mkdir()
    (app / "Marker.java").write_text(
        """
package app;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PACKAGE, ElementType.TYPE, ElementType.FIELD, ElementType.METHOD, ElementType.RECORD_COMPONENT})
public @interface Marker {
    String value();
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (app / "package-info.java").write_text(
        '@Marker("package") package app;\n',
        encoding="utf-8",
    )
    (app / "Annotated.java").write_text(
        """
package app;

@Marker("class")
public class Annotated {
    @Marker("field")
    public static final String NAME = "annotated";

    @Deprecated
    @Marker("method")
    public void oldMethod() {}
}

record AnnotatedRecord(@Marker("component") String name) {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "-g",
            "--release",
            "17",
            "-d",
            str(classes),
            str(app / "Marker.java"),
            str(app / "package-info.java"),
            str(app / "Annotated.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "annotations.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar), "-C", str(classes), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar


def test_java_list_annotations_summarizes_archive_annotations_and_package_info(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_annotations import build_tool

    jar = _compile_annotation_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.archive_path == str(jar)
    assert result.class_count_scanned >= 4
    assert result.package_info_count == 1
    assert result.annotation_count_seen >= 5
    assert result.descriptor_counts["Lapp/Marker;"] >= 4
    assert result.descriptor_counts["Ljava/lang/Deprecated;"] >= 1

    marker_targets = {
        (
            item.target_kind,
            item.class_name,
            item.member_name,
            item.record_component_name,
        )
        for item in result.annotations
        if item.descriptor == "Lapp/Marker;"
    }
    assert ("package", "app/package-info", None, None) in marker_targets
    assert ("class", "app/Annotated", None, None) in marker_targets
    assert ("field", "app/Annotated", "NAME", None) in marker_targets
    assert ("method", "app/Annotated", "oldMethod", None) in marker_targets
    assert ("record_component", "app/AnnotatedRecord", None, "name") in marker_targets

    assert any(
        node.kind == NodeKind.java_annotation
        and node.props.get("tool") == "java_list_annotations"
        and node.props.get("descriptor") == "Lapp/Marker;"
        for node in ctx.kb.nodes()
    )


def test_java_list_annotations_filters_by_descriptor(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_annotations import build_tool

    jar = _compile_annotation_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), descriptor_filter="Deprecated"),
    )

    assert result.matched_annotation_count >= 1
    assert {item.descriptor for item in result.annotations} == {
        "Ljava/lang/Deprecated;"
    }


def test_memory_agent_registers_java_list_annotations() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_list_annotations" in agent._function_toolset.tools
