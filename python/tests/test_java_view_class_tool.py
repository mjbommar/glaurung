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


def _compile_obfuscated_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "a.java").write_text(
        """
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.List;

@Retention(RetentionPolicy.RUNTIME)
@interface Marker {
    String value();
}

@Marker("game-thing")
public class a implements Runnable {
    public int b = 1;
    public String d = "hello";
    public List<String> g = List.of("hello");
    public static class f {}
    @Marker("tick")
    public void c() { b++; }
    public int e(int value) { return b + value; }
    public void h(@Marker("param") String input) {}
    public int j(boolean flag) {
        if (flag) {
            return 1;
        }
        return 2;
    }
    public Runnable k() {
        return () -> System.out.println("lambda");
    }
    public void run() {}
}

record r(String token, int count) {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "-parameters",
            "--release",
            "17",
            "-d",
            str(out),
            str(src / "a.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "obfuscated.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _compile_sealed_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "sealed-src"
    out = tmp_path / "sealed-classes"
    src.mkdir()
    out.mkdir()
    (src / "Shape.java").write_text(
        """
public sealed interface Shape permits Circle, Square {}

final class Circle implements Shape {}

non-sealed class Square implements Shape {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "-g", "--release", "17", "-d", str(out), str(src / "Shape.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "sealed.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _compile_module_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java module fixture")
    src = tmp_path / "module-src"
    out = tmp_path / "module-classes"
    src.mkdir()
    out.mkdir()
    (src / "module-info.java").write_text(
        """
module com.example.fixture {
    requires java.logging;
    exports com.example.api;
    opens com.example.internal;
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    api = src / "com" / "example" / "api"
    internal = src / "com" / "example" / "internal"
    api.mkdir(parents=True)
    internal.mkdir(parents=True)
    (api / "Api.java").write_text(
        "package com.example.api; public class Api {}\n",
        encoding="utf-8",
    )
    (internal / "Internal.java").write_text(
        "package com.example.internal; public class Internal {}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "-g",
            "--release",
            "17",
            "-d",
            str(out),
            str(src / "module-info.java"),
            str(api / "Api.java"),
            str(internal / "Internal.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "module.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "mappings.txt"
    path.write_text(
        """
com.example.GameThing -> a:
    int health -> b
    java.lang.String greeting -> d
    void tick() -> c
    void unrelated(java.lang.String) -> c
    int score(int) -> e
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def test_java_view_class_applies_mapping_to_actual_class_members(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_view_class import build_tool

    jar = _compile_obfuscated_jar(tmp_path)
    mapping = _mapping_file(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="com.example.GameThing",
            mapping_path=str(mapping),
        ),
    )

    assert result.class_found
    assert result.matched_by == "official"
    assert result.class_name == "a"
    assert result.mapped_class_name == "com.example.GameThing"
    assert result.source_file == "a.java"
    assert "public" in result.access_flag_names
    assert "super" in result.access_flag_names
    assert result.java_release == 17
    assert result.classfile_version_label == "Java 17 (classfile 61.0)"
    assert result.classfile_size is not None and result.classfile_size > 0
    assert result.classfile_warnings == []
    assert result.bootstrap_method_count > 0
    assert result.methods_with_code >= 4
    assert result.method_code_length_total > 0
    assert result.method_instruction_count > 0
    assert result.method_line_number_count > 0
    assert result.invoke_instruction_count > 0
    assert result.field_instruction_count > 0
    assert result.dynamic_instruction_count > 0
    assert result.return_instruction_count > 0
    assert result.annotations[0].descriptor == "LMarker;"
    assert result.annotations[0].elements[0].value.value == "game-thing"
    assert any(item.inner_class == "a$f" for item in result.inner_classes)
    field_b = next(f for f in result.fields if f.name == "b")
    field_g = next(f for f in result.fields if f.name == "g")
    method_c = next(m for m in result.methods if m.name == "c")
    method_h = next(m for m in result.methods if m.name == "h")
    method_j = next(m for m in result.methods if m.name == "j")
    assert field_b.mapped_names == ["health"]
    assert field_b.field_type == "int"
    assert field_b.access_flag_names == ["public"]
    assert field_g.field_type == "java.util.List"
    assert field_g.generic_signature == "Ljava/util/List<Ljava/lang/String;>;"
    assert field_g.generic_field_type == "java.util.List<java.lang.String>"
    assert method_c.mapped_names == ["tick"]
    assert method_c.access_flag_names == ["public"]
    assert method_c.parameter_types == []
    assert method_c.return_type == "void"
    assert method_c.annotations[0].elements[0].value.value == "tick"
    assert method_h.method_parameters[0].name == "input"
    assert method_h.parameter_annotations[0].parameter_index == 0
    assert method_h.parameter_annotations[0].annotations[0].elements[0].value.value == (
        "param"
    )
    assert method_c.code is not None
    assert method_c.code.code_length > 0
    assert method_c.code.field_xref_count >= 2
    assert method_c.code.field_instruction_count >= 2
    assert method_c.code.line_number_count >= 1
    assert method_c.code.first_line is not None
    assert method_c.code.last_line is not None
    assert method_j.code is not None
    assert method_j.code.stack_map_frame_count > 0
    assert method_j.code.branch_instruction_count >= 1
    assert method_j.code.return_instruction_count >= 1
    assert any(
        n.kind == NodeKind.java_class
        and n.props.get("mapped_class_name") == "com.example.GameThing"
        and n.props.get("source_file") == "a.java"
        and n.props.get("annotations", [{}])[0].get("descriptor") == "LMarker;"
        for n in ctx.kb.nodes()
    )
    assert any(
        n.kind == NodeKind.java_method
        and n.props.get("mapped_names") == ["tick"]
        and n.props.get("source_file") == "a.java"
        for n in ctx.kb.nodes()
    )
    class_node = next(
        node
        for node in ctx.kb.nodes()
        if node.kind == NodeKind.java_class
        and node.props.get("mapped_class_name") == "com.example.GameThing"
    )
    assert any(
        edge.src == class_node.id
        and edge.kind == "implements"
        and edge.props.get("target_class") == "java/lang/Runnable"
        for edge in ctx.kb.edges()
    )


def test_java_view_class_reports_record_components(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_view_class import build_tool

    jar = _compile_obfuscated_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), class_name="r", include_members=False),
    )

    assert result.class_found
    assert result.source_file == "a.java"
    assert result.super_class == "java/lang/Record"
    assert result.class_kind == "record"
    assert result.is_record is True
    assert [item.name for item in result.record_components] == ["token", "count"]
    assert result.record_components[0].descriptor == "Ljava/lang/String;"
    assert result.record_components[1].descriptor == "I"
    assert any(
        n.kind == NodeKind.java_class
        and n.props.get("class_name") == "r"
        and n.props.get("record_component_count") == 2
        for n in ctx.kb.nodes()
    )


def test_java_view_class_reports_permitted_subclasses(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_view_class import build_tool

    jar = _compile_sealed_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), class_name="Shape"))

    assert result.class_found
    assert result.is_sealed is True
    assert result.permitted_subclasses == ["Circle", "Square"]
    class_node = next(
        node
        for node in ctx.kb.nodes()
        if node.kind == NodeKind.java_class and node.props.get("class_name") == "Shape"
    )
    assert class_node.props["permitted_subclasses"] == ["Circle", "Square"]


def test_java_view_class_reports_module_info(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_view_class import build_tool

    jar = _compile_module_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), class_name="module-info"),
    )

    assert result.class_found
    assert result.class_kind == "module"
    assert result.module_info is not None
    assert result.module_info.name == "com.example.fixture"
    assert {item.module for item in result.module_info.requires} >= {
        "java.base",
        "java.logging",
    }
    assert [item.package for item in result.module_info.exports] == ["com/example/api"]
    assert [item.package for item in result.module_info.opens] == [
        "com/example/internal"
    ]


def test_java_view_class_can_lookup_by_obfuscated_name(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_view_class import build_tool

    jar = _compile_obfuscated_jar(tmp_path)
    mapping = _mapping_file(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), class_name="a", mapping_path=str(mapping)),
    )

    assert result.class_found
    assert result.matched_by == "obfuscated"
    assert result.mapped_class_name == "com.example.GameThing"
    assert {m.mapped_names[0] for m in result.methods if m.mapped_names} >= {
        "tick",
        "score",
    }


def test_memory_agent_registers_java_view_class() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_view_class" in agent._function_toolset.tools
