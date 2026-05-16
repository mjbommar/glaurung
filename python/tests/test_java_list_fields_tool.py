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


def _compile_field_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java field fixture")
    src = tmp_path / "src"
    classes = tmp_path / "classes"
    app = src / "app"
    app.mkdir(parents=True)
    classes.mkdir()
    source = app / "Fields.java"
    source.write_text(
        """
package app;

import java.util.List;

public class Fields<T extends Number> {
    @Deprecated
    public static final int ANSWER = 42;

    public static final String NAME = "glaurung";
    public List<T> values;
    private long hidden;
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "-g", "--release", "17", "-d", str(classes), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "fields.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar), "-C", str(classes), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar


def test_java_list_fields_reports_descriptors_constants_and_kb(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_fields import build_tool

    jar = _compile_field_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_filter="app.Fields",
            include_annotations=True,
        ),
    )

    assert result.archive_path == str(jar)
    assert result.class_count_scanned == 1
    assert result.field_count_seen == 4
    assert result.matched_field_count == 4
    assert result.truncated is False

    fields = {field.name: field for field in result.fields}
    answer = fields["ANSWER"]
    assert answer.class_name == "app/Fields"
    assert answer.field_type == "int"
    assert answer.constant_value is not None
    assert answer.constant_value.kind == "int"
    assert answer.constant_value.value == "42"
    assert answer.is_deprecated is True
    assert answer.is_synthetic is False
    assert answer.access_flag_names == ["public", "static", "final"]
    assert answer.annotation_descriptors == ["Ljava/lang/Deprecated;"]
    assert "ConstantValue" in answer.attribute_names

    name = fields["NAME"]
    assert name.field_type == "java.lang.String"
    assert name.constant_value is not None
    assert name.constant_value.kind == "string"
    assert name.constant_value.value == "glaurung"

    values = fields["values"]
    assert values.generic_signature == "Ljava/util/List<TT;>;"
    assert values.generic_field_type == "java.util.List<T>"
    assert values.field_type == "java.util.List"

    hidden = fields["hidden"]
    assert hidden.access_flag_names == ["private"]
    assert hidden.field_type == "long"

    assert any(
        node.kind == NodeKind.java_field
        and node.props.get("tool") == "java_list_fields"
        and node.props.get("class_name") == "app/Fields"
        and node.props.get("name") == "ANSWER"
        for node in ctx.kb.nodes()
    )


def test_java_list_fields_filters_by_name_descriptor_and_access(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_fields import build_tool

    jar = _compile_field_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    constants = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), access_flags_all=0x0018),
    )
    longs = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), descriptor_filter="J"),
    )
    named = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), name_filter="NAME"),
    )

    assert {field.name for field in constants.fields} == {"ANSWER", "NAME"}
    assert {field.name for field in longs.fields} == {"hidden"}
    assert {field.name for field in named.fields} == {"NAME"}


def test_java_list_fields_handles_non_zip(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_fields import build_tool

    not_zip = tmp_path / "not.jar"
    not_zip.write_text("not a jar", encoding="utf-8")
    ctx = _ctx(not_zip)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(not_zip)))

    assert result.archive_path == str(not_zip)
    assert result.stop_reasons == ["input_not_zip"]


def test_memory_agent_registers_java_list_fields() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_list_fields" in agent._function_toolset.tools
