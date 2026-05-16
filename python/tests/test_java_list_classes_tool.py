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


def _compile_source(tmp_path: Path, source: str) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java class fixture")
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
    jar = tmp_path / "classes.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar), "-C", str(classes), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar


def _patch_jar_class_version(
    tmp_path: Path,
    jar: Path,
    entry_name: str,
    *,
    major_version: int,
    minor_version: int = 0,
) -> Path:
    patched = tmp_path / "patched-version.jar"
    with zipfile.ZipFile(jar) as src, zipfile.ZipFile(patched, "w") as dst:
        for info in src.infolist():
            data = src.read(info)
            if info.filename == entry_name:
                data = (
                    data[:4]
                    + minor_version.to_bytes(2, "big")
                    + major_version.to_bytes(2, "big")
                    + data[8:]
                )
            dst.writestr(info, data)
    return patched


_SOURCE = """
package app;

@Deprecated
public class Main extends Base implements Runnable {
    public static class Inner {}

    public void run() {}
}

abstract class Base {}

class Helper {}

record Pair(String id, int count) {}

class Box<T extends Number> {}

sealed interface Gate permits OpenGate, ClosedGate {}

final class OpenGate implements Gate {}

non-sealed class ClosedGate implements Gate {}

enum Mode { ALPHA, BETA }
"""


def test_java_list_classes_filters_and_records_kb_nodes(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            package_prefix="app",
            name_filter="Main",
            include_annotations=True,
        ),
    )

    assert result.truncated is False
    assert result.matched_class_count == 2
    names = {cls.class_name for cls in result.classes}
    assert names == {"app/Main", "app/Main$Inner"}
    main = next(cls for cls in result.classes if cls.class_name == "app/Main")
    assert main.super_class == "app/Base"
    assert main.interface_count == 1
    assert main.method_count >= 2
    assert main.field_count == 0
    assert main.source_file == "Main.java"
    assert main.inner_class_count >= 1
    assert "public" in main.access_flag_names
    assert "super" in main.access_flag_names
    assert main.java_release == 17
    assert main.java_release_label == "Java 17"
    assert main.classfile_version_label == "Java 17 (classfile 61.0)"
    assert main.classfile_size is not None and main.classfile_size > 0
    assert main.classfile_warnings == []
    assert main.annotation_descriptors == ["Ljava/lang/Deprecated;"]
    assert any(
        node.kind == NodeKind.java_class
        and node.props.get("tool") == "java_list_classes"
        and node.props.get("class_name") == "app/Main"
        and node.props.get("source_file") == "Main.java"
        for node in ctx.kb.nodes()
    )
    main_node = next(
        node
        for node in ctx.kb.nodes()
        if node.kind == NodeKind.java_class
        and node.props.get("tool") == "java_list_classes"
        and node.props.get("class_name") == "app/Main"
    )
    assert any(
        edge.src == main_node.id
        and edge.kind == "extends"
        and edge.props.get("target_class") == "app/Base"
        for edge in ctx.kb.edges()
    )
    assert any(
        edge.src == main_node.id
        and edge.kind == "implements"
        and edge.props.get("target_class") == "java/lang/Runnable"
        for edge in ctx.kb.edges()
    )


def test_java_list_classes_supports_access_flag_filters(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    ctx = _ctx(jar)
    tool = build_tool()

    public_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), access_flags_all=0x0001),
    )
    non_public_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), access_flags_none=0x0001),
    )

    assert "app/Main" in {cls.class_name for cls in public_result.classes}
    assert "app/Helper" not in {cls.class_name for cls in public_result.classes}
    assert "app/Helper" in {cls.class_name for cls in non_public_result.classes}
    assert "app/Base" in {cls.class_name for cls in non_public_result.classes}
    helper = next(
        cls for cls in non_public_result.classes if cls.class_name == "app/Helper"
    )
    assert "public" not in helper.access_flag_names
    assert "super" in helper.access_flag_names


def test_java_list_classes_reports_record_metadata(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), name_filter="Pair"))

    assert result.matched_class_count == 1
    pair = result.classes[0]
    assert pair.class_name == "app/Pair"
    assert pair.class_kind == "record"
    assert pair.is_record is True
    assert pair.super_class == "java/lang/Record"
    assert pair.record_component_count == 2


def test_java_list_classes_reports_sealed_metadata(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), name_filter="Gate"))

    gate = next(cls for cls in result.classes if cls.class_name == "app/Gate")
    assert gate.class_kind == "interface"
    assert gate.is_interface is True
    assert gate.is_sealed is True
    assert gate.permitted_subclass_count == 2


def test_java_list_classes_reports_enum_kind(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), name_filter="Mode"))

    mode = next(cls for cls in result.classes if cls.class_name == "app/Mode")
    assert mode.class_kind == "enum"
    assert mode.is_enum is True


def test_java_list_classes_decodes_generic_class_signatures(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), name_filter="Box"))

    assert result.matched_class_count == 1
    box = result.classes[0]
    assert box.class_name == "app/Box"
    assert box.generic_signature == "<T:Ljava/lang/Number;>Ljava/lang/Object;"
    assert box.generic_type_parameters == ["T extends java.lang.Number"]
    assert box.generic_super_class == "java.lang.Object"
    assert box.generic_signature_error is None


def test_java_list_classes_reports_classfile_policy_warnings(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    future_jar = _patch_jar_class_version(
        tmp_path,
        jar,
        "app/Main.class",
        major_version=71,
        minor_version=65535,
    )
    ctx = _ctx(future_jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(future_jar), name_filter="app/Main"),
    )

    assert result.matched_class_count >= 1
    main = next(cls for cls in result.classes if cls.class_name == "app/Main")
    assert main.major_version == 71
    assert main.minor_version == 65535
    assert main.java_release == 27
    assert main.is_preview_classfile is True
    assert any("preview" in warning for warning in main.classfile_warnings)
    assert any(
        "newer than Java SE 26" in warning for warning in main.classfile_warnings
    )


def test_java_list_classes_respects_limit(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    jar = _compile_source(tmp_path, _SOURCE)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), limit=1))

    assert result.matched_class_count == 1
    assert result.truncated is True
    assert result.stop_reasons == ["limit"]


def test_java_list_classes_handles_non_zip(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_classes import build_tool

    sample = tmp_path / "not.jar"
    sample.write_text("not a jar\n", encoding="utf-8")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(sample)))

    assert result.classes == []
    assert result.stop_reasons == ["input_not_zip"]


def test_memory_agent_registers_java_list_classes() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_list_classes" in agent._function_toolset.tools
