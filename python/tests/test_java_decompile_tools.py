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

    public static class Nested {
        public int nestedValue() {
            return 7;
        }
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    helper_path = src / "Helper.java"
    helper_path.write_text(
        """
package app;

public class Helper {
    public static String helperValue() {
        return "helper-constant";
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
            str(source_path),
            str(helper_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "decompile-fixture.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "Main.class", "app/Main.class")
        zf.write(out / "app" / "Main$Nested.class", "app/Main$Nested.class")
        zf.write(out / "app" / "Helper.class", "app/Helper.class")
    return jar, source_path


def _inner_fixture_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java inner-class fixture")
    src = tmp_path / "inner-src"
    out = tmp_path / "inner-classes"
    src.mkdir()
    out.mkdir()
    source_path = src / "Outer.java"
    source_path.write_text(
        """
package app;

public class Outer {
    public Object anonymous() {
        return new Object() {
            public String value() {
                return "anonymous";
            }
        };
    }

    public static class Named {
        public int number() {
            return 42;
        }
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
    jar = tmp_path / "inner-fixture.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        for class_file in sorted((out / "app").glob("*.class")):
            zf.write(class_file, f"app/{class_file.name}")
    return jar


def _obfuscated_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java mapping fixture")
    src = tmp_path / "obf-src"
    out = tmp_path / "obf-classes"
    src.mkdir()
    out.mkdir()
    source_path = src / "a.java"
    source_path.write_text(
        """
public class a {
    public int b = 1;

    public int c(int value) {
        return this.b + value;
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
    jar = tmp_path / "obfuscated.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "a.class", "a.class")
    return jar


def _colliding_obfuscated_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java mapping fixture")
    src = tmp_path / "collision-src"
    out = tmp_path / "collision-classes"
    src.mkdir()
    out.mkdir()
    (src / "a.java").write_text("public class a { public int value() { return 1; } }\n")
    (src / "b.java").write_text("public class b { public int value() { return 2; } }\n")
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(out),
            str(src / "a.java"),
            str(src / "b.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "colliding-obfuscated.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "a.class", "a.class")
        zf.write(out / "b.class", "b.class")
    return jar


def _dependency_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java dependency fixture")
    src = tmp_path / "dep-src"
    out = tmp_path / "dep-classes"
    src.mkdir()
    out.mkdir()
    (src / "Helper.java").write_text(
        """
package dep;

public class Helper {
    public static String value() {
        return "dep";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "Helper.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "dep.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "dep" / "Helper.class", "dep/Helper.class")
    return jar


def _jar_using_dependency(tmp_path: Path) -> tuple[Path, Path]:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java dependency fixture")
    dep_jar = _dependency_jar(tmp_path)
    src = tmp_path / "uses-dep-src"
    out = tmp_path / "uses-dep-classes"
    src.mkdir()
    out.mkdir()
    (src / "UsesDep.java").write_text(
        """
package app;

import dep.Helper;

public class UsesDep {
    public String value() {
        return Helper.value();
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
            "-classpath",
            str(dep_jar),
            "-d",
            str(out),
            str(src / "UsesDep.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "uses-dep.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "UsesDep.class", "app/UsesDep.class")
    return jar, dep_jar


def _mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "mappings.txt"
    path.write_text(
        """
com.example.MainThing -> app.Main:
    java.lang.String value() -> value
com.example.HelperThing -> app.Helper:
    java.lang.String helperValue() -> helperValue
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def _obfuscated_mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "obfuscated-mappings.txt"
    path.write_text(
        """
com.example.GameThing -> a:
    int health -> b
    int score(int) -> c
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def _tiny_v2_mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "tiny-v2-mappings.tiny"
    path.write_text(
        "\n".join(
            [
                "tiny\t2\t0\tofficial\tnamed",
                "c\ta\tcom/example/GameThing",
                "\tf\tI\tb\thealth",
                "\tm\t(I)I\tc\tscore",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def _colliding_tiny_v1_mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "colliding-v1.tiny"
    path.write_text(
        "\n".join(
            [
                "v1\tofficial\tnamed",
                "CLASS\ta\tcom/example/Thing",
                "CLASS\tb\tcom/example/Thing",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


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
    assert result.ast_node_id is not None
    assert result.parse_node_id is not None
    assert any(
        node.kind == NodeKind.java_source_ast
        and node.props.get("tool") == "java_parse_decompiled_source"
        and node.props.get("package_name") == "app"
        for node in ctx.kb.nodes()
    )


def test_java_decompile_archive_writes_filtered_sources_and_quality(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar, _source_path = _fixture_jar(tmp_path)
    output = tmp_path / "recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            write_sources=True,
            include_packages=["app"],
            max_classes=8,
            include_bytecode_correlation=True,
        ),
    )

    assert result.class_count == 3
    assert result.attempted_class_count == 2
    assert result.success_count == 2
    assert result.parseable_count == 2
    assert result.skipped_inner_class_count == 1
    assert result.written_source_count == 2
    assert result.classes[0].attempted_engines
    assert all(summary.quality == "parseable" for summary in result.classes)
    assert all(summary.bytecode_method_count for summary in result.classes)
    assert all(summary.decompiled_methods for summary in result.classes)
    assert any(
        "value" in summary.decompiled_methods
        and "value()Ljava/lang/String;" in summary.bytecode_methods
        for summary in result.classes
    )
    assert (output / "src" / "main" / "java" / "app" / "Main.java").is_file()
    assert (output / "src" / "main" / "java" / "app" / "Helper.java").is_file()
    assert not (output / "src" / "main" / "java" / "app" / "Main$Nested.java").exists()
    assert (output / "decompiled-sources.txt").is_file()
    assert any(
        node.kind == NodeKind.java_decompile_archive
        and node.props.get("tool") == "java_decompile_archive"
        for node in ctx.kb.nodes()
    )


def test_java_decompile_archive_respects_class_globs(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar, _source_path = _fixture_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            include_class_globs=["app/Helper"],
        ),
    )

    assert result.attempted_class_count == 1
    assert result.classes[0].class_name == "app/Helper"
    assert result.classes[0].selected_engine in {"cfr", "vineflower"}


def test_java_decompile_archive_can_emit_inner_class_companions(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar, _source_path = _fixture_jar(tmp_path)
    output = tmp_path / "recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            write_sources=True,
            include_class_globs=["app/Main$Nested"],
            inner_class_policy="companion",
        ),
    )

    assert result.attempted_class_count == 1
    assert result.skipped_inner_class_count == 0
    assert result.classes[0].class_name == "app/Main$Nested"
    assert result.classes[0].inner_class_kind == "named_inner"
    assert result.classes[0].outer_class_name == "app/Main"
    assert result.classes[0].source_file == "src/main/java/app/Main$Nested.java"
    assert (output / "src" / "main" / "java" / "app" / "Main$Nested.java").is_file()


def test_java_decompile_archive_groups_and_classifies_inner_classes(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar = _inner_fixture_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            include_packages=["app"],
            inner_class_policy="companion",
            max_classes=8,
        ),
    )

    assert result.inner_class_group_count == 1
    group = result.inner_class_groups[0]
    assert group.outer_class_name == "app/Outer"
    assert "app/Outer$Named" in group.named_inner_classes
    assert "app/Outer$1" in group.anonymous_classes
    kinds = {summary.class_name: summary.inner_class_kind for summary in result.classes}
    assert kinds["app/Outer"] == "top_level"
    assert kinds["app/Outer$Named"] == "named_inner"
    assert kinds["app/Outer$1"] == "anonymous"


def test_java_decompile_archive_merges_named_inner_and_suppresses_anonymous(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar = _inner_fixture_jar(tmp_path)
    output = tmp_path / "merged"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            write_sources=True,
            include_packages=["app"],
            inner_class_policy="merge",
            compile_candidates=True,
            max_classes=8,
        ),
    )

    assert result.attempted_class_count == 2
    assert result.suppressed_inner_class_count == 1
    named = next(
        item for item in result.classes if item.class_name == "app/Outer$Named"
    )
    assert named.inner_class_action == "merged_into_outer"
    assert named.source_file == "src/main/java/app/Outer.java"
    assert not (output / "src" / "main" / "java" / "app" / "Outer$Named.java").exists()
    outer = output / "src" / "main" / "java" / "app" / "Outer.java"
    text = outer.read_text(encoding="utf-8")
    assert "class Named" in text
    assert "number()" in text


def test_java_decompile_archive_rewrites_mapped_source_names(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar = _obfuscated_jar(tmp_path)
    mappings = _obfuscated_mapping_file(tmp_path)
    output = tmp_path / "mapped"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            mapping_path=str(mappings),
            output_root=str(output),
            write_sources=True,
            rewrite_mapped_sources=True,
            include_packages=["com.example"],
        ),
    )

    assert result.attempted_class_count == 1
    assert result.classes[0].mapped_source_rewritten is True
    assert result.classes[0].source_file == ("src/main/java/com/example/GameThing.java")
    source = output / "src" / "main" / "java" / "com" / "example" / "GameThing.java"
    text = source.read_text(encoding="utf-8")
    assert "package com.example;" in text
    assert "class GameThing" in text
    assert "health" in text
    assert "score" in text


def test_java_decompile_archive_rewrites_tiny_v2_mapped_source_names(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar = _obfuscated_jar(tmp_path)
    mappings = _tiny_v2_mapping_file(tmp_path)
    output = tmp_path / "tiny-mapped"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            mapping_path=str(mappings),
            output_root=str(output),
            write_sources=True,
            rewrite_mapped_sources=True,
            include_packages=["com.example"],
        ),
    )

    assert result.attempted_class_count == 1
    assert result.classes[0].mapped_source_rewritten is True
    source = output / "src" / "main" / "java" / "com" / "example" / "GameThing.java"
    text = source.read_text(encoding="utf-8")
    assert "package com.example;" in text
    assert "class GameThing" in text
    assert "health" in text
    assert "score" in text


def test_java_decompile_archive_does_not_overwrite_mapping_collisions(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar = _colliding_obfuscated_jar(tmp_path)
    mappings = _colliding_tiny_v1_mapping_file(tmp_path)
    output = tmp_path / "colliding"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            mapping_path=str(mappings),
            output_root=str(output),
            write_sources=True,
            rewrite_mapped_sources=True,
            include_packages=["com.example"],
        ),
    )

    assert result.attempted_class_count == 2
    assert result.written_source_count == 1
    assert any(
        "mapped_source_collision" in item.stop_reasons for item in result.classes
    )
    source = output / "src" / "main" / "java" / "com" / "example" / "Thing.java"
    assert source.is_file()


def test_java_decompile_archive_can_score_candidate_compilation(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar, _source_path = _fixture_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            include_class_globs=["app/Helper"],
            compile_candidates=True,
            java_release=17,
        ),
    )

    assert result.attempted_class_count == 1
    assert result.classes[0].compile_success is True
    assert result.classes[0].attempted_engines[0].compile_success is True
    assert result.classes[0].attempted_engines[0].compile_context == "isolated"


def test_java_decompile_archive_scores_candidates_with_project_classpath(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar, dep_jar = _jar_using_dependency(tmp_path)
    output = tmp_path / "project"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            write_sources=True,
            include_class_globs=["app/UsesDep"],
            compile_candidates=True,
            candidate_classpath=[str(dep_jar)],
            candidate_project_root=str(output),
            java_release=17,
        ),
    )

    assert result.attempted_class_count == 1
    assert result.classes[0].compile_success is True
    assert result.classes[0].attempted_engines[0].compile_success is True
    assert result.classes[0].attempted_engines[0].compile_context == "project"


def test_java_decompile_archive_uses_mappings_for_filters_and_metadata(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_decompile_archive import build_tool

    jar, _source_path = _fixture_jar(tmp_path)
    mappings = _mapping_file(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            mapping_path=str(mappings),
            include_packages=["com.example"],
        ),
    )

    assert result.attempted_class_count == 2
    assert result.mapped_class_count == 2
    mapped_names = {summary.mapped_class_name for summary in result.classes}
    assert mapped_names == {"com.example.MainThing", "com.example.HelperThing"}
    assert all(summary.mapping_match == "obfuscated" for summary in result.classes)


def test_memory_agent_registers_java_decompiler_tools() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_decompile_class" in agent._function_toolset.tools
    assert "java_decompile_archive" in agent._function_toolset.tools
    assert "java_parse_decompiled_source" in agent._function_toolset.tools
