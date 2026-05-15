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


def _compile_source(tmp_path: Path, source: str, *, out_name: str) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / f"{out_name}-src"
    classes = tmp_path / f"{out_name}-classes"
    src.mkdir()
    classes.mkdir()
    (src / "Main.java").write_text(source.strip() + "\n", encoding="utf-8")
    subprocess.run(
        ["javac", "--release", "17", "-d", str(classes), str(src / "Main.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / f"{out_name}.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar), "-C", str(classes), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar


_ORIGINAL_SOURCE = """
package app;

public class Main {
    public int count;

    public String value() {
        return "hello";
    }
}
"""


def test_java_compare_rebuilt_abi_matches_identical_rebuild(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_compare_rebuilt_abi import build_tool

    original = _compile_source(tmp_path, _ORIGINAL_SOURCE, out_name="original")
    rebuilt = _compile_source(tmp_path, _ORIGINAL_SOURCE, out_name="rebuilt")
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(original_path=str(original), rebuilt_path=str(rebuilt)),
    )

    assert result.abi_match is True
    assert result.difference_count == 0
    assert result.original_class_count == 1
    assert result.rebuilt_class_count == 1
    assert any(
        node.kind == NodeKind.java_abi_comparison
        and node.props.get("tool") == "java_compare_rebuilt_abi"
        for node in ctx.kb.nodes()
    )


def test_java_compare_rebuilt_abi_detects_missing_method(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_compare_rebuilt_abi import build_tool

    original = _compile_source(tmp_path, _ORIGINAL_SOURCE, out_name="original")
    rebuilt = _compile_source(
        tmp_path,
        """
package app;

public class Main {
    public int count;
}
""",
        out_name="rebuilt",
    )
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(original_path=str(original), rebuilt_path=str(rebuilt)),
    )

    assert result.abi_match is False
    assert any(
        diff.kind == "missing_method"
        and diff.class_name == "app/Main"
        and diff.member_name == "value"
        and diff.descriptor == "()Ljava/lang/String;"
        for diff in result.differences
    )


def test_java_compare_rebuilt_abi_detects_missing_annotations(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_compare_rebuilt_abi import build_tool

    original = _compile_source(
        tmp_path,
        """
package app;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@interface Marker {
    String value();
}

@Marker("class")
public class Main {
    @Marker("field")
    public int count;

    @Marker("method")
    public String value() {
        return "hello";
    }
}
""",
        out_name="original",
    )
    rebuilt = _compile_source(
        tmp_path,
        """
package app;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@interface Marker {
    String value();
}

public class Main {
    public int count;

    public String value() {
        return "hello";
    }
}
""",
        out_name="rebuilt",
    )
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            rebuilt_path=str(rebuilt),
            include_annotations=True,
        ),
    )

    assert result.abi_match is False
    assert any(
        diff.kind == "missing_class_annotation"
        and diff.class_name == "app/Main"
        and diff.annotation_descriptor == "Lapp/Marker;"
        for diff in result.differences
    )
    assert any(
        diff.kind == "missing_field_annotation"
        and diff.class_name == "app/Main"
        and diff.member_name == "count"
        and diff.annotation_descriptor == "Lapp/Marker;"
        for diff in result.differences
    )
    assert any(
        diff.kind == "missing_method_annotation"
        and diff.class_name == "app/Main"
        and diff.member_name == "value"
        and diff.annotation_descriptor == "Lapp/Marker;"
        for diff in result.differences
    )


def test_java_compare_rebuilt_abi_supports_public_and_package_scopes(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_compare_rebuilt_abi import build_tool

    original = _compile_source(
        tmp_path,
        """
package app;

public class Main {
    public String value() {
        return helper();
    }

    String packageOnly() {
        return "package";
    }

    private String helper() {
        return "hello";
    }
}
""",
        out_name="original",
    )
    rebuilt = _compile_source(
        tmp_path,
        """
package app;

public class Main {
    public String value() {
        return "hello";
    }
}
""",
        out_name="rebuilt",
    )
    ctx = _ctx(original)
    tool = build_tool()

    all_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            rebuilt_path=str(rebuilt),
            scope="all",
        ),
    )
    public_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            rebuilt_path=str(rebuilt),
            scope="public_api",
        ),
    )
    package_result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            rebuilt_path=str(rebuilt),
            scope="package_api",
        ),
    )

    assert all_result.abi_match is False
    assert any(diff.member_name == "helper" for diff in all_result.differences)
    assert public_result.abi_match is True
    assert package_result.abi_match is False
    assert any(
        diff.kind == "missing_method" and diff.member_name == "packageOnly"
        for diff in package_result.differences
    )
    assert not any(diff.member_name == "helper" for diff in package_result.differences)


def test_java_compare_rebuilt_abi_handles_missing_rebuilt_path(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_compare_rebuilt_abi import build_tool

    original = _compile_source(tmp_path, _ORIGINAL_SOURCE, out_name="original")
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original), rebuilt_path=str(tmp_path / "nope")
        ),
    )

    assert result.abi_match is False
    assert result.stop_reasons == ["rebuilt_path_missing"]


def test_memory_agent_registers_java_compare_rebuilt_abi() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_compare_rebuilt_abi" in agent._function_toolset.tools
