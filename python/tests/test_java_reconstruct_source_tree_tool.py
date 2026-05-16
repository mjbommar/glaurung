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


def _fixture_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "Main.java").write_text(
        """
package app;

public class Main {
    public String value() {
        return "hello";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "Main.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "reconstruct-fixture.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "Main.class", "app/Main.class")
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n\n")
        zf.writestr("META-INF/services/app.Service", "app.Main\n")
        zf.writestr("config/app.properties", "enabled=true\n")
        zf.writestr("META-INF/TEST.SF", "signature\n")
        zf.writestr("META-INF/TEST.RSA", b"signature")
    return jar


def test_java_reconstruct_source_tree_preserves_resources_and_skips_signatures(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_reconstruct_source_tree import build_tool

    jar = _fixture_jar(tmp_path)
    output = tmp_path / "recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), output_root=str(output)),
    )

    assert result.wrote_files is True
    assert result.source_project_root == str(output)
    assert result.class_count == 1
    assert "app/Main.class" in result.classes_requiring_decompile
    assert result.java_source_files == []
    assert (
        output / "src" / "main" / "resources" / "config" / "app.properties"
    ).is_file()
    assert (
        output / "src" / "main" / "resources" / "META-INF" / "services" / "app.Service"
    ).is_file()
    assert not (output / "src" / "main" / "resources" / "META-INF" / "TEST.SF").exists()
    assert "META-INF/TEST.SF" in result.skipped_signature_files
    assert "META-INF/TEST.RSA" in result.skipped_signature_files
    assert any(
        node.kind == NodeKind.java_source_tree
        and node.props.get("tool") == "java_reconstruct_source_tree"
        for node in ctx.kb.nodes()
    )


def test_java_reconstruct_source_tree_emits_marked_stubs_when_requested(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_reconstruct_source_tree import build_tool

    jar = _fixture_jar(tmp_path)
    output = tmp_path / "recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar), output_root=str(output), emit_stub_sources=True
        ),
    )

    stub = output / "src" / "main" / "java" / "app" / "Main.java"
    assert stub.is_file()
    text = stub.read_text(encoding="utf-8")
    assert "GLAURUNG GENERATED STUB" in text
    assert "UnsupportedOperationException" in text
    assert result.java_source_files == ["src/main/java/app/Main.java"]
    assert result.classes_requiring_stubs == ["app/Main.class"]
    assert (output / "sources.txt").read_text(encoding="utf-8").strip() == (
        "src/main/java/app/Main.java"
    )


def test_java_reconstruct_source_tree_decompiles_top_level_sources(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_compile_recovered_project import (
        build_tool as build_compile_tool,
    )
    from glaurung.llm.tools.java_reconstruct_source_tree import build_tool

    jar = _fixture_jar(tmp_path)
    output = tmp_path / "recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            decompile_sources=True,
            decompiler_engine="cfr",
        ),
    )

    source = output / "src" / "main" / "java" / "app" / "Main.java"
    assert source.is_file()
    text = source.read_text(encoding="utf-8")
    assert "class Main" in text
    assert "GLAURUNG GENERATED STUB" not in text
    assert result.java_source_files == ["src/main/java/app/Main.java"]
    assert result.decompiled_source_files == ["src/main/java/app/Main.java"]
    assert result.classes_requiring_decompile == []

    compile_tool = build_compile_tool()
    compiled = compile_tool.run(
        ctx,
        ctx.kb,
        compile_tool.input_model(source_project_root=str(output), java_release=17),
    )
    assert compiled.success is True


def test_java_reconstruct_source_tree_emits_recovery_build_files(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_reconstruct_source_tree import build_tool

    jar = _fixture_jar(tmp_path)
    output = tmp_path / "recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            decompile_sources=True,
            decompiler_engine="cfr",
            java_release=17,
            project_name="fixture-app",
        ),
    )

    assert "pom.xml" in result.build_files
    assert "javac.args" in result.build_files
    assert ".glaurung/recovery.json" in result.build_files
    assert (output / "pom.xml").read_text(encoding="utf-8").count("<artifactId>") == 1
    assert "@sources.txt" in (output / "javac.args").read_text(encoding="utf-8")
    assert "src/main/java/app/Main.java" in (output / "sources.txt").read_text(
        encoding="utf-8"
    )


def test_java_reconstruct_source_tree_requires_output_root(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_reconstruct_source_tree import build_tool

    jar = _fixture_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.wrote_files is False
    assert result.stop_reasons == ["output_root_missing"]


def test_java_reconstruct_source_tree_handles_non_zip(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_reconstruct_source_tree import build_tool

    sample = tmp_path / "not.jar"
    sample.write_text("not a jar\n", encoding="utf-8")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(sample), output_root=str(tmp_path / "out")),
    )

    assert result.wrote_files is False
    assert result.stop_reasons == ["input_not_zip"]


def test_memory_agent_registers_java_reconstruct_source_tree() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_reconstruct_source_tree" in agent._function_toolset.tools
