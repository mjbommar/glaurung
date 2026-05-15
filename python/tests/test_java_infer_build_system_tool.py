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


def _compile_fixture_jar(
    tmp_path: Path,
    *,
    jar_name: str = "build-fixture.jar",
    extra_entries: dict[str, str] | None = None,
) -> Path:
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
    public static void main(String[] args) {
        System.out.println("hello");
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
    jar = tmp_path / jar_name
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "Main.class", "app/Main.class")
        for name, text in (extra_entries or {}).items():
            zf.writestr(name, text)
    return jar


def test_java_infer_build_system_prefers_embedded_maven_metadata(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_infer_build_system import build_tool

    jar = _compile_fixture_jar(
        tmp_path,
        extra_entries={
            "META-INF/maven/com.example/build-fixture/pom.properties": (
                "groupId=com.example\nartifactId=build-fixture\nversion=1.2.3\n"
            ),
            "META-INF/maven/com.example/build-fixture/pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.example</groupId>"
                "<artifactId>build-fixture</artifactId>"
                "<version>1.2.3</version></project>"
            ),
        },
    )
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.selected_build_tool == "maven"
    assert result.project_name == "build-fixture"
    assert result.group_id == "com.example"
    assert result.version == "1.2.3"
    assert result.java_release == 17
    assert result.class_file_major_max == 61
    assert any(file.path == "pom.xml" for file in result.build_files)
    assert any(
        node.kind == NodeKind.java_build_system
        and node.props.get("tool") == "java_infer_build_system"
        for node in ctx.kb.nodes()
    )


def test_java_infer_build_system_uses_javac_for_plain_fixture(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_infer_build_system import build_tool

    jar = _compile_fixture_jar(tmp_path, jar_name="plain.jar")
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.selected_build_tool == "javac"
    assert result.java_release == 17
    assert any(file.path == "javac.args" for file in result.build_files)
    assert "No embedded Maven or Gradle metadata" in " ".join(result.warnings)


def test_java_infer_build_system_selects_gradle_for_minecraft_mod_metadata(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_infer_build_system import build_tool

    jar = _compile_fixture_jar(
        tmp_path,
        jar_name="forge-mod.jar",
        extra_entries={
            "META-INF/mods.toml": (
                'modLoader="javafml"\n'
                'loaderVersion="[47,)"\n'
                "[[mods]]\n"
                'modId="fixturemod"\n'
                'version="1.0.0"\n'
            )
        },
    )
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.selected_build_tool == "gradle"
    assert result.java_release == 17
    assert any(file.path == "build.gradle" for file in result.build_files)
    assert any("Minecraft mod metadata" in warning for warning in result.warnings)


def test_java_infer_build_system_handles_non_zip(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_infer_build_system import build_tool

    sample = tmp_path / "not.jar"
    sample.write_text("not a jar\n", encoding="utf-8")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(sample)))

    assert result.selected_build_tool == "unknown"
    assert result.stop_reasons == ["input_not_zip"]


def test_memory_agent_registers_java_infer_build_system() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_infer_build_system" in agent._function_toolset.tools
