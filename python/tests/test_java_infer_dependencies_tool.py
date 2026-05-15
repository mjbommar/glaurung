from __future__ import annotations

import io
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


def _compile_dependency_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")

    stub_src = tmp_path / "stub-src"
    stub_out = tmp_path / "stub-classes"
    app_src = tmp_path / "app-src"
    app_out = tmp_path / "app-classes"
    for path in (stub_src, stub_out, app_src, app_out):
        path.mkdir()

    (stub_src / "Logger.java").parent.mkdir(parents=True, exist_ok=True)
    (stub_src / "Logger.java").write_text(
        """
package org.slf4j;

public interface Logger {
    void info(String message);
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
            str(stub_out),
            str(stub_src / "Logger.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    (app_src / "DependencyFixture.java").write_text(
        """
package fixture;

public class DependencyFixture {
    private final org.slf4j.Logger logger;

    public DependencyFixture(org.slf4j.Logger logger) {
        this.logger = logger;
    }

    public org.slf4j.Logger[] passthrough(org.slf4j.Logger[] loggers) {
        return loggers;
    }

    public void run() {
        logger.info("hello");
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
            "-cp",
            str(stub_out),
            "-d",
            str(app_out),
            str(app_src / "DependencyFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    nested_buf = io.BytesIO()
    with zipfile.ZipFile(nested_buf, "w") as nested:
        nested.writestr("placeholder.txt", "dependency placeholder\n")

    jar = tmp_path / "dependency-fixture.jar"
    manifest = (
        "Manifest-Version: 1.0\nClass-Path: libs/helper-1.2.3.jar external.jar\n\n"
    )
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", manifest)
        zf.write(
            app_out / "fixture" / "DependencyFixture.class",
            "fixture/DependencyFixture.class",
        )
        zf.writestr(
            "META-INF/maven/com.example/dependency-fixture/pom.properties",
            ("groupId=com.example\nartifactId=dependency-fixture\nversion=1.0.0\n"),
        )
        zf.writestr(
            "META-INF/libraries/org/slf4j/slf4j-api/2.0.1/slf4j-api-2.0.1.jar",
            nested_buf.getvalue(),
        )
        zf.writestr("libs/guava-31.1-jre.jar", nested_buf.getvalue())
    return jar


def test_java_infer_dependencies_combines_metadata_and_bytecode_refs(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_infer_dependencies import build_tool

    jar = _compile_dependency_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.dependency_count >= 5
    assert result.manifest_class_path_count == 2
    assert result.maven_metadata_count == 1
    assert result.nested_archive_count == 2
    assert result.external_package_count >= 1
    assert result.summary_by_source["manifest_class_path"] == 2
    assert any(
        dep.source == "maven_metadata"
        and dep.group_id == "com.example"
        and dep.artifact_id == "dependency-fixture"
        and dep.version == "1.0.0"
        for dep in result.dependencies
    )
    assert any(
        dep.source == "nested_archive_path"
        and dep.group_id == "org.slf4j"
        and dep.artifact_id == "slf4j-api"
        and dep.version == "2.0.1"
        for dep in result.dependencies
    )
    assert any(
        dep.source == "bytecode_external_package"
        and dep.package_prefix == "org.slf4j"
        and dep.group_id == "org.slf4j"
        and dep.artifact_id == "slf4j-api"
        and dep.reference_count >= 1
        for dep in result.dependencies
    )
    assert not any(
        dep.package_prefix and dep.package_prefix.startswith("[")
        for dep in result.dependencies
    )
    assert any(
        node.kind == NodeKind.java_dependency
        and node.props.get("tool") == "java_infer_dependencies"
        for node in ctx.kb.nodes()
    )


def test_java_infer_dependencies_handles_non_zip(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_infer_dependencies import build_tool

    sample = tmp_path / "not.jar"
    sample.write_text("not a jar\n", encoding="utf-8")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(sample)))

    assert result.dependency_count == 0
    assert result.stop_reasons == ["input_not_zip"]


def test_java_dependency_owner_normalization_handles_array_descriptors() -> None:
    from glaurung.llm.tools.java_infer_dependencies import _method_xref_owners

    parsed = {
        "methods": [
            {
                "code": {
                    "xrefs": [
                        {"kind": "class", "owner": "[Lorg/slf4j/Logger;"},
                        {"kind": "class", "owner": "[[Ljava/lang/String;"},
                        {"kind": "class", "owner": "[[I"},
                        {"kind": "method", "owner": "org/slf4j/Logger"},
                    ]
                }
            }
        ]
    }

    assert _method_xref_owners(parsed) == [
        "org/slf4j/Logger",
        "java/lang/String",
        "org/slf4j/Logger",
    ]


def test_java_dependency_package_prefix_groups_common_libraries() -> None:
    from glaurung.llm.tools.java_infer_dependencies import (
        _known_dependency_hint,
        _package_prefix,
    )

    assert _package_prefix("joptsimple/OptionParser") == "joptsimple"
    assert _known_dependency_hint("joptsimple") == ("net.sf.jopt-simple", "jopt-simple")
    assert _package_prefix("org/joml/Matrix4f") == "org.joml"
    assert _known_dependency_hint("org.joml") == ("org.joml", "joml")
    assert _package_prefix("oshi/hardware/CentralProcessor") == "oshi"
    assert _known_dependency_hint("oshi") == ("com.github.oshi", "oshi-core")


def test_memory_agent_registers_java_infer_dependencies() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_infer_dependencies" in agent._function_toolset.tools
