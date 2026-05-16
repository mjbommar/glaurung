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


def _recoverable_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java recovery fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "Main.java").write_text(
        """
package app;

public class Main {
    public String value() {
        return "recover-me";
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
    jar = tmp_path / "recoverable.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "Main.class", "app/Main.class")
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n\n")
        zf.writestr("META-INF/services/app.Service", "app.Main\n")
        zf.writestr("config/app.properties", "enabled=true\n")
    return jar


def _vendored_fixture_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java recovery fixture")
    fixture = Path(__file__).parent / "fixtures" / "java" / "recoverable"
    src_root = fixture / "src" / "main" / "java"
    resource_root = fixture / "src" / "main" / "resources"
    out = tmp_path / "vendored-classes"
    out.mkdir()
    sources = sorted(str(path) for path in src_root.rglob("*.java"))
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), *sources],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "vendored-fixture.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        for class_file in sorted(out.rglob("*.class")):
            zf.write(class_file, class_file.relative_to(out).as_posix())
        for resource in sorted(resource_root.rglob("*")):
            if resource.is_file():
                zf.write(resource, resource.relative_to(resource_root).as_posix())
    return jar


def test_java_recover_project_orchestrates_decompile_compile_repair_validate(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_recover_project import build_tool

    jar = _recoverable_jar(tmp_path)
    output = tmp_path / "recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            java_release=17,
            max_classes=8,
            validate_profile="full_static",
        ),
    )

    assert result.success is True
    assert result.source_project_root == str(output)
    assert result.decompile_success_count == 1
    assert result.compile_success is True
    assert result.validation_passed is True
    assert result.repair_success is True
    assert result.quality_summary.startswith("clean_enough")
    assert (output / "src" / "main" / "java" / "app" / "Main.java").is_file()
    assert (
        output / "src" / "main" / "resources" / "META-INF" / "services" / "app.Service"
    ).is_file()
    assert (output / "pom.xml").is_file()
    assert (output / "javac.args").is_file()
    assert (output / ".glaurung" / "recovery.json").is_file()
    assert any(
        node.kind == NodeKind.java_recovery_project
        and node.props.get("tool") == "java_recover_project"
        for node in ctx.kb.nodes()
    )


def test_java_recover_project_accepts_vendored_safe_fixture_sources(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_recover_project import build_tool

    jar = _vendored_fixture_jar(tmp_path)
    output = tmp_path / "vendored-recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            java_release=17,
            max_classes=4,
        ),
    )

    assert result.success is True
    assert result.generated_source_count == 1
    assert (output / "src" / "main" / "resources" / "fixture.properties").is_file()


def test_memory_agent_registers_java_recover_project() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_recover_project" in agent._function_toolset.tools
