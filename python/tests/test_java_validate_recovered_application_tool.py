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


_SOURCE = """
package app;

public class Main {
    public String value() {
        return "hello";
    }
}
"""


def _write_source_project(root: Path, source: str = _SOURCE) -> Path:
    src = root / "src" / "main" / "java" / "app"
    resources = root / "src" / "main" / "resources" / "config"
    src.mkdir(parents=True)
    resources.mkdir(parents=True)
    source_path = src / "Main.java"
    source_path.write_text(source.strip() + "\n", encoding="utf-8")
    (resources / "app.properties").write_text("enabled=true\n", encoding="utf-8")
    return source_path


def _compile_original_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java validation fixture")
    src = tmp_path / "original-src"
    classes = tmp_path / "original-classes"
    src.mkdir()
    classes.mkdir()
    source_path = src / "Main.java"
    source_path.write_text(_SOURCE.strip() + "\n", encoding="utf-8")
    subprocess.run(
        ["javac", "--release", "17", "-d", str(classes), str(source_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "original.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(classes / "app" / "Main.class", "app/Main.class")
        zf.writestr("config/app.properties", "enabled=true\n")
    return jar


def test_java_validate_recovered_application_passes_static_validation(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_validate_recovered_application import build_tool

    original = _compile_original_jar(tmp_path)
    project = tmp_path / "recovered"
    _write_source_project(project)
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            source_project_root=str(project),
            java_release=17,
        ),
    )

    assert result.validation_passed is True
    assert result.status == "valid"
    assert result.compile_success is True
    assert result.abi_match is True
    assert result.resource_match is True
    assert result.stub_source_count == 0
    assert result.resource_difference_count == 0
    assert any(
        node.kind == NodeKind.java_recovery_validation
        and node.props.get("tool") == "java_validate_recovered_application"
        for node in ctx.kb.nodes()
    )


def test_java_validate_recovered_application_detects_resource_drift(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_validate_recovered_application import build_tool

    original = _compile_original_jar(tmp_path)
    project = tmp_path / "recovered"
    _write_source_project(project)
    (project / "src" / "main" / "resources" / "config" / "app.properties").unlink()
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            source_project_root=str(project),
            java_release=17,
        ),
    )

    assert result.validation_passed is False
    assert result.status == "invalid"
    assert result.compile_success is True
    assert result.abi_match is True
    assert result.resource_match is False
    assert any(diff.kind == "missing_resource" for diff in result.resource_differences)


def test_java_validate_recovered_application_rejects_generated_stubs(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_validate_recovered_application import build_tool

    original = _compile_original_jar(tmp_path)
    project = tmp_path / "recovered"
    _write_source_project(
        project,
        """
package app;

/* GLAURUNG GENERATED STUB: original bytecode still requires decompilation. */
public final class Main {
    private Main() {
        throw new UnsupportedOperationException("generated stub");
    }
}
""",
    )
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            source_project_root=str(project),
            java_release=17,
        ),
    )

    assert result.validation_passed is False
    assert result.status == "invalid"
    assert result.stub_source_count == 1
    assert result.stop_reasons == ["generated_stubs_present"]


def test_java_validate_recovered_application_handles_missing_source_root(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_validate_recovered_application import build_tool

    original = _compile_original_jar(tmp_path)
    ctx = _ctx(original)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            original_path=str(original),
            source_project_root=str(tmp_path / "missing"),
        ),
    )

    assert result.validation_passed is False
    assert result.status == "unsupported"
    assert result.stop_reasons == ["source_project_root_missing"]


def test_memory_agent_registers_java_validate_recovered_application() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_validate_recovered_application" in agent._function_toolset.tools
