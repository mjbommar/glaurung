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


def _compile_archive_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java archive fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    app = src / "app"
    impl = app / "impl"
    impl.mkdir(parents=True)
    out.mkdir()
    (app / "Service.java").write_text(
        "package app; public interface Service { String name(); }\n",
        encoding="utf-8",
    )
    (impl / "ServiceImpl.java").write_text(
        """
package app.impl;

public class ServiceImpl implements app.Service {
    public String name() { return "provider-name"; }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (app / "Main.java").write_text(
        """
package app;

public class Main {
    public static final String FIELD_CONST = "field-constant";

    public String greet() {
        return "method-constant";
    }

    public static void main(String[] args) {}
}
""".strip()
        + "\n",
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
            str(app / "Service.java"),
            str(impl / "ServiceImpl.java"),
            str(app / "Main.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "archive-tools.jar"
    main_class = out / "app" / "Main.class"
    with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "\n".join(
                [
                    "Manifest-Version: 1.0",
                    "Main-Class: app.Main",
                    "Class-Path: lib/a.jar lib/b.jar",
                    "Multi-Release: true",
                    "Sealed: true",
                    "Created-By: Glaurung Test",
                    "",
                    "",
                ]
            ),
        )
        for class_file in out.rglob("*.class"):
            zf.write(class_file, class_file.relative_to(out).as_posix())
        zf.writestr(
            "META-INF/services/app.Service",
            "# service provider\napp.impl.ServiceImpl\n",
        )
        zf.writestr("assets/data.json", '{"name":"fixture"}\n')
        zf.writestr("assets/native.bin", b"\x7fELFfixture")
        zf.writestr(
            "META-INF/versions/9/app/Main.class",
            main_class.read_bytes() + b"\0",
        )
    return jar


def test_java_list_resources_classifies_archive_entries(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_resources import build_tool

    jar = _compile_archive_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), prefix="assets/"),
    )

    assert result.matched_resource_count == 2
    resources = {resource.entry_name: resource for resource in result.resources}
    assert resources["assets/data.json"].magic == "json_like"
    assert resources["assets/data.json"].extension == "json"
    assert resources["assets/native.bin"].magic == "elf"
    assert resources["assets/native.bin"].sha256 is not None
    assert any(
        node.kind == NodeKind.java_resource
        and node.props.get("tool") == "java_list_resources"
        and node.props.get("entry_name") == "assets/data.json"
        for node in ctx.kb.nodes()
    )


def test_java_view_manifest_parses_launch_and_security_attributes(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_view_manifest import build_tool

    jar = _compile_archive_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.manifest_found is True
    assert result.main_class == "app.Main"
    assert result.class_path == ["lib/a.jar", "lib/b.jar"]
    assert result.multi_release is True
    assert result.sealed is True
    assert result.build_attributes["Created-By"] == "Glaurung Test"
    assert result.manifest_node_id is not None


def test_java_list_services_parses_service_loader_descriptors(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_services import build_tool

    jar = _compile_archive_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.matched_descriptor_count == 1
    service = result.services[0]
    assert service.service == "app.Service"
    assert service.providers == ["app/impl/ServiceImpl"]
    assert service.dotted_providers == ["app.impl.ServiceImpl"]
    assert any(
        node.kind == NodeKind.java_resource
        and node.props.get("tool") == "java_list_services"
        and node.props.get("service") == "app.Service"
        for node in ctx.kb.nodes()
    )


def test_java_detect_duplicate_classes_reports_multi_release_variants(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_detect_duplicate_classes import build_tool

    jar = _compile_archive_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), class_filter="app.Main"),
    )

    assert result.duplicate_class_count == 1
    duplicate = result.duplicates[0]
    assert duplicate.class_name == "app/Main"
    assert duplicate.entry_count == 2
    assert duplicate.divergent_hashes is True
    assert duplicate.multi_release_only is True
    assert {entry.version for entry in duplicate.entries} == {None, 9}


def test_java_list_string_constants_reports_hashes_and_optional_values(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_string_constants import build_tool

    jar = _compile_archive_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_filter="app.Main",
            min_length=6,
        ),
    )

    previews = {item.value_preview: item for item in result.strings}
    assert "field-constant" in previews
    assert "method-constant" in previews
    assert previews["field-constant"].source == "field_constant"
    assert previews["field-constant"].value is None
    assert previews["method-constant"].source == "ldc"
    assert previews["method-constant"].sha256
    assert any(
        node.kind == NodeKind.string
        and node.props.get("tool") == "java_list_string_constants"
        and node.props.get("value_preview") == "method-constant"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_java_archive_navigation_tools() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_list_resources" in agent._function_toolset.tools
    assert "java_view_manifest" in agent._function_toolset.tools
    assert "java_list_services" in agent._function_toolset.tools
    assert "java_detect_duplicate_classes" in agent._function_toolset.tools
    assert "java_list_string_constants" in agent._function_toolset.tools
