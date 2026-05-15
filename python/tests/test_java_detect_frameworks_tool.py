from __future__ import annotations

from pathlib import Path
import zipfile

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _framework_fixture(tmp_path: Path) -> Path:
    jar = tmp_path / "frameworks.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "\n".join(
                [
                    "Manifest-Version: 1.0",
                    "Main-Class: demo.App",
                    "Premain-Class: demo.Agent",
                    "Spring-Boot-Version: 3.2.1",
                    "Start-Class: demo.SpringApp",
                    "Bundle-SymbolicName: demo.bundle",
                    "",
                ]
            ),
        )
        zf.writestr(
            "META-INF/mods.toml",
            """
modLoader="javafml"
loaderVersion="[47,)"
[[mods]]
modId="examplemod"
version="1.2.3"
displayName="Example Mod"
""".strip()
            + "\n",
        )
        zf.writestr(
            "fabric.mod.json",
            '{"id":"fabricthing","version":"2.0.0","entrypoints":{"main":["demo.Fabric"]}}',
        )
        zf.writestr(
            "quilt.mod.json",
            '{"quilt_loader":{"id":"quiltthing","version":"3.0.0"}}',
        )
        zf.writestr(
            "META-INF/services/java.lang.Runnable",
            "demo.ServiceImpl\n",
        )
        zf.writestr(
            "META-INF/maven/com.example/app/pom.properties",
            "groupId=com.example\nartifactId=app\nversion=4.5.6\n",
        )
        zf.writestr(
            "plugin.yml",
            "name: DemoPlugin\nmain: demo.Plugin\nversion: 7.8.9\n",
        )
        zf.writestr("module-info.class", b"\xca\xfe\xba\xbe")
    return jar


def test_java_detect_frameworks_reports_generic_metadata(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_detect_frameworks import build_tool

    jar = _framework_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    kinds = {framework.kind for framework in result.frameworks}
    assert {
        "java_application",
        "java_agent",
        "spring_boot",
        "osgi_bundle",
        "minecraft_forge_mod",
        "minecraft_fabric_mod",
        "minecraft_quilt_mod",
        "service_loader",
        "maven_artifact",
        "bukkit_plugin",
        "java_module",
    }.issubset(kinds)
    assert result.summary_by_kind["minecraft_forge_mod"] == 1
    assert any(
        framework.kind == "maven_artifact"
        and framework.name == "com.example:app"
        and framework.version == "4.5.6"
        for framework in result.frameworks
    )
    assert any(
        node.kind == NodeKind.java_framework
        and node.props.get("tool") == "java_detect_frameworks"
        for node in ctx.kb.nodes()
    )


def test_java_detect_frameworks_ignores_non_zip(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_detect_frameworks import build_tool

    path = tmp_path / "not.jar"
    path.write_text("not a jar", encoding="utf-8")
    ctx = _ctx(path)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(path)))

    assert result.framework_count == 0
    assert result.frameworks == []


def test_memory_agent_registers_java_detect_frameworks() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_detect_frameworks" in agent._function_toolset.tools
