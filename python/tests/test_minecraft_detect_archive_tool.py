from __future__ import annotations

import json
import zipfile
from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _vanilla_client_jar(tmp_path: Path) -> Path:
    jar = tmp_path / "minecraft-client.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Main-Class: net.minecraft.client.Main\n")
        zf.writestr(
            "version.json",
            json.dumps(
                {
                    "id": "1.20.1",
                    "name": "1.20.1",
                    "world_version": 3465,
                    "protocol_version": 763,
                    "java_version": 17,
                    "stable": True,
                }
            ),
        )
    return jar


def _forge_jar(tmp_path: Path) -> Path:
    jar = tmp_path / "forge.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr(
            "META-INF/mods.toml",
            """
modLoader="javafml"
loaderVersion="[47,)"
[[mods]]
modId="forge"
displayName="Forge"
version="47.4.18"
""".strip()
            + "\n",
        )
        zf.writestr("coremods/example.js", "// test coremod\n")
    return jar


def _bundler_server_jar(tmp_path: Path) -> Path:
    jar = tmp_path / "minecraft-server.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\n"
            "Main-Class: net.minecraft.bundler.Main\n"
            "Bundler-Format: 1.0\n",
        )
        zf.writestr("version.json", json.dumps({"id": "1.20.1", "java_version": 17}))
        zf.writestr("META-INF/versions/1.20.1/server-1.20.1.jar", b"PK\x03\x04")
    return jar


def test_minecraft_detect_archive_identifies_vanilla_client(tmp_path: Path) -> None:
    from glaurung.llm.tools.minecraft_detect_archive import build_tool

    jar = _vanilla_client_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.is_minecraft
    assert result.loader == "vanilla"
    assert result.side == "client"
    assert result.minecraft_version == "1.20.1"
    assert result.java_version == 17
    assert result.protocol_version == 763
    assert result.mapping_recommended
    assert result.preferred_mapping_source == "mojang"
    assert any(
        n.kind == NodeKind.note and "minecraft" in n.tags for n in ctx.kb.nodes()
    )


def test_minecraft_detect_archive_identifies_forge(tmp_path: Path) -> None:
    from glaurung.llm.tools.minecraft_detect_archive import build_tool

    jar = _forge_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.is_minecraft
    assert result.loader == "forge"
    assert result.side == "unknown"
    assert result.forge_mod_ids == ["forge"]
    assert result.coremod_count == 1


def test_minecraft_detect_archive_identifies_bundled_server(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.minecraft_detect_archive import build_tool

    jar = _bundler_server_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.is_minecraft
    assert result.loader == "vanilla"
    assert result.side == "server"
    assert result.bundler_format == "1.0"
    assert result.bundled_server_entries == [
        "META-INF/versions/1.20.1/server-1.20.1.jar"
    ]
    assert "Bundled server entries=1" in result.rationale


def test_memory_agent_registers_minecraft_detect_archive() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "minecraft_detect_archive" in agent._function_toolset.tools
