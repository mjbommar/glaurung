from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _inner_server_jar() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bvo.class", b"\xca\xfe\xba\xbe")
        zf.writestr("server.properties", "online-mode=true\n")
    return buf.getvalue()


def _bundler_jar(tmp_path: Path) -> Path:
    jar = tmp_path / "minecraft-server-1.20.1.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\n"
            "Main-Class: net.minecraft.bundler.Main\n"
            "Bundler-Format: 1.0\n",
        )
        zf.writestr(
            "version.json",
            json.dumps(
                {
                    "id": "1.20.1",
                    "world_version": 3465,
                    "protocol_version": 763,
                    "java_version": 17,
                    "stable": True,
                }
            ),
        )
        zf.writestr("META-INF/versions/1.20.1/server-1.20.1.jar", _inner_server_jar())
    return jar


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def test_minecraft_extract_bundled_server_extracts_nested_jar(tmp_path: Path) -> None:
    from glaurung.llm.tools.minecraft_extract_bundled_server import build_tool

    jar = _bundler_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), out_dir=str(tmp_path / "cache")),
    )

    assert result.outer_path == str(jar)
    assert result.nested_entry == "META-INF/versions/1.20.1/server-1.20.1.jar"
    assert result.extracted_path.endswith("server-1.20.1.jar")
    assert result.class_count == 1
    assert result.resource_count == 1
    with zipfile.ZipFile(result.extracted_path) as zf:
        assert sorted(zf.namelist()) == ["bvo.class", "server.properties"]
    assert any(
        n.kind == NodeKind.java_archive and "bundled-server" in n.tags
        for n in ctx.kb.nodes()
    )


def test_minecraft_extract_bundled_server_respects_cache(tmp_path: Path) -> None:
    from glaurung.llm.tools.minecraft_extract_bundled_server import build_tool

    jar = _bundler_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()
    args = tool.input_model(path=str(jar), out_dir=str(tmp_path / "cache"))

    first = tool.run(ctx, ctx.kb, args)
    second = tool.run(ctx, ctx.kb, args)

    assert not first.from_cache
    assert second.from_cache
    assert second.sha256 == first.sha256


def test_memory_agent_registers_minecraft_extract_bundled_server() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "minecraft_extract_bundled_server" in agent._function_toolset.tools
