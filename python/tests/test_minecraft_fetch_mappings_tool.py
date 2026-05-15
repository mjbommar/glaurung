from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(tmp_path: Path) -> MemoryContext:
    jar = tmp_path / "sample.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    art = g.triage.analyze_path(str(jar), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(jar), artifact=art)
    import_triage(ctx.kb, art, str(jar))
    return ctx


def _mapping_text() -> str:
    return "\n".join(
        [
            "# Synthetic mapping fixture safe to vendor in tests.",
            "net.minecraft.client.Minecraft -> fgo:",
            "    int missTime -> a",
            "    void tick() -> p",
            "net.minecraft.world.level.Level -> dcw:",
            "",
        ]
    )


def _metadata_fixture(tmp_path: Path, *, mapping_bytes: bytes | None = None) -> str:
    mapping = tmp_path / "client.txt"
    data = mapping_bytes or _mapping_text().encode()
    mapping.write_bytes(data)
    version_meta = tmp_path / "version.json"
    version_meta.write_text(
        json.dumps(
            {
                "id": "1.20.1",
                "downloads": {
                    "client_mappings": {
                        "url": mapping.as_uri(),
                        "sha1": hashlib.sha1(data).hexdigest(),
                        "size": len(data),
                    }
                },
            }
        )
    )
    manifest = tmp_path / "version_manifest_v2.json"
    manifest.write_text(
        json.dumps(
            {
                "versions": [
                    {
                        "id": "1.20.1",
                        "url": version_meta.as_uri(),
                    }
                ]
            }
        )
    )
    return manifest.as_uri()


def test_minecraft_fetch_mappings_downloads_and_indexes_synthetic_fixture(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.minecraft_fetch_mappings import build_tool

    ctx = _ctx(tmp_path)
    manifest_url = _metadata_fixture(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            version="1.20.1",
            side="client",
            source="mojang",
            manifest_url=manifest_url,
            cache_dir=str(tmp_path / "cache"),
        ),
    )

    assert result.version == "1.20.1"
    assert result.side == "client"
    assert result.source == "mojang"
    assert result.format == "proguard"
    assert result.verified_sha1
    assert result.verified_size
    assert result.class_count == 2
    assert result.field_count == 1
    assert result.method_count == 1
    assert Path(result.mapping_path).read_text() == _mapping_text()
    assert any(n.kind == NodeKind.java_mapping for n in ctx.kb.nodes())


def test_minecraft_fetch_mappings_uses_verified_cache(tmp_path: Path) -> None:
    from glaurung.llm.tools.minecraft_fetch_mappings import build_tool

    ctx = _ctx(tmp_path)
    manifest_url = _metadata_fixture(tmp_path)
    tool = build_tool()
    args = tool.input_model(
        version="1.20.1",
        side="client",
        manifest_url=manifest_url,
        cache_dir=str(tmp_path / "cache"),
    )

    first = tool.run(ctx, ctx.kb, args)
    second = tool.run(ctx, ctx.kb, args)

    assert not first.from_cache
    assert second.from_cache
    assert second.mapping_path == first.mapping_path
    assert second.sha1 == first.sha1


def test_minecraft_fetch_mappings_rejects_hash_mismatch(tmp_path: Path) -> None:
    from glaurung.llm.tools.minecraft_fetch_mappings import build_tool

    ctx = _ctx(tmp_path)
    manifest_url = _metadata_fixture(tmp_path)
    version_meta = tmp_path / "version.json"
    payload = json.loads(version_meta.read_text())
    payload["downloads"]["client_mappings"]["sha1"] = "0" * 40
    version_meta.write_text(json.dumps(payload))

    tool = build_tool()
    try:
        tool.run(
            ctx,
            ctx.kb,
            tool.input_model(
                version="1.20.1",
                side="client",
                manifest_url=manifest_url,
                cache_dir=str(tmp_path / "cache"),
            ),
        )
    except ValueError as e:
        assert "sha1" in str(e)
    else:
        raise AssertionError("expected sha1 mismatch")


def test_minecraft_fetch_mappings_ignores_missing_version_or_side(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.minecraft_fetch_mappings import build_tool

    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model())

    assert result.version == ""
    assert result.side == "client"
    assert result.mapping_path == ""
    assert result.class_count == 0
    assert result.mapping_node_id is None


def test_memory_agent_registers_minecraft_fetch_mappings() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "minecraft_fetch_mappings" in agent._function_toolset.tools
