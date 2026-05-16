from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import json
import zipfile

import pytest

import glaurung as g
from glaurung.cli.commands.ask import AskCommand
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


_HELLO_JAR = Path("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar")


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def test_ask_command_seeds_java_archive_context_for_jar() -> None:
    jar = _need(_HELLO_JAR)
    art = g.triage.analyze_path(str(jar), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(jar), artifact=art)
    import_triage(ctx.kb, art, str(jar))

    AskCommand()._seed_high_signal_context(
        ctx,
        SimpleNamespace(max_functions=5),
    )

    nodes = list(ctx.kb.nodes())
    assert any(n.kind == NodeKind.java_agent_context for n in nodes)
    assert any(n.kind == NodeKind.java_archive for n in nodes)
    assert any(n.kind == NodeKind.java_class and n.label == "HelloWorld" for n in nodes)
    assert any(n.kind == NodeKind.note and "obfuscation" in n.tags for n in nodes)


def test_ask_command_seeds_minecraft_archive_context(tmp_path: Path) -> None:
    jar = tmp_path / "minecraft-client.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Main-Class: net.minecraft.client.Main\n")
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
    art = g.triage.analyze_path(str(jar), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(jar), artifact=art)
    import_triage(ctx.kb, art, str(jar))

    AskCommand()._seed_high_signal_context(
        ctx,
        SimpleNamespace(max_functions=5),
    )

    nodes = list(ctx.kb.nodes())
    assert any(
        n.kind == NodeKind.note
        and "minecraft" in n.tags
        and n.props.get("preferred_mapping_source") == "mojang"
        for n in nodes
    )
