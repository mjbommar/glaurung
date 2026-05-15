from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


_HELLO_JAR = Path("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar")


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def test_java_index_archive_summarizes_vendored_jar() -> None:
    from glaurung.llm.tools.java_index_archive import build_tool

    jar = _need(_HELLO_JAR)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx, ctx.kb, tool.input_model(path=str(jar), include_resources=True)
    )

    assert result.archive_path == str(jar)
    assert result.archive_format == "jar"
    assert result.class_count == 1
    assert result.resource_count == 1
    assert result.manifest_main_class == "HelloWorld"
    assert not result.truncated
    assert len(result.classes) == 1
    cls = result.classes[0]
    assert cls.entry_name == "HelloWorld.class"
    assert cls.class_name == "HelloWorld"
    assert cls.major_version in {55, 61, 65}
    assert cls.method_count >= 1
    assert cls.methods_with_code >= 1

    assert any(n.kind == NodeKind.java_archive for n in ctx.kb.nodes())
    assert any(
        n.kind == NodeKind.java_class and n.label == "HelloWorld"
        for n in ctx.kb.nodes()
    )


def test_java_index_archive_respects_class_limit() -> None:
    from glaurung.llm.tools.java_index_archive import build_tool

    jar = _need(_HELLO_JAR)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), max_classes=0))

    assert result.class_count == 1
    assert result.classes == []
    assert result.truncated


def test_memory_agent_registers_java_index_archive() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_index_archive" in agent._function_toolset.tools
