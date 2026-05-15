from __future__ import annotations

from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "mapping.txt"
    path.write_text("# context file\n", encoding="utf-8")
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "mappings.txt"
    path.write_text(
        """
com.example.GameThing -> a:
    int health -> b
    void tick() -> c
    void setScreen(com.example.Screen) -> d
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def test_java_lookup_mapping_finds_class_by_obfuscated_name(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_lookup_mapping import build_tool

    mapping = _mapping_file(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(mapping_path=str(mapping), class_name="a"),
    )

    assert result.class_found
    assert result.matched_by == "obfuscated"
    assert result.official_class_name == "com.example.GameThing"
    assert result.obfuscated_class_name == "a"
    assert {m.official_name for m in result.methods} == {"tick", "setScreen"}
    assert result.fields[0].official_name == "health"
    assert any(n.kind == NodeKind.note and "mapping" in n.tags for n in ctx.kb.nodes())


def test_java_lookup_mapping_filters_member_by_either_namespace(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_lookup_mapping import build_tool

    mapping = _mapping_file(tmp_path)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    by_official = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            mapping_path=str(mapping),
            class_name="com.example.GameThing",
            member_name="tick",
        ),
    )
    by_obfuscated = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            mapping_path=str(mapping),
            class_name="a",
            member_name="c",
        ),
    )

    assert by_official.matched_by == "official"
    assert [m.obfuscated_name for m in by_official.methods] == ["c"]
    assert [m.official_name for m in by_obfuscated.methods] == ["tick"]


def test_memory_agent_registers_java_lookup_mapping() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_lookup_mapping" in agent._function_toolset.tools
