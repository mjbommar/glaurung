from __future__ import annotations

import shutil
import subprocess
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


def _compile_obfuscated_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "a.java").write_text(
        """
public class a {
    public int b = 1;
    public String d = "hello";
    public void c() { b++; }
    public int e(int value) { return b + value; }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "a.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "obfuscated.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "mappings.txt"
    path.write_text(
        """
com.example.GameThing -> a:
    int health -> b
    java.lang.String greeting -> d
    void tick() -> c
    void unrelated(java.lang.String) -> c
    int score(int) -> e
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def test_java_annotate_mappings_adds_deobfuscated_class_nodes(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_annotate_mappings import build_tool

    jar = _compile_obfuscated_jar(tmp_path)
    mapping = _mapping_file(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), mapping_path=str(mapping)),
    )

    assert result.class_count == 1
    assert result.parsed_class_count == 1
    assert result.mapped_class_count == 1
    assert result.parsed_field_count == 2
    assert result.mapped_field_count == 2
    assert result.parsed_method_count >= 3
    assert result.mapped_method_count == 2
    assert result.classes[0].class_name == "a"
    assert result.classes[0].mapped_class_name == "com.example.GameThing"
    assert result.classes[0].field_mapping_count == 2
    assert result.classes[0].method_mapping_count == 2
    assert any(
        n.kind == NodeKind.java_class
        and n.props.get("mapped_class_name") == "com.example.GameThing"
        for n in ctx.kb.nodes()
    )


def test_memory_agent_registers_java_annotate_mappings() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_annotate_mappings" in agent._function_toolset.tools
