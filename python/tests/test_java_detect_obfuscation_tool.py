from __future__ import annotations

import shutil
import subprocess
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


def _compile_short_name_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "a.java").write_text(
        """
public class a {
    int b = 1;
    int c = 2;
    public void d() { b++; }
    public int e() { return b + c; }
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
    jar_path = tmp_path / "short.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_java_detect_obfuscation_reports_low_for_helloworld() -> None:
    from glaurung.llm.tools.java_detect_obfuscation import build_tool

    jar = _need(_HELLO_JAR)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.level in {"none", "low"}
    assert result.class_count == 1
    assert result.short_class_name_count == 0
    assert result.note_node_id is not None
    assert any(
        n.kind == NodeKind.note and "obfuscation" in n.tags for n in ctx.kb.nodes()
    )


def test_java_detect_obfuscation_reports_high_for_generated_short_names(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_detect_obfuscation import build_tool

    jar = _compile_short_name_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.level in {"medium", "high"}
    assert result.class_count == 1
    assert result.short_class_name_count == 1
    assert result.short_member_name_count >= 4
    assert "a" in result.short_class_examples
    assert result.mapping_recommended


def test_memory_agent_registers_java_detect_obfuscation() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_detect_obfuscation" in agent._function_toolset.tools
