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


def _compile_xref_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "Callee.java").write_text(
        """
public class Callee {
    public static String label = "ready";
    public static int add(int left, int right) {
        return left + right;
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "Caller.java").write_text(
        """
public class Caller {
    public static int run() {
        System.out.println(Callee.label);
        return Callee.add(2, 3);
    }
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
            str(src / "Callee.java"),
            str(src / "Caller.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "xrefs.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_java_xrefs_from_lists_method_references(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_xrefs_from import build_tool

    jar = _compile_xref_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="Caller",
            method_name="run",
            method_descriptor="()I",
        ),
    )

    assert result.method_found
    assert result.xref_count >= 3
    assert any(
        xref.kind == "field" and xref.owner == "Callee" and xref.name == "label"
        for xref in result.xrefs
    )
    assert any(
        xref.kind == "method" and xref.owner == "Callee" and xref.name == "add"
        for xref in result.xrefs
    )
    assert any(
        n.kind == NodeKind.java_xref
        and n.props.get("source_class_name") == "Caller"
        and n.props.get("tool") == "java_xrefs_from"
        for n in ctx.kb.nodes()
    )


def test_java_xrefs_to_finds_callers_by_target(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_xrefs_to import build_tool

    jar = _compile_xref_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            target_owner="Callee",
            target_name="add",
            target_descriptor="(II)I",
        ),
    )

    assert result.xref_count == 1
    assert result.xrefs[0].source_class_name == "Caller"
    assert result.xrefs[0].source_method_name == "run"
    assert result.xrefs[0].line_number == 4


def test_memory_agent_registers_java_xref_tools() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_xrefs_from" in agent._function_toolset.tools
    assert "java_xrefs_to" in agent._function_toolset.tools
