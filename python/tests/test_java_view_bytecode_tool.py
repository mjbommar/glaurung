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


def _compile_bytecode_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "BytecodeFixture.java").write_text(
        """
public class BytecodeFixture {
    public static void print() {
        System.out.println("bytecode-fixture");
    }

    public static int gate(int value) {
        if (value > 10) {
            return value + 1;
        }
        return value - 1;
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "BytecodeFixture.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "bytecode-fixture.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_java_view_bytecode_lists_method_instructions_and_xrefs(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_view_bytecode import build_tool

    jar = _compile_bytecode_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="BytecodeFixture",
            method_name="print",
            method_descriptor="()V",
            include_xrefs=True,
        ),
    )

    assert result.method_found
    assert result.class_name == "BytecodeFixture"
    assert result.method_name == "print"
    assert [ins.mnemonic for ins in result.instructions][:3] == [
        "getstatic",
        "ldc",
        "invokevirtual",
    ]
    assert result.instructions[0].line_number == 3
    assert any(
        xref.owner == "java/io/PrintStream" and xref.name == "println"
        for xref in result.xrefs
    )
    assert any(
        n.kind == NodeKind.java_bytecode
        and n.props.get("method_name") == "print"
        and n.props.get("instruction_count") == len(result.instructions)
        for n in ctx.kb.nodes()
    )


def test_java_view_bytecode_can_show_branch_targets(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_view_bytecode import build_tool

    jar = _compile_bytecode_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="BytecodeFixture",
            method_name="gate",
            method_descriptor="(I)I",
        ),
    )

    assert result.method_found
    assert any(
        ins.mnemonic.startswith("if_")
        and any(op.startswith("target=") for op in ins.operands)
        for ins in result.instructions
    )


def test_memory_agent_registers_java_view_bytecode() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_view_bytecode" in agent._function_toolset.tools
