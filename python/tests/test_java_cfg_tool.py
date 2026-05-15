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


def _compile_cfg_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "CfgFixture.java").write_text(
        """
public class CfgFixture {
    public static int classify(int value) {
        int total = 0;
        for (int i = 0; i < value; i++) {
            if ((i & 1) == 0) {
                total += i;
            } else {
                total -= i;
            }
        }
        return total;
    }

    public static int guarded(String input) {
        try {
            return Integer.parseInt(input);
        } catch (NumberFormatException ex) {
            return -1;
        }
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
            str(src / "CfgFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "cfg-fixture.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_java_cfg_builds_basic_blocks_and_edges(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_cfg import build_tool

    jar = _compile_cfg_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="CfgFixture",
            method_name="classify",
            method_descriptor="(I)I",
        ),
    )

    assert result.method_found
    assert result.block_count >= 5
    assert result.edge_count >= 5
    assert any(block.start_bci == 0 for block in result.blocks)
    assert any(edge.kind == "conditional_true" for edge in result.edges)
    assert any(edge.kind == "conditional_false" for edge in result.edges)
    assert any(
        edge.kind == "goto" and edge.target_start_bci < edge.source_start_bci
        for edge in result.edges
    )
    assert any(
        block.terminator_mnemonic in {"ireturn", "return"} for block in result.blocks
    )
    assert any(
        n.kind == NodeKind.java_cfg
        and n.props.get("method_name") == "classify"
        and n.props.get("block_count") == result.block_count
        for n in ctx.kb.nodes()
    )


def test_java_cfg_models_exception_handler_edges(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_cfg import build_tool

    jar = _compile_cfg_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="CfgFixture",
            method_name="guarded",
            method_descriptor="(Ljava/lang/String;)I",
        ),
    )

    assert result.method_found
    assert result.exception_handler_count == 1
    assert result.exception_handlers[0].catch_type == "java/lang/NumberFormatException"
    assert any(
        block.start_bci == result.exception_handlers[0].handler_pc
        for block in result.blocks
    )
    exception_edges = [edge for edge in result.edges if edge.kind == "exception"]
    assert exception_edges
    assert any(
        edge.target_start_bci == result.exception_handlers[0].handler_pc
        and edge.catch_type == "java/lang/NumberFormatException"
        for edge in exception_edges
    )
    assert "exception_edges_not_yet_modeled" not in result.stop_reasons
    assert "stack_frame_analysis_not_yet_available" in result.stop_reasons


def test_memory_agent_registers_java_cfg() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_cfg" in agent._function_toolset.tools
