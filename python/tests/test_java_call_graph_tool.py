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


def _compile_call_graph_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "Worker.java").write_text(
        """
public interface Worker {
    int work(int value);
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "Helper.java").write_text(
        """
public class Helper {
    public static int add(int value) {
        return value + 1;
    }

    public int instance(int value) {
        return add(value);
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "Caller.java").write_text(
        """
public class Caller {
    public static int run(Worker worker) {
        Helper helper = new Helper();
        int first = Helper.add(1);
        int second = helper.instance(first);
        return worker.work(second);
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
            str(src / "Worker.java"),
            str(src / "Helper.java"),
            str(src / "Caller.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "call-graph.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _compile_mapped_call_graph_jar(tmp_path: Path) -> tuple[Path, Path]:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "mapped-src"
    out = tmp_path / "mapped-classes"
    src.mkdir()
    out.mkdir()
    (src / "a.java").write_text(
        """
public class a {
    public static int b() {
        return c.c();
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "c.java").write_text(
        """
public class c {
    public static int c() {
        return 42;
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
            str(src / "a.java"),
            str(src / "c.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "mapped-call-graph.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    mapping_path = tmp_path / "mapped.txt"
    mapping_path.write_text(
        """
com.example.Caller -> a:
    int run() -> b
com.example.Helper -> c:
    int compute() -> c
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return jar_path, mapping_path


def test_java_call_graph_lists_invocation_edges(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_call_graph import build_tool

    jar = _compile_call_graph_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="Caller",
            method_name="run",
            method_descriptor="(LWorker;)I",
        ),
    )

    assert result.edge_count == 4
    assert result.node_count >= 5
    assert not result.truncated
    assert {
        (edge.target_owner, edge.target_name, edge.target_descriptor, edge.invoke_kind)
        for edge in result.edges
    } == {
        ("Helper", "<init>", "()V", "invokespecial"),
        ("Helper", "add", "(I)I", "invokestatic"),
        ("Helper", "instance", "(I)I", "invokevirtual"),
        ("Worker", "work", "(I)I", "invokeinterface"),
    }
    assert all(edge.target_defined for edge in result.edges)
    assert any(edge.line_number == 3 for edge in result.edges)
    assert any(
        node.kind == NodeKind.java_call_graph
        and node.props.get("tool") == "java_call_graph"
        and node.props.get("edge_count") == 4
        for node in ctx.kb.nodes()
    )


def test_java_call_graph_marks_external_targets(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_call_graph import build_tool

    jar = _compile_call_graph_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            class_name="Helper",
            method_name="<init>",
            method_descriptor="()V",
        ),
    )

    assert result.edge_count == 1
    edge = result.edges[0]
    assert edge.target_owner == "java/lang/Object"
    assert edge.target_name == "<init>"
    assert not edge.target_defined
    assert result.external_target_count == 1


def test_memory_agent_registers_java_call_graph() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_call_graph" in agent._function_toolset.tools


def test_java_call_graph_applies_mapping_annotations(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_call_graph import build_tool

    jar, mapping = _compile_mapped_call_graph_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            mapping_path=str(mapping),
            class_name="com.example.Caller",
            method_name="run",
            method_descriptor="()I",
        ),
    )

    assert result.edge_count == 1
    edge = result.edges[0]
    assert edge.source_class_name == "a"
    assert edge.mapped_source_class_name == "com.example.Caller"
    assert edge.mapped_source_method_names == ["run"]
    assert edge.target_owner == "c"
    assert edge.mapped_target_owner == "com.example.Helper"
    assert edge.mapped_target_names == ["compute"]
    assert edge.mapped_target_descriptor == "()I"
