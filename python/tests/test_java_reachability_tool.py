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


def _compile_reachability_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "App.java").write_text(
        """
import java.nio.file.Path;

public class App {
    public static void main(String[] args) throws Exception {
        Controller.handle(Path.of("demo.txt"));
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "Controller.java").write_text(
        """
import java.nio.file.Path;

public class Controller {
    public static void handle(Path path) throws Exception {
        Worker.write(path);
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "Worker.java").write_text(
        """
import java.nio.file.Files;
import java.nio.file.Path;

public class Worker {
    public static void write(Path path) throws Exception {
        Files.writeString(path, "reachable");
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
            *[str(path) for path in src.glob("*.java")],
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "reachability.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_java_reachability_finds_entrypoint_to_external_sink_path(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_reachability import build_tool

    jar = _compile_reachability_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            target_owner="java/nio/file/Files",
            target_name="writeString",
            target_descriptor="(Ljava/nio/file/Path;Ljava/lang/CharSequence;[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;",
            max_depth=4,
        ),
    )

    assert result.reachable
    assert result.path_count == 1
    path = result.paths[0]
    assert path.entrypoint_category == "main_method"
    assert path.entrypoint_method_id == "App#main([Ljava/lang/String;)V"
    assert path.target_method_id.startswith("java/nio/file/Files#writeString")
    assert path.depth == 3
    assert [edge.source_method_id for edge in path.edges] == [
        "App#main([Ljava/lang/String;)V",
        "Controller#handle(Ljava/nio/file/Path;)V",
        "Worker#write(Ljava/nio/file/Path;)V",
    ]
    assert any(
        node.kind == NodeKind.java_reachability
        and node.props.get("tool") == "java_reachability"
        and node.props.get("reachable") is True
        for node in ctx.kb.nodes()
    )


def test_java_reachability_reports_unreachable_target(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_reachability import build_tool

    jar = _compile_reachability_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            target_owner="java/net/Socket",
            target_name="<init>",
            max_depth=4,
        ),
    )

    assert not result.reachable
    assert result.path_count == 0
    assert "target_not_reached" in result.stop_reasons


def test_memory_agent_registers_java_reachability() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_reachability" in agent._function_toolset.tools
