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
    (src / "net" / "minecraftforge" / "eventbus" / "api").mkdir(parents=True)
    out.mkdir()
    (
        src / "net" / "minecraftforge" / "eventbus" / "api" / "SubscribeEvent.java"
    ).write_text(
        """
package net.minecraftforge.eventbus.api;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface SubscribeEvent {}
""".strip()
        + "\n",
        encoding="utf-8",
    )
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
    (src / "ForgeEventHandler.java").write_text(
        """
import java.nio.file.Path;
import net.minecraftforge.eventbus.api.SubscribeEvent;

public class ForgeEventHandler {
    @SubscribeEvent
    public void onEvent(Path path) throws Exception {
        Worker.write(path);
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

    public static void unused(Path path) throws Exception {
        Files.writeString(path, "unreachable");
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
            *[str(path) for path in src.rglob("*.java")],
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
            entrypoint_categories=["main_method"],
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


def test_java_reachability_uses_forge_event_annotation_entrypoints(
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
            entrypoint_categories=["forge_subscribe_event"],
            max_depth=4,
        ),
    )

    assert result.reachable
    assert result.path_count == 1
    path = result.paths[0]
    assert path.entrypoint_category == "forge_subscribe_event"
    assert path.entrypoint_method_id == (
        "ForgeEventHandler#onEvent(Ljava/nio/file/Path;)V"
    )
    assert [edge.source_method_id for edge in path.edges] == [
        "ForgeEventHandler#onEvent(Ljava/nio/file/Path;)V",
        "Worker#write(Ljava/nio/file/Path;)V",
    ]


def test_java_reachability_can_match_exact_call_site(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_call_graph import build_tool as build_call_graph_tool
    from glaurung.llm.tools.java_reachability import build_tool

    jar = _compile_reachability_jar(tmp_path)
    ctx = _ctx(jar)
    call_graph_tool = build_call_graph_tool()
    graph = call_graph_tool.run(
        ctx,
        ctx.kb,
        call_graph_tool.input_model(
            path=str(jar),
            class_name="Worker",
            method_name="unused",
            method_descriptor="(Ljava/nio/file/Path;)V",
        ),
    )
    unused_call = next(
        edge
        for edge in graph.edges
        if edge.target_owner == "java/nio/file/Files"
        and edge.target_name == "writeString"
    )
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            target_owner="java/nio/file/Files",
            target_name="writeString",
            target_descriptor="(Ljava/nio/file/Path;Ljava/lang/CharSequence;[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;",
            target_source_class_name="Worker",
            target_source_method_name="unused",
            target_source_method_descriptor="(Ljava/nio/file/Path;)V",
            target_bci=unused_call.bci,
            max_depth=4,
        ),
    )

    assert not result.reachable
    assert result.path_count == 0
    assert result.target_match_count == 1
    assert "target_not_reached" in result.stop_reasons


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
