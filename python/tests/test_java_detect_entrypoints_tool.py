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


def _compile_entrypoint_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    classes = tmp_path / "classes"
    manifest = tmp_path / "MANIFEST.MF"
    src.mkdir()
    (src / "demo").mkdir()
    (src / "net" / "minecraftforge" / "fml" / "common").mkdir(parents=True)
    (src / "net" / "minecraftforge" / "eventbus" / "api").mkdir(parents=True)
    classes.mkdir()
    (src / "net" / "minecraftforge" / "fml" / "common" / "Mod.java").write_text(
        """
package net.minecraftforge.fml.common;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface Mod {
    String value();
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
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
    (src / "demo" / "App.java").write_text(
        """
package demo;

public class App {
    public static void main(String[] args) {
        new SchedulerThing().install(null);
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "demo" / "ForgeMod.java").write_text(
        """
package demo;

import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.eventbus.api.SubscribeEvent;

@Mod("demo_mod")
public class ForgeMod {
    public ForgeMod() {
        new SchedulerThing();
    }

    @SubscribeEvent
    public void onServerStarting(String event) {}
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "demo" / "AgentThing.java").write_text(
        """
package demo;

import java.lang.instrument.Instrumentation;

public class AgentThing {
    public static void premain(String args, Instrumentation inst) {}
    public static void agentmain(String args, Instrumentation inst) {}
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "demo" / "ServiceImpl.java").write_text(
        """
package demo;

public class ServiceImpl implements Runnable {
    public void run() {}
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "demo" / "SchedulerThing.java").write_text(
        """
package demo;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SchedulerThing {
    public void install(ScheduledExecutorService service) {
        service.scheduleAtFixedRate(() -> {}, 1, 1, TimeUnit.SECONDS);
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(classes),
            *[str(path) for path in src.rglob("*.java")],
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    service_dir = classes / "META-INF" / "services"
    service_dir.mkdir(parents=True)
    (service_dir / "java.lang.Runnable").write_text(
        "demo.ServiceImpl\n", encoding="utf-8"
    )
    manifest.write_text(
        """
Manifest-Version: 1.0
Main-Class: demo.App
Premain-Class: demo.AgentThing
Agent-Class: demo.AgentThing
""".lstrip(),
        encoding="utf-8",
    )
    jar_path = tmp_path / "entrypoints.jar"
    subprocess.run(
        [
            "jar",
            "--create",
            "--file",
            str(jar_path),
            "--manifest",
            str(manifest),
            "-C",
            str(classes),
            ".",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_java_detect_entrypoints_reports_manifest_services_and_schedulers(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_detect_entrypoints import build_tool

    jar = _compile_entrypoint_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    categories = {entry.category for entry in result.entrypoints}
    assert {
        "manifest_main",
        "main_method",
        "java_agent_premain",
        "java_agent_agentmain",
        "service_provider",
        "scheduler_registration",
        "forge_mod_constructor",
        "forge_subscribe_event",
    } <= categories
    assert result.class_count == 7
    assert result.entrypoint_count == len(result.entrypoints)
    assert any(
        entry.category == "manifest_main"
        and entry.class_name == "demo/App"
        and entry.method_name == "main"
        for entry in result.entrypoints
    )
    assert any(
        entry.category == "scheduler_registration"
        and entry.class_name == "demo/SchedulerThing"
        and entry.method_name == "install"
        and entry.bci is not None
        for entry in result.entrypoints
    )
    assert any(
        entry.category == "forge_mod_constructor"
        and entry.class_name == "demo/ForgeMod"
        and entry.method_name == "<init>"
        and entry.method_descriptor == "()V"
        and "demo_mod" in entry.detail
        for entry in result.entrypoints
    )
    assert any(
        entry.category == "forge_subscribe_event"
        and entry.class_name == "demo/ForgeMod"
        and entry.method_name == "onServerStarting"
        and entry.method_descriptor == "(Ljava/lang/String;)V"
        for entry in result.entrypoints
    )
    assert any(n.kind == NodeKind.java_entrypoint for n in ctx.kb.nodes())


def test_memory_agent_registers_java_detect_entrypoints() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_detect_entrypoints" in agent._function_toolset.tools
