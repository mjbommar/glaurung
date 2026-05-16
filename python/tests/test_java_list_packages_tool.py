from __future__ import annotations

import shutil
import subprocess
import zipfile
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


def _compile_package_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java package fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    app = src / "app"
    sub = app / "sub"
    other = src / "other"
    app.mkdir(parents=True)
    sub.mkdir(parents=True)
    other.mkdir(parents=True)
    out.mkdir()
    (app / "Main.java").write_text(
        """
package app;

public class Main implements Runnable {
    public void run() {}

    public Runnable task() {
        return () -> System.out.println("package summary");
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (sub / "Mode.java").write_text(
        "package app.sub; public enum Mode { ALPHA, BETA }\n",
        encoding="utf-8",
    )
    (other / "Pair.java").write_text(
        "package other; public record Pair(String key, int value) {}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(out),
            str(app / "Main.java"),
            str(sub / "Mode.java"),
            str(other / "Pair.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "packages.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    with zipfile.ZipFile(jar, "a") as zf:
        zf.writestr("app/config.properties", "enabled=true\n")
        zf.writestr("app/sub/data.json", '{"name":"mode"}\n')
    return jar


def test_java_list_packages_summarizes_classes_resources_and_kb(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_list_packages import build_tool

    jar = _compile_package_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), package_prefix="app", include_resources=True),
    )

    assert result.archive_path == str(jar)
    assert result.class_count_scanned == 3
    assert result.resource_count_scanned >= 2
    assert result.matched_package_count == 2
    assert result.truncated is False

    packages = {pkg.package_name: pkg for pkg in result.packages}
    assert set(packages) == {"app", "app/sub"}

    app = packages["app"]
    assert app.dotted_package_name == "app"
    assert app.class_count == 1
    assert app.public_class_count == 1
    assert app.method_count >= 3
    assert app.methods_with_code >= 2
    assert app.bootstrap_method_count > 0
    assert app.resource_count == 1
    assert app.resource_bytes > 0
    assert app.classes_sample == ["app/Main"]
    assert app.resources_sample == ["app/config.properties"]
    assert app.java_releases == [17]
    assert app.java_release_labels == ["Java 17"]

    sub = packages["app/sub"]
    assert sub.dotted_package_name == "app.sub"
    assert sub.class_count == 1
    assert sub.enum_count == 1
    assert sub.resource_count == 1
    assert sub.resources_sample == ["app/sub/data.json"]

    assert any(
        node.kind == NodeKind.java_package
        and node.props.get("tool") == "java_list_packages"
        and node.props.get("package_name") == "app"
        for node in ctx.kb.nodes()
    )
    archive_node = next(
        node
        for node in ctx.kb.nodes()
        if node.kind == NodeKind.java_archive
        and node.props.get("tool") == "java_list_packages"
    )
    package_node = next(
        node
        for node in ctx.kb.nodes()
        if node.kind == NodeKind.java_package
        and node.props.get("package_name") == "app"
    )
    assert any(
        edge.src == archive_node.id
        and edge.dst == package_node.id
        and edge.kind == "contains_package"
        for edge in ctx.kb.edges()
    )


def test_java_list_packages_respects_limit(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_packages import build_tool

    jar = _compile_package_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), limit=1))

    assert result.package_count >= 3
    assert len(result.packages) == 1
    assert result.truncated
    assert result.stop_reasons == ["limit"]


def test_java_list_packages_handles_non_zip(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_list_packages import build_tool

    not_zip = tmp_path / "not.jar"
    not_zip.write_text("not a jar", encoding="utf-8")
    ctx = _ctx(not_zip)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(not_zip)))

    assert result.archive_path == str(not_zip)
    assert result.package_count == 0
    assert result.stop_reasons == ["input_not_zip"]


def test_memory_agent_registers_java_list_packages() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_list_packages" in agent._function_toolset.tools
