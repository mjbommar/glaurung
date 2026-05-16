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


def _simple_recoverable_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java recovery fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "Main.java").write_text(
        """
package app;

public class Main {
    public String value() {
        return "daily-driver";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "Main.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "simple.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "Main.class", "app/Main.class")
    return jar


def _dependency_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java dependency fixture")
    src = tmp_path / "dep-src"
    out = tmp_path / "dep-classes"
    src.mkdir()
    out.mkdir()
    (src / "Helper.java").write_text(
        """
package dep;

public class Helper {
    public static String value() {
        return "dependency";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src / "Helper.java")],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "dep.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "dep" / "Helper.class", "dep/Helper.class")
    return jar


def _jar_with_unextracted_dependency(tmp_path: Path) -> Path:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java recovery fixture")
    dep_jar = _dependency_jar(tmp_path)
    src = tmp_path / "app-src"
    out = tmp_path / "app-classes"
    src.mkdir()
    out.mkdir()
    (src / "UsesDep.java").write_text(
        """
package app;

import dep.Helper;

public class UsesDep {
    public String value() {
        return Helper.value();
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
            "-classpath",
            str(dep_jar),
            "-d",
            str(out),
            str(src / "UsesDep.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "uses-dep.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.write(out / "app" / "UsesDep.class", "app/UsesDep.class")
        zf.write(dep_jar, "META-INF/libraries/dep/dep/1.0.0/dep-1.0.0.jar")
    return jar


def test_java_recovery_report_summarizes_clean_recovery(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_recovery_report import build_tool

    jar = _simple_recoverable_jar(tmp_path)
    output = tmp_path / "clean-recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            java_release=17,
            max_classes=4,
        ),
    )

    assert result.status == "clean"
    assert result.blocker_count == 0
    assert result.progress.compile_success is True
    assert result.progress.validation_passed is True
    assert result.progress.generated_source_count == 1
    assert result.progress.parsed_source_count == 1
    assert "Status: clean" in result.markdown
    assert "No blocking recovery issues" in result.markdown
    assert any(
        node.kind == NodeKind.java_recovery_report
        and node.props.get("tool") == "java_recovery_report"
        for node in ctx.kb.nodes()
    )


def test_java_recovery_report_ranks_dependency_blocker_with_excerpt(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_recovery_report import build_tool

    jar = _jar_with_unextracted_dependency(tmp_path)
    output = tmp_path / "blocked-recovered"
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            java_release=17,
            max_classes=4,
            extract_nested_archives=False,
            run_repair=True,
            max_repair_iterations=1,
            validate_profile="compile_only",
        ),
    )

    assert result.status in {"blocked", "partial"}
    assert result.blocker_count >= 1
    blocker = result.blockers[0]
    assert blocker.kind in {"compile_error", "repair_deferred"}
    assert blocker.location is not None
    assert blocker.location.file.endswith("UsesDep.java")
    assert blocker.next_action
    assert "classpath" in " ".join(result.next_actions).lower()
    assert "Top Blockers" in result.markdown
    assert "Error:" in result.markdown
    assert "UsesDep.java" in result.markdown
    assert any("Helper" in line.text or "dep" in line.text for line in blocker.snippet)


def test_memory_agent_registers_java_recovery_report() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_recovery_report" in agent._function_toolset.tools
