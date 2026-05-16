from __future__ import annotations

import shutil
import subprocess
import zipfile
import json
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
    assert result.report_markdown_path is not None
    assert result.report_json_path is not None
    assert Path(result.report_markdown_path).is_file()
    assert Path(result.report_json_path).is_file()
    assert result.report_markdown_path.endswith(".glaurung/recovery-report.md")
    assert result.class_summary_count == 1
    assert result.class_summaries[0].class_name == "app/Main"
    assert result.class_summaries[0].selected_engine in {"cfr", "vineflower"}
    assert result.class_summaries[0].source_file == "src/main/java/app/Main.java"
    assert result.class_summaries[0].bytecode_method_count is not None
    assert result.class_summaries[0].bytecode_method_count >= 2
    assert any(
        "value()Ljava/lang/String;" in method
        for method in result.class_summaries[0].bytecode_methods
    )
    assert result.class_summaries[0].bytecode_line_anchors
    assert result.class_summaries[0].candidate_notes
    assert result.rollups.by_package["app"] == 1
    assert result.rollups.by_engine[result.class_summaries[0].selected_engine] == 1
    assert result.rollups.by_quality[result.class_summaries[0].quality] == 1
    assert result.rollups.by_compile_status["pass"] == 1
    assert result.rollups.omitted_class_summary_count == 0
    assert any("javac" in command for command in result.commands)
    assert "Status: clean" in result.markdown
    assert "No blocking recovery issues" in result.markdown
    assert "## Rollups" in result.markdown
    assert "## Source/Bytecode Links" in result.markdown
    assert "value()Ljava/lang/String;" in result.markdown
    assert "## Class Summary" in result.markdown
    assert "## Commands" in result.markdown
    persisted = json.loads(Path(result.report_json_path).read_text(encoding="utf-8"))
    assert persisted["status"] == "clean"
    assert "recovery_result" not in persisted
    second = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            output_root=str(output),
            java_release=17,
            max_classes=4,
        ),
    )
    assert second.progress.cache_hit is True
    assert second.class_summary_count == 1
    assert second.rollups.total_class_summary_count == 1
    assert second.class_summaries[0].class_name == "app/Main"
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
    assert result.rollups.blocker_summary_by_category
    assert (
        result.rollups.blocker_summary_by_category.get(
            "missing_classpath_dependency", 0
        )
        >= 1
    )
    assert result.rollups.blocker_summary_by_file
    assert result.repair_summary_count >= 1
    assert any(
        repair.kind == "write_build_repair_plan" for repair in result.repair_summaries
    )
    assert any(repair.automation == "automatic" for repair in result.repair_summaries)
    assert any("recovery-report.md" in command for command in result.commands)
    blocker = result.blockers[0]
    assert blocker.kind in {"compile_error", "repair_deferred"}
    assert blocker.location is not None
    assert blocker.location.file.endswith("UsesDep.java")
    assert blocker.location.absolute_file is not None
    assert Path(blocker.location.absolute_file).is_file()
    assert blocker.next_action
    assert "classpath" in " ".join(result.next_actions).lower()
    assert "Top Blockers" in result.markdown
    assert "Error:" in result.markdown
    assert "UsesDep.java" in result.markdown
    assert "## Repair Summary" in result.markdown
    assert any("Helper" in line.text or "dep" in line.text for line in blocker.snippet)


def test_java_recovery_report_tracks_omitted_class_summaries(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_recovery_report import build_tool

    jar = _jar_with_unextracted_dependency(tmp_path)
    output = tmp_path / "limited-recovered"
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
            max_class_summaries=0,
            extract_nested_archives=True,
            validate_profile="compile_only",
        ),
    )

    assert result.class_summary_count == 0
    assert result.rollups.total_class_summary_count >= 1
    assert result.rollups.omitted_class_summary_count >= 1
    assert "additional class summaries" in result.markdown


def test_memory_agent_registers_java_recovery_report() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_recovery_report" in agent._function_toolset.tools
