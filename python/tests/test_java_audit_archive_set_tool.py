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


def _compile_jar(tmp_path: Path, class_name: str, source: str) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / f"{class_name}.java"
    out = tmp_path / f"{class_name}-classes"
    out.mkdir()
    src.write_text(source.strip() + "\n", encoding="utf-8")
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(src)],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / f"{class_name}.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _fixture_dir(tmp_path: Path) -> Path:
    root = tmp_path / "mods"
    root.mkdir()
    sensitive = _compile_jar(
        tmp_path,
        "AuditSensitive",
        """
import java.nio.file.Files;
import java.nio.file.Path;

public class AuditSensitive {
    public void run(Path path) throws Exception {
        Runtime.getRuntime().exec("echo test");
        Files.writeString(path.resolve("audit.txt"), "test");
    }
}
""",
    )
    benign = _compile_jar(
        tmp_path,
        "AuditBenign",
        """
public class AuditBenign {
    public int add(int left, int right) {
        return left + right;
    }
}
""",
    )
    sensitive.replace(root / sensitive.name)
    benign.replace(root / benign.name)
    return root


def test_java_audit_archive_set_summarizes_directory_findings(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_audit_archive_set import build_tool

    root = _fixture_dir(tmp_path)
    ctx = _ctx(next(root.glob("*.jar")))
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(paths=[str(root)]))

    assert result.archive_count == 2
    assert result.scanned_archive_count == 2
    assert result.finding_count >= 2
    assert result.summary_by_category["process"] >= 1
    assert result.summary_by_category["filesystem"] >= 1
    sensitive = next(
        item for item in result.archives if item.path.endswith("AuditSensitive.jar")
    )
    benign = next(
        item for item in result.archives if item.path.endswith("AuditBenign.jar")
    )
    assert sensitive.finding_count >= 2
    assert benign.finding_count == 0
    assert any(
        n.kind == NodeKind.note and "java-audit" in n.tags for n in ctx.kb.nodes()
    )


def test_java_audit_archive_set_respects_archive_limit(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_audit_archive_set import build_tool

    root = _fixture_dir(tmp_path)
    ctx = _ctx(next(root.glob("*.jar")))
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(paths=[str(root)], max_archives=1),
    )

    assert result.archive_count == 2
    assert result.scanned_archive_count == 1
    assert result.truncated


def test_memory_agent_registers_java_audit_archive_set() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_audit_archive_set" in agent._function_toolset.tools
