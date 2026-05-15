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


def _compile_trace_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "TraceFixture.java").write_text(
        """
import java.nio.file.Files;
import java.nio.file.Path;

public class TraceFixture {
    public void launch(Path path) throws Exception {
        String enabled = System.getProperty("trace.fixture.enabled", "false");
        String tokenName = System.getenv("TRACE_FIXTURE_TOKEN");
        Files.writeString(path.resolve("trace.txt"), enabled + tokenName);
        Runtime.getRuntime().exec(new String[] {"sh", "-c", "echo trace"});
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
            str(out),
            str(src / "TraceFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "trace.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "mappings.txt"
    path.write_text(
        """
com.example.TraceFixture -> TraceFixture:
    void start(java.nio.file.Path) -> launch
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def test_java_trace_to_sink_returns_constants_and_neighbor_xrefs(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_trace_to_sink import build_tool

    jar = _compile_trace_fixture(tmp_path)
    mapping = _mapping_file(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            mapping_path=str(mapping),
            category="process",
            sink_owner="java/lang/Runtime",
            sink_name="exec",
        ),
    )

    assert result.sink_found
    assert result.finding is not None
    assert result.finding.category == "process"
    assert result.finding.mapped_class_name == "com.example.TraceFixture"
    assert result.finding.mapped_method_names == ["start"]
    assert result.sink_line_number is not None
    values = {constant.value for constant in result.constants}
    assert {
        "trace.fixture.enabled",
        "TRACE_FIXTURE_TOKEN",
        "trace.txt",
        "echo trace",
    } <= values
    assert any(
        constant.value_kind == "system_property" for constant in result.constants
    )
    assert any(
        constant.value_kind == "environment_variable" for constant in result.constants
    )
    assert all(constant.line_number is not None for constant in result.constants)
    assert any(
        xref.owner == "java/nio/file/Files" and xref.name == "writeString"
        for xref in result.neighbor_xrefs
    )
    assert any(
        xref.line_number == result.sink_line_number for xref in result.neighbor_xrefs
    )
    assert "precise_dataflow_not_yet_available" in result.stop_reasons
    assert any(
        n.kind == NodeKind.note and "trace-to-sink" in n.tags for n in ctx.kb.nodes()
    )


def test_java_trace_to_sink_returns_not_found_for_non_matching_sink(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_trace_to_sink import build_tool

    jar = _compile_trace_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            path=str(jar),
            category="network",
            sink_owner="java/net/Socket",
        ),
    )

    assert not result.sink_found
    assert result.finding is None
    assert result.constants == []
    assert "no_matching_sensitive_finding" in result.stop_reasons


def test_memory_agent_registers_java_trace_to_sink() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_trace_to_sink" in agent._function_toolset.tools
