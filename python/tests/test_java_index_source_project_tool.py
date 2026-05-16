from __future__ import annotations

from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def test_java_index_source_project_records_project_ast_surface(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_index_source_project import build_tool

    root = tmp_path / "project"
    src = root / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    main = src / "Main.java"
    main.write_text(
        """
package app;

import java.io.IOException;
import java.util.List;

@Deprecated
public class Main {
    private final List<String> values = List.of();

    public String value(String input) throws IOException {
        return input + values.size();
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (src / "Broken.java").write_text(
        """
package app;

public class Broken {
    public void missing(
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    ctx = _ctx(main)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(source_project_root=str(root), max_sources=8),
    )

    assert result.source_count == 2
    assert result.parse_success_count == 1
    assert result.parse_error_count == 1
    assert result.packages == ["app"]
    assert "java.io.IOException" in result.imports
    assert "java.util.List" in result.imports
    assert result.syntax_problem_count >= 1
    main_type = next(item for item in result.types if item.name == "Main")
    assert main_type.package_name == "app"
    assert main_type.annotations == ["Deprecated"]
    assert main_type.fields[0].name == "values"
    assert main_type.methods[0].name == "value"
    assert main_type.methods[0].thrown_exceptions == ["IOException"]
    assert result.index_node_id is not None
    assert any(
        node.kind == NodeKind.java_source_project_index
        and node.props.get("tool") == "java_index_source_project"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_java_index_source_project() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_index_source_project" in agent._function_toolset.tools
