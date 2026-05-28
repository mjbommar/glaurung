from __future__ import annotations

from pathlib import Path

import pytest
import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_binary_diff_summary import build_tool


_SWITCHY_V1 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2"
)
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_binary_diff_summary_reports_changed_function(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            status="changed",
            function="dispatch",
        ),
    )

    assert result.changed > 0
    assert result.filtered_row_count == 1
    assert result.rows[0].name == "dispatch"
    assert result.rows[0].status == "changed"
    assert result.rows[0].a is not None
    assert result.rows[0].b is not None
    assert result.rows[0].b.size > result.rows[0].a.size
    assert "patch-triage seed" in result.notes[0]


def test_windows_binary_diff_summary_can_omit_rows_and_add_evidence(
    tmp_path: Path,
) -> None:
    a = _need(_SWITCHY_V1)
    b = _need(_SWITCHY_V2)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_a=str(a),
            binary_b=str(b),
            status="changed",
            max_rows=0,
            add_to_kb=True,
        ),
    )

    assert result.filtered_row_count >= 1
    assert result.rows == []
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_binary_diff_summary"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_binary_diff_summary() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_binary_diff_summary" in agent._function_toolset.tools
