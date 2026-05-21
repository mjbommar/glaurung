from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_callgraph_reachability import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "driver.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "driver.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
CREATE TABLE binaries (
    binary_id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL,
    first_path TEXT,
    format TEXT,
    arch TEXT,
    bits INTEGER,
    size_bytes INTEGER,
    discovered_at INTEGER
);
CREATE TABLE function_names (
    binary_id INTEGER NOT NULL,
    entry_va INTEGER NOT NULL,
    canonical TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL,
    src_va INTEGER NOT NULL,
    dst_va INTEGER NOT NULL,
    kind TEXT NOT NULL,
    src_function_va INTEGER,
    indexed_at INTEGER
);
"""
        )
        conn.execute(
            "INSERT INTO binaries VALUES (1, 'sha256', 'driver.sys', 'PE', 'x86_64', 64, 16, 0)"
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, ?, ?)",
            [
                (1, 0x1000, "driver!Entry", "pdb", None, None),
                (1, 0x1100, "driver!Dispatch", "pdb", None, None),
                (1, 0x1200, "driver!Validate", "pdb", None, None),
                (1, 0x1300, "driver!CopyHelper", "pdb", None, None),
                (1, 0x1400, "RtlCopyMemory", "import", None, None),
                (1, 0x1500, "driver!AdminEntry", "pdb", None, None),
                (1, 0x1600, "driver!Unrelated", "pdb", None, None),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, ?, ?, ?, ?, 0)",
            [
                (1, 0x1010, 0x1100, "call", 0x1000),
                (2, 0x1110, 0x1200, "call", 0x1100),
                (3, 0x1210, 0x1300, "call", 0x1200),
                (4, 0x1310, 0x1400, "call", 0x1300),
                (5, 0x1510, 0x1300, "call", 0x1500),
                (6, 0x1610, 0x1700, "call", 0x1600),
                (7, 0x1320, 0x1800, "jump", 0x1300),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


def test_windows_project_callgraph_reachability_finds_source_to_sink_path(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_project(tmp_path)),
            source_function_name="Entry",
            target_function_name="RtlCopyMemory",
            add_to_kb=True,
        ),
    )

    assert result.mode == "source_to_target"
    assert result.reachable is True
    assert result.path_count == 1
    assert result.paths[0].depth == 4
    assert [item.name for item in result.paths[0].function_sequence] == [
        "driver!Entry",
        "driver!Dispatch",
        "driver!Validate",
        "driver!CopyHelper",
        "RtlCopyMemory",
    ]
    assert result.paths[0].edges[-1].callsite_va == 0x1310
    assert "callgraph_paths" in result.coverage
    assert "interprocedural_value_flow" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_callgraph_reachability"
        for node in ctx.kb.nodes()
    )


def test_windows_project_callgraph_reachability_samples_upstream_paths(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_project(tmp_path)),
            target_function_name="RtlCopyMemory",
            max_paths=4,
        ),
    )

    assert result.mode == "upstream_to_target"
    assert result.reachable is True
    assert {
        tuple(item.name for item in path.function_sequence) for path in result.paths
    } == {
        (
            "driver!Entry",
            "driver!Dispatch",
            "driver!Validate",
            "driver!CopyHelper",
            "RtlCopyMemory",
        ),
        ("driver!AdminEntry", "driver!CopyHelper", "RtlCopyMemory"),
    }
    assert result.stop_reasons[0] == "upstream_paths_found"


def test_windows_project_callgraph_reachability_reports_unreachable(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_project(tmp_path)),
            source_function_name="Unrelated",
            target_function_name="RtlCopyMemory",
        ),
    )

    assert result.reachable is False
    assert result.path_count == 0
    assert result.stop_reasons == ["target_not_reached"]
    assert "callgraph_path" in result.missing_capabilities


def test_windows_project_callgraph_reachability_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    rc = GlaurungCLI().run(
        [
            "windows",
            "project-callgraph-reachability",
            "--project-path",
            str(_project(tmp_path)),
            "--source-function-name",
            "Entry",
            "--target-function-name",
            "RtlCopyMemory",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["reachable"] is True
    assert output["paths"][0]["depth"] == 4
    assert output["paths"][0]["target"]["name"] == "RtlCopyMemory"


def test_memory_agent_registers_windows_project_callgraph_reachability() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_callgraph_reachability" in agent._function_toolset.tools
