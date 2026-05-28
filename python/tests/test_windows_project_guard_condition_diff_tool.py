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
from glaurung.llm.tools.windows_project_guard_condition_diff import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "driver.sys"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path, name: str, *, variant: str) -> Path:
    project = tmp_path / f"{name}.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
CREATE TABLE binaries (
    binary_id INTEGER PRIMARY KEY,
    first_path TEXT
);
CREATE TABLE function_names (
    binary_id INTEGER,
    entry_va INTEGER,
    canonical TEXT,
    aliases_json TEXT DEFAULT '[]',
    set_by TEXT,
    set_at INTEGER,
    demangled TEXT,
    flavor TEXT,
    PRIMARY KEY (binary_id, entry_va)
);
CREATE TABLE cfg_branch_facts (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    branch_va INTEGER NOT NULL,
    branch_mnemonic TEXT NOT NULL,
    branch_operands_json TEXT NOT NULL DEFAULT '[]',
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT NOT NULL DEFAULT '[]',
    condition_kind TEXT NOT NULL,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id, branch_va)
);
CREATE TABLE callsite_path_conditions (
    binary_id INTEGER NOT NULL,
    callsite_va INTEGER NOT NULL,
    caller_va INTEGER,
    block_id TEXT NOT NULL,
    branch_va INTEGER NOT NULL,
    branch_mnemonic TEXT NOT NULL,
    branch_operands_json TEXT NOT NULL DEFAULT '[]',
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT NOT NULL DEFAULT '[]',
    condition_kind TEXT NOT NULL,
    condition_role TEXT NOT NULL,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    distance_bytes INTEGER,
    confidence REAL NOT NULL,
    provenance_json TEXT NOT NULL DEFAULT '[]',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, callsite_va, branch_va)
);
"""
        )
        conn.execute("INSERT INTO binaries VALUES (?, ?)", (1, f"{name}.sys"))
        conn.executemany(
            "INSERT INTO function_names VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 0x140001000, "driver!Dispatch", "[]", "pdb", 0, None, None),
                (1, 0x140002000, "driver!Helper", "[]", "pdb", 0, None, None),
            ],
        )
        if variant == "before":
            branches = [
                _branch(
                    "bb0",
                    0x140001010,
                    "jb",
                    "0x140001080",
                    0x14000100C,
                    "cmp",
                    ["Length", "OutputBufferLength"],
                    "unsigned_less",
                    "bb_ok",
                    "bb_fail",
                ),
                _branch(
                    "bb1",
                    0x140001020,
                    "je",
                    "0x140001090",
                    0x14000101A,
                    "cmp",
                    ["RequestorMode", "KernelMode"],
                    "equal",
                    "bb_kernel",
                    "bb_user",
                ),
            ]
            paths = [
                _path(
                    0x140001060,
                    "bb0",
                    0x140001010,
                    "jb",
                    "0x140001080",
                    0x14000100C,
                    "cmp",
                    ["Length", "OutputBufferLength"],
                    "unsigned_less",
                    "length_bound",
                    "bb_ok",
                    "bb_fail",
                    80,
                )
            ]
        else:
            branches = [
                _branch(
                    "bb0",
                    0x140001012,
                    "jbe",
                    "0x140001080",
                    0x14000100C,
                    "cmp",
                    ["Length", "OutputBufferLength"],
                    "unsigned_less_equal",
                    "bb_ok",
                    "bb_fail",
                ),
                _branch(
                    "bb1",
                    0x140001030,
                    "je",
                    "0x140001090",
                    0x14000102A,
                    "cmp",
                    ["RequestorMode", "KernelMode"],
                    "equal",
                    "bb_kernel",
                    "bb_user",
                ),
                _branch(
                    "bb2",
                    0x140001040,
                    "jne",
                    "0x1400010A0",
                    0x14000103A,
                    "cmp",
                    ["Status", "STATUS_SUCCESS"],
                    "not_equal",
                    "bb_fail",
                    "bb_success",
                ),
            ]
            paths = [
                _path(
                    0x140001068,
                    "bb0",
                    0x140001012,
                    "jbe",
                    "0x140001080",
                    0x14000100C,
                    "cmp",
                    ["Length", "OutputBufferLength"],
                    "unsigned_less_equal",
                    "length_bound",
                    "bb_ok",
                    "bb_fail",
                    86,
                )
            ]
        conn.executemany(
            "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            branches,
        )
        conn.executemany(
            "INSERT INTO callsite_path_conditions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            paths,
        )
        conn.commit()
    finally:
        conn.close()
    return project


def _branch(
    block_id: str,
    branch_va: int,
    branch_mnemonic: str,
    branch_target: str,
    compare_va: int,
    compare_mnemonic: str,
    compare_operands: list[str],
    condition_kind: str,
    target_block: str,
    fallthrough_block: str,
) -> tuple[object, ...]:
    return (
        1,
        0x140001000,
        block_id,
        branch_va,
        branch_mnemonic,
        json.dumps([branch_target]),
        compare_va,
        compare_mnemonic,
        json.dumps(compare_operands),
        condition_kind,
        target_block,
        fallthrough_block,
        0,
    )


def _path(
    callsite_va: int,
    block_id: str,
    branch_va: int,
    branch_mnemonic: str,
    branch_target: str,
    compare_va: int,
    compare_mnemonic: str,
    compare_operands: list[str],
    condition_kind: str,
    condition_role: str,
    target_block: str,
    fallthrough_block: str,
    distance: int,
) -> tuple[object, ...]:
    return (
        1,
        callsite_va,
        0x140001000,
        block_id,
        branch_va,
        branch_mnemonic,
        json.dumps([branch_target]),
        compare_va,
        compare_mnemonic,
        json.dumps(compare_operands),
        condition_kind,
        condition_role,
        target_block,
        fallthrough_block,
        distance,
        0.82,
        json.dumps(["cfg_branch_facts", "callsite_argument_facts"]),
        0,
    )


def test_windows_project_guard_condition_diff_reports_guard_deltas(
    tmp_path: Path,
) -> None:
    before = _project(tmp_path, "before", variant="before")
    after = _project(tmp_path, "after", variant="after")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            before_project_path=str(before),
            after_project_path=str(after),
            add_to_kb=True,
        ),
    )

    assert result.before_guard_count == 3
    assert result.after_guard_count == 4
    assert result.changed_count == 1
    assert result.added_count == 3
    assert result.removed_count == 2
    assert "guard_condition_deltas" in result.coverage
    assert "removed_guard_deltas" in result.coverage

    mode = next(delta for delta in result.deltas if delta.condition_kind == "equal")
    assert mode.status == "changed"
    assert "branches" in mode.changed_fields
    assert "mode_or_user_guard_delta" in mode.security_relevance
    assert "guard_location_delta" in mode.security_relevance

    bounds = [
        delta for delta in result.deltas if "bounds_guard_delta" in delta.reason_codes
    ]
    assert {delta.status for delta in bounds} == {"added", "removed"}

    status = next(
        delta for delta in result.deltas if delta.condition_kind == "not_equal"
    )
    assert status.status == "added"
    assert "status_guard_delta" in status.security_relevance

    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_guard_condition_diff"
        for node in ctx.kb.nodes()
    )


def test_windows_project_guard_condition_diff_cli_json(
    tmp_path: Path,
    capsys,
) -> None:
    before = _project(tmp_path, "before", variant="before")
    after = _project(tmp_path, "after", variant="after")

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-guard-condition-diff",
            "--before-project-path",
            str(before),
            "--after-project-path",
            str(after),
            "--condition-role-contains",
            "length",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["added_count"] == 1
    assert output["removed_count"] == 1
    assert {delta["record_kind"] for delta in output["deltas"]} == {
        "callsite_path_condition"
    }


def test_memory_agent_registers_windows_project_guard_condition_diff() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_guard_condition_diff" in agent._function_toolset.tools
