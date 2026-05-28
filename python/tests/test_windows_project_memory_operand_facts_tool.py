from __future__ import annotations

import sqlite3
from pathlib import Path
import json
from typing import Any, cast

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.kb import windows_memory_operands
from glaurung.llm.tools.windows_project_memory_operand_facts import build_tool


class _Addr:
    def __init__(self, value: int) -> None:
        self.value = value


class _Insn:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Addr(va)
        self.mnemonic = mnemonic
        self.operands = operands


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_project(tmp_path: Path) -> Path:
    project = tmp_path / "sample.glaurung"
    conn = sqlite3.connect(project)
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
CREATE TABLE data_labels (
    binary_id INTEGER NOT NULL,
    va INTEGER NOT NULL,
    name TEXT NOT NULL,
    c_type TEXT,
    size INTEGER,
    set_by TEXT,
    set_at INTEGER,
    PRIMARY KEY (binary_id, va)
);
CREATE TABLE type_field_uses (
    binary_id INTEGER NOT NULL,
    type_name TEXT NOT NULL,
    field_name TEXT NOT NULL,
    use_va INTEGER NOT NULL,
    function_va INTEGER,
    PRIMARY KEY (binary_id, use_va, type_name, field_name)
);
CREATE TABLE function_prototypes (
    binary_id INTEGER NOT NULL,
    function_name TEXT NOT NULL,
    return_type TEXT,
    params_json TEXT NOT NULL DEFAULT '[]',
    semantics_json TEXT,
    confidence REAL,
    PRIMARY KEY (binary_id, function_name)
);
"""
    )
    conn.execute(
        "INSERT INTO binaries VALUES (1, 'abc', 'sample.sys', 'PE', 'x86_64', 64, 1, 0)"
    )
    conn.execute(
        "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, ?, ?)",
        (1, 0x1000, "cldflt!MemoryUser", "pdb", None, None),
    )
    conn.execute(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        (1, 1, 0x1008, 0x3000, "data_read", 0x1000),
    )
    conn.execute(
        "INSERT INTO data_labels VALUES (?, ?, ?, ?, ?, ?, 0)",
        (1, 0x3000, "cldflt!g_Table", "ULONG[]", 32, "unit_test"),
    )
    conn.execute(
        "INSERT INTO type_field_uses VALUES (?, ?, ?, ?, ?)",
        (1, "USER_REQUEST", "OutputBuffer", 0x1000, 0x1000),
    )
    conn.execute(
        "INSERT INTO function_prototypes VALUES (?, ?, ?, ?, ?, ?)",
        (
            1,
            "MemoryUser",
            "NTSTATUS",
            json.dumps(
                [
                    {
                        "name": "InputUserBuffer",
                        "c_type": "void *",
                        "role": "user_pointer",
                    },
                    {
                        "name": "PoolBuffer",
                        "c_type": "PVOID",
                        "role": "pool_allocation",
                    },
                ]
            ),
            "{}",
            0.87,
        ),
    )
    conn.commit()
    conn.close()
    return project


def test_windows_project_memory_operand_facts_extracts_widths_and_roles(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rax", "qword ptr [rcx + 0x20]"]),
            _Insn(0x1004, "mov", ["dword ptr [rbp - 0x10]", "eax"]),
            _Insn(0x1008, "cmp", ["byte ptr [rip + 0x1234]", "0"]),
            _Insn(0x100C, "add", ["qword ptr [rsp + 0x20]", "1"]),
            _Insn(0x1010, "mov", ["rax", "qword ptr [rdx + 0x8]"]),
        ]

    g_mod = cast(Any, g)
    monkeypatch.setattr(
        g_mod.disasm, "disassemble_window_at", fake_disassemble_window_at
    )
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            function_va=0x1000,
            add_to_kb=True,
            persist_to_project=True,
        ),
    )

    assert result.function_name == "cldflt!MemoryUser"
    assert result.returned_fact_count == 5
    assert result.persisted_fact_count == 5
    by_va = {fact.instruction_va: fact for fact in result.facts}
    assert by_va[0x1000].access_kind == "read"
    assert by_va[0x1000].width_bytes == 8
    assert by_va[0x1000].address_expression == "[rcx + 0x20]"
    assert by_va[0x1000].role_hint == "user_pointer"
    assert by_va[0x1000].base_object == "InputUserBuffer"
    assert by_va[0x1000].base_object_kind == "user_pointer"
    assert by_va[0x1000].base_object_type == "void *"
    assert by_va[0x1000].base_object_role == "user_pointer"
    assert by_va[0x1000].field_offset == 0x20
    assert by_va[0x1000].likely_type_name == "USER_REQUEST"
    assert by_va[0x1000].likely_field_name == "OutputBuffer"
    assert by_va[0x1000].confidence > 0.9
    assert by_va[0x1004].access_kind == "write"
    assert by_va[0x1004].role_hint == "stack_local"
    assert by_va[0x1008].access_kind == "read"
    assert by_va[0x1008].role_hint == "global_data"
    assert by_va[0x1008].data_target_va == 0x3000
    assert by_va[0x1008].data_target_name == "cldflt!g_Table"
    assert by_va[0x100C].access_kind == "read_write"
    assert by_va[0x100C].role_hint == "stack_argument"
    assert by_va[0x1010].base_object == "PoolBuffer"
    assert by_va[0x1010].base_object_kind == "heap_pointer"
    assert by_va[0x1010].role_hint == "heap_pointer"
    assert "native_memory_operand_facts" in result.coverage
    assert "memory_operand_widths" in result.coverage
    assert "memory_read_operands" in result.coverage
    assert "memory_write_operands" in result.coverage
    assert "memory_read_write_operands" in result.coverage
    assert "project_data_label_targets" in result.coverage
    assert "base_object_classification" in result.coverage
    assert "user_pointer_memory_operands" in result.coverage
    assert "heap_pointer_memory_operands" in result.coverage
    assert "type_field_use_joins" in result.coverage
    assert "persisted_project_memory_operand_table" in result.coverage
    assert "type_layout_field_names" not in result.missing_capabilities
    assert "user_pointer_classification" not in result.missing_capabilities
    assert "persisted_project_memory_operand_table" not in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_memory_operand_facts"
        for node in ctx.kb.nodes()
    )
    conn = sqlite3.connect(project)
    try:
        rows = windows_memory_operands.list_memory_operand_facts(
            conn,
            binary_id=1,
            base_object_kind="user_pointer",
        )
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0].likely_field_name == "OutputBuffer"


def test_memory_agent_registers_windows_project_memory_operand_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_memory_operand_facts" in agent._function_toolset.tools
