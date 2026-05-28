from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_onehop_flow_packets import build_tool


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
    demangled TEXT,
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
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x2000, "CopyHelper"),
                (0x4000, "ProbeForWrite"),
                (0x5000, "RtlCopyMemory"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, ?, ?, ?, ?, 0)",
            [
                (1, 0x1100, 0x2000, "call", 0x1000),
                (2, 0x2100, 0x5000, "call", 0x2000),
                (3, 0x2050, 0x4000, "call", 0x2000),
            ],
        )
        conn.executescript(
            """
CREATE TABLE basic_blocks (
    binary_id INTEGER,
    function_va INTEGER,
    block_id TEXT,
    start_va INTEGER,
    end_va INTEGER
);
CREATE TABLE cfg_edges (
    binary_id INTEGER,
    function_va INTEGER,
    src_block_id TEXT,
    dst_block_id TEXT
);
CREATE TABLE cfg_branch_facts (
    binary_id INTEGER,
    function_va INTEGER,
    block_id TEXT,
    branch_va INTEGER,
    branch_mnemonic TEXT,
    branch_operands_json TEXT,
    compare_va INTEGER,
    compare_mnemonic TEXT,
    compare_operands_json TEXT,
    condition_kind TEXT,
    target_block_id TEXT,
    fallthrough_block_id TEXT,
    indexed_at INTEGER
);
"""
        )
        conn.executemany(
            "INSERT INTO basic_blocks VALUES (1, ?, ?, ?, ?)",
            [
                (0x2000, "entry", 0x2000, 0x2050),
                (0x2000, "gate", 0x2050, 0x2080),
                (0x2000, "sink", 0x2080, 0x2180),
            ],
        )
        conn.executemany(
            "INSERT INTO cfg_edges VALUES (1, ?, ?, ?)",
            [
                (0x2000, "entry", "gate"),
                (0x2000, "gate", "sink"),
            ],
        )
        conn.execute(
            "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                0x2000,
                "entry",
                0x2040,
                "jne",
                '["0x2050"]',
                0x203c,
                "test",
                '["rdx", "rdx"]',
                "not_equal",
                "gate",
                "reject",
                0,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return project


def _write_sinks(tmp_path: Path) -> Path:
    sinks = tmp_path / "pe-sinks.yaml"
    sinks.write_text(
        """
- id: rtl_copy_memory
  symbols: [RtlCopyMemory, memcpy]
  sink_kind: copy
  effects: [writes_destination_range, reads_source_range]
  arg_roles:
    0: destination_buffer
    1: source_buffer
    2: byte_count
  required_gates: [destination_range_valid, byte_count_bounded]
""",
        encoding="utf-8",
    )
    return sinks


def _write_gates(tmp_path: Path) -> Path:
    gates = tmp_path / "pe-gates.yaml"
    gates.write_text(
        """
- id: probeforwrite
  symbols: [ProbeForWrite]
  gate_kind: user_pointer
  proves: [user_pointer_write_range_valid]
  required_conditions: [call_dominates_write_sink]
  invalid_when: [length_is_zero]
""",
        encoding="utf-8",
    )
    return gates


def _write_project_facts(tmp_path: Path) -> Path:
    project_facts = tmp_path / "pe-project-facts.yaml"
    project_facts.write_text(
        """
- id: driver_project
  target_id: driver
  build_label: unit-test
  build_number: "1"
  architecture: x64
  binary_filename: driver.sys
  project_path: /projects/driver.glaurung
  fact_sources: [unit_test]
  fact_coverage: [function_names, call_xrefs, cfg, cfg_dominance, branch_conditions]
  missing_facts: []
  counts:
    function_name_count: 4
    xref_count: 3
    call_xref_count: 3
    data_read_xref_count: 0
    data_write_xref_count: 0
    data_label_count: 0
    function_prototype_count: 0
    basic_block_count: 3
    cfg_edge_count: 2
    cfg_dominance_count: 3
    cfg_branch_fact_count: 1
""",
        encoding="utf-8",
    )
    return project_facts


def _write_ghidra_delta(tmp_path: Path) -> Path:
    ghidra_delta = tmp_path / "pe-ghidra-delta.yaml"
    ghidra_delta.write_text(
        """
- id: driver_call_argument_flow
  target_id: driver
  component: driver.sys
  build_label: unit-test
  fact_class: call_argument_flow
  coverage_state: partial
  blocking: false
  ghidra_baseline: Ghidra shows call arguments.
  glaurung_status: One-hop snapshot flow covers explicit caller_argN.
  current_capabilities: [project_onehop_argument_flow_snapshot_match]
  missing_capabilities: [helper_side_effect_summaries]
  next_actions: [add helper summaries]
  evidence: [unit-test]
""",
        encoding="utf-8",
    )
    return ghidra_delta


def test_windows_project_onehop_flow_packets_emit_review_packet(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(_path, start_va, **_kwargs):
        if start_va == 0x1000:
            return [
                _Insn(0x1000, "mov", ["rcx", "rdi"]),
                _Insn(0x1004, "mov", ["rdx", "rsi"]),
                _Insn(0x1100, "call", ["0x2000"]),
            ]
        if start_va == 0x2000:
            return [
                _Insn(0x2000, "mov", ["rcx", "r8"]),
                _Insn(0x2004, "mov", ["rdx", "rdx"]),
                _Insn(0x2008, "mov", ["r8", "0x40"]),
                _Insn(0x2100, "call", ["0x5000"]),
            ]
        return []

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            binary="driver.sys",
            build="unit-test",
            attacker_class="local_unprivileged",
            source_role="buffer",
            source_arg="rsi",
            sink_arg_index=1,
            sinks_path=str(_write_sinks(tmp_path)),
            project_facts_path=str(_write_project_facts(tmp_path)),
            ghidra_delta_path=str(_write_ghidra_delta(tmp_path)),
            manifest_target_id="driver",
            manifest_build_label="unit-test",
            manifest_component="driver.sys",
            add_to_kb=True,
        ),
    )

    assert result.packet_count == 1
    assert result.scanned_chain_count == 1
    assert result.onehop_argument_flow_count == 1
    assert result.helper_cfg_path_count == 0
    packet = result.packets[0]
    assert packet.binary == "driver.sys"
    assert packet.entrypoint == "DriverDispatch"
    assert packet.source_role == "buffer"
    assert packet.source_arg == "rsi"
    assert packet.source_refinement_status == "matched"
    assert "helper_sink_arg1:source_buffer" in packet.source_refinement_sources
    assert packet.sink_symbol == "RtlCopyMemory"
    assert packet.sink_kind == "copy"
    assert packet.required_gates == ["destination_range_valid", "byte_count_bounded"]
    assert packet.missing_required_gates == [
        "destination_range_valid",
        "byte_count_bounded",
    ]
    assert packet.gate_status == "unknown"
    assert packet.project_facts is not None
    assert packet.project_facts.counts["call_xref_count"] == 3
    assert packet.ghidra_delta is not None
    assert packet.ghidra_delta.current_capabilities == [
        "project_onehop_argument_flow_snapshot_match"
    ]
    assert any(
        evidence.source == "windows_project_onehop_argument_flow"
        and "caller arg1 rsi reaches RtlCopyMemory arg1" in evidence.summary
        for evidence in packet.evidence
    )
    assert any(
        evidence.source == "windows_project_onehop_sink_gate_metadata"
        and "required gates [destination_range_valid, byte_count_bounded]"
        in evidence.summary
        for evidence in packet.evidence
    )
    assert any(
        "required gate coverage unresolved" in item
        for item in packet.promotion_blockers
    )
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_onehop_flow_packets"
        for node in ctx.kb.nodes()
    )


def test_windows_project_onehop_flow_packets_refines_helper_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)

    def fake_disassemble_window_at(_path, start_va, **_kwargs):
        if start_va == 0x1000:
            return [
                _Insn(0x1000, "mov", ["rcx", "rdi"]),
                _Insn(0x1004, "mov", ["rdx", "rsi"]),
                _Insn(0x1100, "call", ["0x2000"]),
            ]
        if start_va == 0x2000:
            return [
                _Insn(0x2000, "mov", ["rcx", "r8"]),
                _Insn(0x2004, "mov", ["rdx", "rdx"]),
                _Insn(0x2008, "mov", ["r8", "0x40"]),
                _Insn(0x2050, "call", ["0x4000"]),
                _Insn(0x2080, "mov", ["rdx", "rdx"]),
                _Insn(0x2100, "call", ["0x5000"]),
            ]
        return []

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            binary="driver.sys",
            build="unit-test",
            attacker_class="local_unprivileged",
            source_role="buffer",
            source_arg="rsi",
            sink_arg_index=1,
            sinks_path=str(_write_sinks(tmp_path)),
            gates_path=str(_write_gates(tmp_path)),
            refine_helper_gates=True,
            attach_helper_gate_paths=True,
            attach_helper_gate_predicates=True,
            project_facts_path=str(_write_project_facts(tmp_path)),
            ghidra_delta_path=str(_write_ghidra_delta(tmp_path)),
            manifest_target_id="driver",
            manifest_build_label="unit-test",
            manifest_component="driver.sys",
        ),
    )

    assert result.packet_count == 1
    assert result.helper_gate_refinement_count == 1
    assert result.helper_cfg_path_count == 1
    assert result.helper_gate_predicate_count == 1
    packet = result.packets[0]
    assert packet.proven_gates == ["destination_range_valid"]
    assert packet.gate_proof_sources == {
        "destination_range_valid": "user_pointer_write_range_valid"
    }
    assert packet.missing_required_gates == ["byte_count_bounded"]
    assert packet.gate_status == "unknown"
    assert packet.required_project_facts == [
        "function_names",
        "call_xrefs",
        "cfg",
        "cfg_dominance",
        "cfg_paths",
        "branch_conditions",
    ]
    assert any(
        step.symbol == "ProbeForWrite" and step.role == "gate"
        for step in packet.path
    )
    assert any(
        evidence.source == "windows_project_onehop_helper_gate_dominance"
        and "ProbeForWrite@0x2050" in evidence.summary
        for evidence in packet.evidence
    )
    assert any(
        evidence.source == "windows_project_onehop_helper_gate_requirement_coverage"
        and "matched required gates [destination_range_valid]" in evidence.summary
        for evidence in packet.evidence
    )
    assert any(
        evidence.source == "windows_project_onehop_helper_cfg_path"
        and "entry_path=entry->gate->sink" in evidence.summary
        and "gate_path=gate->sink" in evidence.summary
        for evidence in packet.evidence
    )
    assert any(
        evidence.source == "windows_project_onehop_helper_branch_condition_facts"
        and "entry@0x2040 jne: rdx != 0" in evidence.summary
        for evidence in packet.evidence
    )


def test_windows_project_onehop_flow_packets_filters_helper_gate_refined_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = _write_project(tmp_path)
    incompatible_gates = tmp_path / "incompatible-gates.yaml"
    incompatible_gates.write_text(
        """
- id: se_access_check
  symbols: [SeAccessCheck]
  gate_kind: access_check
  proves: [access_checked]
  required_conditions: [call_dominates_privileged_operation]
  invalid_when: []
""",
        encoding="utf-8",
    )

    def fake_disassemble_window_at(_path, start_va, **_kwargs):
        if start_va == 0x1000:
            return [
                _Insn(0x1000, "mov", ["rcx", "rdi"]),
                _Insn(0x1004, "mov", ["rdx", "rsi"]),
                _Insn(0x1100, "call", ["0x2000"]),
            ]
        if start_va == 0x2000:
            return [
                _Insn(0x2000, "mov", ["rcx", "r8"]),
                _Insn(0x2004, "mov", ["rdx", "rdx"]),
                _Insn(0x2080, "mov", ["rdx", "rdx"]),
                _Insn(0x2100, "call", ["0x5000"]),
            ]
        return []

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    no_gate = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            binary="driver.sys",
            source_role="buffer",
            source_arg="rsi",
            sink_arg_index=1,
            sinks_path=str(_write_sinks(tmp_path)),
            gates_path=str(incompatible_gates),
            helper_gate_refined_only=True,
        ),
    )
    assert no_gate.onehop_argument_flow_count == 1
    assert no_gate.packet_count == 0

    def fake_disassemble_with_gate(_path, start_va, **_kwargs):
        if start_va == 0x1000:
            return [
                _Insn(0x1000, "mov", ["rcx", "rdi"]),
                _Insn(0x1004, "mov", ["rdx", "rsi"]),
                _Insn(0x1100, "call", ["0x2000"]),
            ]
        if start_va == 0x2000:
            return [
                _Insn(0x2000, "mov", ["rcx", "r8"]),
                _Insn(0x2004, "mov", ["rdx", "rdx"]),
                _Insn(0x2050, "call", ["0x4000"]),
                _Insn(0x2080, "mov", ["rdx", "rdx"]),
                _Insn(0x2100, "call", ["0x5000"]),
            ]
        return []

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_with_gate)
    refined = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary_path=str(binary),
            project_path=str(project),
            binary="driver.sys",
            source_role="buffer",
            source_arg="rsi",
            sink_arg_index=1,
            sinks_path=str(_write_sinks(tmp_path)),
            gates_path=str(_write_gates(tmp_path)),
            helper_gate_refined_only=True,
        ),
    )
    assert refined.packet_count == 1
    assert refined.helper_gate_refinement_count == 1
    assert refined.packets[0].required_project_facts == [
        "function_names",
        "call_xrefs",
        "cfg",
        "cfg_dominance",
    ]


def test_memory_agent_registers_windows_project_onehop_flow_packets() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_onehop_flow_packets" in agent._function_toolset.tools
