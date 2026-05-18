from __future__ import annotations

import sqlite3
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_project_sink_call_packets import build_tool


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
        conn.execute(
            """
            CREATE TABLE xrefs (
                xref_id INTEGER PRIMARY KEY,
                binary_id INTEGER,
                kind TEXT,
                src_va INTEGER,
                src_function_va INTEGER,
                dst_va INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE function_names (
                binary_id INTEGER,
                entry_va INTEGER,
                canonical TEXT,
                demangled TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            (0x1000, "DriverDispatch"),
        )
        conn.execute(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            (0x5000, "RtlCopyMemory"),
        )
        conn.execute(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            (0x4000, "ProbeForWrite"),
        )
        conn.execute(
            "INSERT INTO xrefs VALUES (1, 1, 'call', ?, ?, ?)",
            (0x1200, 0x1000, 0x5000),
        )
        conn.execute(
            "INSERT INTO xrefs VALUES (2, 1, 'call', ?, ?, ?)",
            (0x1100, 0x1000, 0x4000),
        )
        conn.execute(
            """
            CREATE TABLE basic_blocks (
                binary_id INTEGER,
                function_va INTEGER,
                block_id TEXT,
                start_va INTEGER,
                end_va INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE cfg_edges (
                binary_id INTEGER,
                function_va INTEGER,
                src_block_id TEXT,
                dst_block_id TEXT
            )
            """
        )
        conn.executemany(
            "INSERT INTO basic_blocks VALUES (1, ?, ?, ?, ?)",
            [
                (0x1000, "entry", 0x1000, 0x1100),
                (0x1000, "gate", 0x1100, 0x1180),
                (0x1000, "sink", 0x1180, 0x1280),
            ],
        )
        conn.executemany(
            "INSERT INTO cfg_edges VALUES (1, ?, ?, ?)",
            [
                (0x1000, "entry", "gate"),
                (0x1000, "gate", "sink"),
            ],
        )
        conn.execute(
            """
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
            )
            """
        )
        conn.execute(
            "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                0x1000,
                "entry",
                0x1080,
                "jne",
                '["0x1100"]',
                0x107c,
                "test",
                '["rdi", "rdi"]',
                "not_equal",
                "gate",
                "reject",
                0,
            ),
        )
        conn.execute(
            "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                0x1000,
                "dead",
                0x1400,
                "je",
                '["0x1410"]',
                0x13fc,
                "cmp",
                '["eax", "0"]',
                "equal",
                "dead_sink",
                "dead_fallthrough",
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


def _write_sources(tmp_path: Path) -> Path:
    sources = tmp_path / "pe-sources.yaml"
    sources.write_text(
        """
- id: driver_dispatch_user_buffer
  surface: ioctl
  symbols: [DriverDispatch]
  attacker_class: windows-local-user
  roles:
    - index: 0
      role: buffer
""",
        encoding="utf-8",
    )
    return sources


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
    function_name_count: 2
    xref_count: 1
    call_xref_count: 1
    data_read_xref_count: 0
    data_write_xref_count: 0
    data_label_count: 0
    function_prototype_count: 0
    basic_block_count: 3
    cfg_edge_count: 2
    cfg_dominance_count: 3
    cfg_branch_fact_count: 2
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
  glaurung_status: Local argument snapshots cover simple calls.
  current_capabilities: [rcx_rdx_r8_r9_argument_snapshots]
  missing_capabilities: [path_sensitive_argument_values]
  next_actions: [add helper summaries]
  evidence: [unit-test]
""",
        encoding="utf-8",
    )
    return ghidra_delta


def test_windows_project_sink_call_packets_emits_manifest_backed_seed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1008, "mov", ["r8", "0x40"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            binary_path=str(binary),
            binary="driver.sys",
            build="unit-test",
            attacker_class="local_unprivileged",
            source_role="buffer",
            source_arg="rsi",
            refine_gates=True,
            attach_gate_predicates=True,
            gates_path=str(_write_gates(tmp_path)),
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
    assert result.scanned_callsite_count == 2
    assert result.argument_snapshot_count == 1
    assert result.gate_refinement_count == 1
    assert result.cfg_path_count == 1
    assert result.gate_predicate_count == 1
    assert result.gate_missing_required_count == 1
    assert result.source_value_match_count == 1
    assert result.source_gate_refined_packet_count == 1
    assert result.source_refinement_status_counts == {"matched": 1}
    packet = result.packets[0]
    assert packet.binary == "driver.sys"
    assert packet.entrypoint == "DriverDispatch"
    assert packet.sink_symbol == "RtlCopyMemory"
    assert packet.sink_kind == "copy"
    assert packet.gate_status == "unknown"
    assert packet.required_gates == ["destination_range_valid", "byte_count_bounded"]
    assert packet.proven_gates == ["destination_range_valid"]
    assert packet.gate_proof_sources == {
        "destination_range_valid": "user_pointer_write_range_valid"
    }
    assert packet.missing_required_gates == ["byte_count_bounded"]
    assert packet.source_arg == "rsi"
    assert packet.source_refinement_status == "matched"
    assert "source_arg=rsi" in packet.source_refinement_sources
    assert packet.source_refinement_blockers == []
    assert packet.required_project_facts == [
        "function_names",
        "call_xrefs",
        "cfg",
        "cfg_dominance",
        "branch_conditions",
    ]
    assert packet.project_facts is not None
    assert packet.project_facts.counts["call_xref_count"] == 1
    assert packet.ghidra_delta is not None
    assert packet.ghidra_delta.current_capabilities == [
        "rcx_rdx_r8_r9_argument_snapshots"
    ]
    assert packet.promotion_preconditions_met is False
    assert any(
        "required gate coverage unresolved" in item
        for item in packet.promotion_blockers
    )
    assert any(
        evidence.source == "windows_project_callsite_facts"
        for evidence in packet.evidence
    )
    assert any(evidence.source == "windows_cfg_dominance" for evidence in packet.evidence)
    cfg_path_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_cfg_path_query"
    ]
    assert len(cfg_path_evidence) == 1
    assert "status=covered" in cfg_path_evidence[0].summary
    assert "entry_path=entry->gate->sink" in cfg_path_evidence[0].summary
    assert "gate_path=gate->sink" in cfg_path_evidence[0].summary
    requirement_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_gate_requirement_coverage"
    ]
    assert len(requirement_evidence) == 1
    assert "matched required gates [destination_range_valid]" in (
        requirement_evidence[0].summary
    )
    assert "missing required gates [byte_count_bounded]" in (
        requirement_evidence[0].summary
    )
    predicate_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_branch_condition_facts"
    ]
    assert len(predicate_evidence) == 1
    assert "entry@0x1080 jne: rdi != 0" in predicate_evidence[0].summary
    value_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_sink_argument_match"
    ]
    assert len(value_evidence) == 1
    assert "source buffer rsi matches sink arg1" in value_evidence[0].summary
    assert "source_buffer" in value_evidence[0].summary
    source_gate_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_source_gate_refined_scan"
    ]
    assert len(source_gate_evidence) == 1
    refinement_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_source_refinement_status"
    ]
    assert len(refinement_evidence) == 1
    assert "source refinement matched" in refinement_evidence[0].summary
    snapshot_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_call_argument_snapshot"
    ]
    assert len(snapshot_evidence) == 1
    assert "arg0=rdi" in snapshot_evidence[0].summary
    assert "arg2=0x40" in snapshot_evidence[0].summary
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_sink_call_packets"
        for node in ctx.kb.nodes()
    )


def test_windows_project_sink_call_packets_infers_source_roles(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rdx", "rcx"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            binary_path=str(binary),
            binary="driver.sys",
            build="unit-test",
            infer_source_roles=True,
            sources_path=str(_write_sources(tmp_path)),
            sinks_path=str(_write_sinks(tmp_path)),
            project_facts_path=str(_write_project_facts(tmp_path)),
            ghidra_delta_path=str(_write_ghidra_delta(tmp_path)),
            manifest_target_id="driver",
            manifest_build_label="unit-test",
            manifest_component="driver.sys",
        ),
    )

    assert result.packet_count == 1
    assert result.source_role_inference_count == 1
    assert result.source_value_match_count == 1
    assert result.source_gate_refined_packet_count == 0
    assert result.source_refinement_status_counts == {"matched": 1}
    packet = result.packets[0]
    assert packet.source_role == "buffer"
    assert packet.source_arg == "caller_arg0"
    assert packet.source_refinement_status == "matched"
    assert "source_arg=caller_arg0" in packet.source_refinement_sources
    value_evidence = [
        evidence
        for evidence in packet.evidence
        if evidence.source == "windows_project_sink_argument_match"
    ]
    assert len(value_evidence) == 1
    assert "source buffer caller_arg0 matches sink arg1" in value_evidence[0].summary
    assert "source_provenance=asb_pe_source_metadata" in value_evidence[0].summary


def test_windows_project_sink_call_packets_marks_missing_source_refinement(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            binary="driver.sys",
            build="unit-test",
            source_role="buffer",
            source_arg="rsi",
            sinks_path=str(_write_sinks(tmp_path)),
            project_facts_path=str(_write_project_facts(tmp_path)),
            ghidra_delta_path=str(_write_ghidra_delta(tmp_path)),
            manifest_target_id="driver",
            manifest_build_label="unit-test",
            manifest_component="driver.sys",
        ),
    )

    assert result.packet_count == 1
    assert result.argument_snapshot_count == 0
    assert result.source_value_match_count == 0
    assert result.source_gate_refined_packet_count == 0
    assert result.source_refinement_status_counts == {"missing": 1}
    packet = result.packets[0]
    assert packet.source_refinement_status == "missing"
    assert "no local sink argument snapshot available" in (
        packet.source_refinement_blockers
    )
    assert any(
        "source refinement missing" in blocker
        for blocker in packet.promotion_blockers
    )


def test_windows_project_sink_call_packets_filters_source_gate_refined_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(g.disasm, "disassemble_window_at", fake_disassemble_window_at)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            project_path=str(_write_project(tmp_path)),
            binary_path=str(binary),
            binary="driver.sys",
            build="unit-test",
            source_role="buffer",
            source_arg="rsi",
            refine_gates=True,
            gates_path=str(_write_gates(tmp_path)),
            sinks_path=str(_write_sinks(tmp_path)),
            project_facts_path=str(_write_project_facts(tmp_path)),
            ghidra_delta_path=str(_write_ghidra_delta(tmp_path)),
            manifest_target_id="driver",
            manifest_build_label="unit-test",
            manifest_component="driver.sys",
            source_gate_refined_only=True,
        ),
    )

    assert result.packet_count == 1
    assert result.source_gate_refined_packet_count == 1
    assert any(
        evidence.source == "windows_project_source_gate_refined_scan"
        for evidence in result.packets[0].evidence
    )


def test_memory_agent_registers_windows_project_sink_call_packets() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_project_sink_call_packets" in agent._function_toolset.tools
