from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Literal, cast

import glaurung as g

from glaurung.llm.agents.windows_sink_to_gate_review import (
    WindowsSinkToGateReviewBatchConfig,
    WindowsSinkToGateReviewConfig,
    run_windows_sink_to_gate_review,
    run_windows_sink_to_gate_review_batch,
)
from glaurung.llm.tools.windows_cfg_dominance import CfgBlockFact
from glaurung.llm.tools.windows_compose_source_gate_sink_packet import (
    WindowsComposeSourceGateSinkPacketArgs,
)
from glaurung.llm.tools.windows_build_corpus import WindowsBuildCorpusArgs
from glaurung.llm.tools.windows_project_branch_condition_facts import (
    ProjectBranchConditionFact,
)
from glaurung.llm.tools.windows_project_call_argument_snapshot import (
    WindowsProjectCallArgumentSnapshotResult,
)
from glaurung.llm.tools.windows_project_cfg_path_query import (
    WindowsProjectCfgPathQueryResult,
)


class _Addr:
    def __init__(self, value: int) -> None:
        self.value = value


class _Insn:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Addr(va)
        self.mnemonic = mnemonic
        self.operands = operands


def _write_metadata(tmp_path: Path) -> tuple[Path, Path]:
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
    return gates, sinks


def _cfg(bypass: bool) -> list[CfgBlockFact]:
    entry_successors = ["gate", "bypass"] if bypass else ["gate"]
    sink_predecessors = ["gate", "bypass"] if bypass else ["gate"]
    blocks = [
        CfgBlockFact(
            id="entry",
            start_va=0x1000,
            end_va=0x1020,
            successor_ids=entry_successors,
        ),
        CfgBlockFact(
            id="gate",
            start_va=0x2000,
            end_va=0x2020,
            successor_ids=["sink"],
            predecessor_ids=["entry"],
        ),
        CfgBlockFact(
            id="sink",
            start_va=0x3000,
            end_va=0x3020,
            predecessor_ids=sink_predecessors,
        ),
    ]
    if bypass:
        blocks.append(
            CfgBlockFact(
                id="bypass",
                start_va=0x2500,
                end_va=0x2520,
                successor_ids=["sink"],
                predecessor_ids=["entry"],
            )
        )
    return blocks


def _packet_args(
    gates: Path, sinks: Path, *, bypass: bool
) -> WindowsComposeSourceGateSinkPacketArgs:
    return WindowsComposeSourceGateSinkPacketArgs(
        binary="driver.sys",
        build="unit-test",
        entrypoint="DriverDispatch",
        attacker_class="local_unprivileged",
        source_role="buffer",
        source_name="user_buffer",
        sink_symbol="RtlCopyMemory",
        sink_arg_index=1,
        gate_symbol="ProbeForWrite",
        gate_va=0x2010,
        sink_va=0x3010,
        pseudocode="""
void DriverDispatch(void *dst, void *user_buffer, ULONG len) {
    void *captured = user_buffer;
    ProbeForWrite(dst, len, 1);
    RtlCopyMemory(dst, captured, len);
}
""",
        cfg_blocks=_cfg(bypass=bypass),
        gates_path=str(gates),
        sinks_path=str(sinks),
    )


def _argument_snapshot() -> WindowsProjectCallArgumentSnapshotResult:
    return WindowsProjectCallArgumentSnapshotResult(
        binary_path="/binaries/driver.sys",
        project_path="/projects/driver.glaurung",
        callsite_va=0x3010,
        caller_va=0x1000,
        caller_name="DriverDispatch",
        callee_va=0x5000,
        callee_name="RtlCopyMemory",
        callsite_text="call RtlCopyMemory",
        arguments=[],
        inspected_instruction_count=12,
        coverage=["register_arguments", "data_xrefs"],
        missing_capabilities=[],
    )


def _cfg_query(
    status: Literal["covered", "bypass"] = "covered",
) -> WindowsProjectCfgPathQueryResult:
    return WindowsProjectCfgPathQueryResult(
        project_path="/projects/driver.glaurung",
        function_va=0x1000,
        entry_block_id="entry",
        gate_block_id="gate",
        sink_block_id="sink",
        block_count=3,
        edge_count=2,
        entry_reaches_sink=True,
        gate_reaches_sink=True,
        all_paths_to_sink_pass_gate=status == "covered",
        status=status,
        confidence=0.9 if status == "covered" else 0.4,
        reason="all paths pass gate" if status == "covered" else "bypass reaches sink",
        entry_to_sink_path_block_ids=["entry", "gate", "sink"],
        gate_to_sink_path_block_ids=["gate", "sink"],
        bypass_path_block_ids=[]
        if status == "covered"
        else ["entry", "bypass", "sink"],
        provenance=["windows_project_cfg_path_query"],
    )


def _branch_fact() -> ProjectBranchConditionFact:
    return ProjectBranchConditionFact(
        function_va=0x1000,
        block_id="entry",
        block_start_va=0x1000,
        block_end_va=0x1020,
        branch_va=0x1018,
        branch_mnemonic="jne",
        branch_operands=["0x2500"],
        compare_va=0x1010,
        compare_mnemonic="test",
        compare_operands=["eax", "eax"],
        condition_kind="not_equal",
        inverse_condition_kind="equal",
        target_predicate="eax != 0",
        fallthrough_predicate="eax == 0",
        target_block_id="gate",
        fallthrough_block_id="bypass",
        on_supplied_path=True,
    )


def _write_auto_project(tmp_path: Path) -> tuple[Path, Path]:
    binary = tmp_path / "driver.sys"
    binary.write_bytes(b"MZ")
    project = tmp_path / "driver.glaurung"
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
CREATE TABLE basic_blocks (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    block_id TEXT NOT NULL,
    start_va INTEGER NOT NULL,
    end_va INTEGER NOT NULL,
    instruction_count INTEGER NOT NULL,
    is_entry INTEGER NOT NULL DEFAULT 0,
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, block_id)
);
CREATE TABLE cfg_edges (
    binary_id INTEGER NOT NULL,
    function_va INTEGER NOT NULL,
    src_block_id TEXT NOT NULL,
    dst_block_id TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'cfg',
    indexed_at INTEGER NOT NULL,
    PRIMARY KEY (binary_id, function_va, src_block_id, dst_block_id, kind)
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
"""
    )
    conn.execute(
        "INSERT INTO binaries VALUES (1, 'abc', 'driver.sys', 'PE', 'x86_64', 64, 1, 0)"
    )
    conn.executemany(
        "INSERT INTO function_names VALUES (?, ?, ?, '[]', ?, 0, ?, ?)",
        [
            (1, 0x1000, "driver!DriverDispatch", "pdb", None, None),
            (1, 0x5000, "driver!RtlCopyMemory", "pdb", None, None),
        ],
    )
    conn.execute(
        "INSERT INTO xrefs VALUES (?, ?, ?, ?, ?, ?, 0)",
        (1, 1, 0x3010, 0x5000, "call", 0x1000),
    )
    conn.executemany(
        "INSERT INTO basic_blocks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 0x1000, "entry", 0x1000, 0x1020, 2, 1, 0),
            (1, 0x1000, "gate", 0x2000, 0x2020, 2, 0, 0),
            (1, 0x1000, "sink", 0x3000, 0x3020, 2, 0, 0),
        ],
    )
    conn.executemany(
        "INSERT INTO cfg_edges VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, 0x1000, "entry", "gate", "cfg", 0),
            (1, 0x1000, "gate", "sink", "cfg", 0),
        ],
    )
    conn.execute(
        "INSERT INTO cfg_branch_facts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            1,
            0x1000,
            "entry",
            0x1018,
            "jne",
            '["0x2000"]',
            0x1010,
            "test",
            '["eax", "eax"]',
            "not_equal",
            "gate",
            None,
            0,
        ),
    )
    conn.commit()
    conn.close()
    return binary, project


def _write_project_fact_manifest(tmp_path: Path, project: Path) -> Path:
    manifest = tmp_path / "pe-project-facts.yaml"
    manifest.write_text(
        f"""
- id: driver_project
  target_id: driver
  build_label: unit-test
  build_number: "1"
  architecture: x64
  binary_filename: driver.sys
  project_path: {project}
  project_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  project_size_bytes: 4096
  fact_sources: [unit]
  fact_coverage: [function_names, call_xrefs, cfg, branch_conditions]
  missing_facts: []
  counts:
    function_name_count: 4
    call_xref_count: 2
    basic_block_count: 3
    cfg_edge_count: 2
    cfg_branch_fact_count: 1
""",
        encoding="utf-8",
    )
    return manifest


def _write_build_corpus_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-build-corpus.yaml"
    manifest.write_text(
        """
- id: driver
  filename: driver.sys
  binary_kind: driver
  priority: high
  scan_roles: [ioctl_dispatch]
  surfaces: [ioctl]
  architectures: [x64]
  corpus_globs: ["driver.sys"]
  project_globs: ["driver.glaurung"]
  notes: Synthetic sink-to-gate target.
""",
        encoding="utf-8",
    )
    return manifest


def test_windows_sink_to_gate_review_keeps_bypass_as_blocked_static_candidate(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)

    result = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(
            packet_args=_packet_args(gates, sinks, bypass=True),
        )
    )

    assert result.claim_level == "sink_to_gate_review_not_finding"
    assert result.operand_status == "alias"
    assert result.gate_status == "not_dominated"
    assert result.packet.gate_status == "not_dominated"
    assert result.packet.claim_level == "candidate_not_finding"
    assert result.promotion_preconditions_met is False
    assert "byte_count_bounded" in result.packet.missing_required_gates
    assert result.evidence_bundle.subject.candidate_id == result.packet.candidate_id
    assert "windows_cfg_gate_to_sink" in result.evidence_bundle.source_tools
    assert result.evidence_bundle.blockers == result.packet.promotion_blockers


def test_windows_sink_to_gate_review_records_dominated_gate_without_promotion(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)

    result = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(
            packet_args=_packet_args(gates, sinks, bypass=False),
        )
    )

    assert result.gate_status == "dominated"
    assert result.packet.gate_status == "dominated"
    assert result.packet.proven_gates == ["destination_range_valid"]
    assert result.promotion_preconditions_met is False
    assert any("missing project fact coverage" in item for item in result.blockers)


def test_windows_sink_to_gate_review_attaches_project_path_facts(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)

    result = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(
            packet_args=_packet_args(gates, sinks, bypass=False),
            call_argument_snapshots=[_argument_snapshot()],
            cfg_path_queries=[_cfg_query()],
            branch_conditions=[_branch_fact()],
        )
    )

    assert result.call_argument_snapshot_count == 1
    assert result.cfg_path_query_count == 1
    assert result.branch_condition_count == 1
    assert result.project_fact_blockers == []
    assert "provided_windows_project_call_argument_snapshot" in result.tool_sequence
    assert "provided_windows_project_cfg_path_query" in result.tool_sequence
    assert "provided_windows_project_branch_condition_facts" in result.tool_sequence
    assert "project_call_argument_snapshot" in (
        result.evidence_bundle.coverage.fact_coverage
    )
    assert "project_cfg_path_query" in result.evidence_bundle.coverage.fact_coverage
    assert "project_branch_conditions" in (
        result.evidence_bundle.coverage.fact_coverage
    )


def test_windows_sink_to_gate_review_auto_invokes_project_tools(
    tmp_path: Path,
    monkeypatch,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    binary, project = _write_auto_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "lea", ["rdx", "[rbp - 0x40]"]),
            _Insn(0x1008, "xor", ["r8d", "r8d"]),
            _Insn(0x100C, "mov", ["r9", "0x20"]),
            _Insn(0x3010, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    result = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(
            packet_args=_packet_args(gates, sinks, bypass=False),
            project_path=str(project),
            binary_path=str(binary),
        )
    )

    assert result.call_argument_snapshot_count == 1
    assert result.cfg_path_query_count == 1
    assert result.branch_condition_count == 1
    assert "auto_windows_project_call_argument_snapshot" in result.tool_sequence
    assert "auto_windows_project_cfg_path_query" in result.tool_sequence
    assert "auto_windows_project_branch_condition_facts" in result.tool_sequence
    assert "project_cfg_path_query" in result.evidence_bundle.coverage.fact_coverage
    assert "project_branch_conditions" in (
        result.evidence_bundle.coverage.fact_coverage
    )
    assert any(
        "call_argument_snapshot missing full_alias_tracking" in item
        for item in result.project_fact_blockers
    )


def test_windows_sink_to_gate_review_uses_manifest_project_path(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    _binary, project = _write_auto_project(tmp_path)
    manifest = _write_project_fact_manifest(tmp_path, project)
    packet_args = _packet_args(gates, sinks, bypass=False).model_copy(
        update={
            "auto_join_manifest_context": True,
            "project_facts_path": str(manifest),
            "manifest_target_id": "driver",
            "manifest_build_label": "unit-test",
        }
    )

    result = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(packet_args=packet_args)
    )

    assert result.auto_project_path == str(project)
    assert result.call_argument_snapshot_count == 0
    assert result.cfg_path_query_count == 1
    assert result.branch_condition_count == 1
    assert "auto_windows_project_cfg_path_query" in result.tool_sequence
    assert "auto_windows_project_branch_condition_facts" in result.tool_sequence
    assert "project_cfg_path_query" in result.evidence_bundle.coverage.fact_coverage
    assert result.packet.project_facts is not None
    assert result.packet.project_facts.project_path == str(project)


def test_windows_sink_to_gate_review_resolves_binary_path_from_build_corpus(
    tmp_path: Path,
    monkeypatch,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    binary, project = _write_auto_project(tmp_path)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "lea", ["rdx", "[rbp - 0x40]"]),
            _Insn(0x1008, "xor", ["r8d", "r8d"]),
            _Insn(0x100C, "mov", ["r9", "0x20"]),
            _Insn(0x3010, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    result = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(
            packet_args=_packet_args(gates, sinks, bypass=False),
            build_corpus=WindowsBuildCorpusArgs(
                manifest_path=str(_write_build_corpus_manifest(tmp_path)),
                corpus_root=str(tmp_path),
                project_root=str(tmp_path),
                target_id="driver",
            ),
        )
    )

    assert result.auto_project_path == str(project)
    assert result.auto_binary_path == str(binary)
    assert result.auto_build_corpus_target_count == 1
    assert result.call_argument_snapshot_count == 1
    assert result.cfg_path_query_count == 1
    assert "windows_build_corpus" in result.tool_sequence
    assert "auto_windows_project_call_argument_snapshot" in result.tool_sequence
    assert result.evidence_bundle.subject.attributes["auto_binary_path"] == str(binary)
    assert result.evidence_bundle.subject.attributes["auto_project_path"] == str(
        project
    )


def test_windows_sink_to_gate_review_blocks_project_cfg_bypass(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)

    result = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(
            packet_args=_packet_args(gates, sinks, bypass=False),
            cfg_path_queries=[_cfg_query(status="bypass")],
        )
    )

    assert any(
        "cfg_path_query status bypass" in item for item in result.project_fact_blockers
    )
    assert any("cfg_path_query status bypass" in item for item in result.blockers)
    assert result.evidence_bundle.blockers == result.blockers


def test_windows_sink_to_gate_review_batch_reviews_multiple_callsites(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)

    result = run_windows_sink_to_gate_review_batch(
        WindowsSinkToGateReviewBatchConfig(
            reviews=[
                WindowsSinkToGateReviewConfig(
                    packet_args=_packet_args(gates, sinks, bypass=True)
                ),
                WindowsSinkToGateReviewConfig(
                    packet_args=_packet_args(gates, sinks, bypass=False)
                ),
            ],
            max_reviews=4,
        )
    )

    assert result.claim_level == "sink_to_gate_review_batch_not_finding"
    assert result.review_count == 2
    assert result.reviewed_count == 2
    assert result.promotion_preconditions_met_count == 0
    assert result.blocked_count == 2
    assert len(result.results) == 2
    assert result.results[0].gate_status == "not_dominated"
    assert result.results[1].gate_status == "dominated"
    assert "windows_sink_to_gate_review_batch" in result.tool_sequence
    assert "windows_cfg_gate_to_sink" in result.tool_sequence
    assert result.evidence_bundle.subject.attributes["review_count"] == 2
    assert result.evidence_bundle.subject.attributes["reviewed_count"] == 2
    assert result.evidence_bundle.subject.attributes["blocked_count"] == 2
    assert result.evidence_bundle.evidence_refs
    assert all(
        item.packet.candidate_id
        in str(result.evidence_bundle.subject.attributes["candidate_ids"])
        for item in result.results
    )


def test_windows_sink_to_gate_review_batch_loads_candidate_packet_artifact(
    tmp_path: Path,
) -> None:
    gates, sinks = _write_metadata(tmp_path)
    packet = run_windows_sink_to_gate_review(
        WindowsSinkToGateReviewConfig(
            packet_args=_packet_args(gates, sinks, bypass=False),
        )
    ).packet
    packets_path = tmp_path / "candidate-packets.json"
    packets_path.write_text(
        json.dumps({"candidate_packets": [packet.model_dump(mode="json")]}),
        encoding="utf-8",
    )

    result = run_windows_sink_to_gate_review_batch(
        WindowsSinkToGateReviewBatchConfig(candidate_packets_path=str(packets_path))
    )

    assert result.review_count == 1
    assert result.reviewed_count == 1
    assert result.results[0].packet.candidate_id == packet.candidate_id
    assert result.results[0].gate_status == packet.gate_status
    assert result.results[0].tool_sequence == ["provided_windows_review_packet"]
    assert "candidate_packet_artifact_loader" in result.tool_sequence
    assert result.evidence_bundle.subject.attributes["candidate_ids"] == (
        packet.candidate_id
    )
