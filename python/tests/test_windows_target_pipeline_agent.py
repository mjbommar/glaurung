from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, cast

import glaurung as g
import pytest

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.agents.windows_target_pipeline import (
    WindowsTargetPipelineConfig,
    run_windows_target_pipeline,
)
from glaurung.llm.tools.windows_build_corpus import WindowsBuildCorpusArgs


COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)
DIAGNOSTICS = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
)
_SWITCHY_V1 = Path("samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2")
_SWITCHY_V2 = Path(
    "samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2"
)


class _Addr:
    def __init__(self, value: int) -> None:
        self.value = value


class _Insn:
    def __init__(self, va: int, mnemonic: str, operands: list[str]) -> None:
        self.address = _Addr(va)
        self.mnemonic = mnemonic
        self.operands = operands


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _write_inventory(tmp_path: Path) -> Path:
    path = tmp_path / "pe-validation-inventory.yaml"
    path.write_text(
        r"""
- id: win11_ltsc_v4_cold_postlogon
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  sku: Win11 IoT Enterprise LTSC 2024 Evaluation
  snapshot_name: cold-postlogon
  baseline_kind: canonical_fuzz
  image_path: /images/win11-ltsc-v4.qcow2
  ovmf_vars_path: /images/win11-ltsc-v4.OVMF_VARS.fd
  qmp_endpoint: 127.0.0.1:4447
  rdp_endpoint: server0:3390
  kdnet_port: 51000
  kdnet_status: attach_validated
  debugger_status: attached_once
  kdnet_attach_proof: /evidence/kdnet-attach.log
  boot_script: boot-win11-test.sh
  expected_artifacts: []
  stock_current_comparison:
    - Run stock build once.
    - Run current build once.
""",
        encoding="utf-8",
    )
    return path


def _write_project(tmp_path: Path) -> Path:
    project = tmp_path / "driver.glaurung"
    conn = sqlite3.connect(project)
    try:
        conn.executescript(
            """
CREATE TABLE xrefs (
    xref_id INTEGER PRIMARY KEY,
    binary_id INTEGER,
    kind TEXT,
    src_va INTEGER,
    src_function_va INTEGER,
    dst_va INTEGER
);
CREATE TABLE function_names (
    binary_id INTEGER,
    entry_va INTEGER,
    canonical TEXT,
    demangled TEXT
);
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
"""
        )
        conn.executemany(
            "INSERT INTO function_names VALUES (1, ?, ?, NULL)",
            [
                (0x1000, "DriverDispatch"),
                (0x4000, "ProbeForWrite"),
                (0x5000, "RtlCopyMemory"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, 'call', ?, ?, ?)",
            [
                (1, 0x1100, 0x1000, 0x4000),
                (2, 0x1200, 0x1000, 0x5000),
            ],
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
        conn.commit()
    finally:
        conn.close()
    return project


def _write_build_corpus_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "pe-build-corpus.yaml"
    path.write_text(
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
  notes: Synthetic target pipeline target.
""",
        encoding="utf-8",
    )
    return path


def _write_project_sinks(tmp_path: Path) -> Path:
    path = tmp_path / "pe-sinks.yaml"
    path.write_text(
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
    return path


def _write_project_gates(tmp_path: Path) -> Path:
    path = tmp_path / "pe-gates.yaml"
    path.write_text(
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
    return path


def _write_vulnerability_seeds(tmp_path: Path) -> Path:
    path = tmp_path / "pe-vulnerability-seeds.yaml"
    path.write_text(
        """
- id: driver_ioctl_seed
  public_ids: [CVE-2099-4242]
  title: Driver IOCTL validation seed
  target_id: driver
  component: driver.sys
  functions: [DriverDispatch]
  surfaces: [ioctl]
  attacker_classes: [windows-local-user]
  invariant_family: validation
  primitive: ioctl_buffer_without_destination_gate
  source_roles: [ioctl_input_buffer]
  expected_gates: [destination_range_valid]
  expected_sinks: [RtlCopyMemory]
  diff_signals: [added_destination_range_check]
  validation_requirements: [prove ioctl caller reachability]
  references: []
""",
        encoding="utf-8",
    )
    return path


def _write_operation_backlog(tmp_path: Path) -> Path:
    path = tmp_path / "pe-operation-classification-backlog.yaml"
    path.write_text(
        """
- id: driver_rtlcopy_backlog
  target_id: driver
  component: driver.sys
  build_label: win11-ltsc-v4
  source_snapshot_id: snapshot-driver
  symbol: RtlCopyMemory
  observed_callsite_count: 2
  caller_function_count: 1
  resolution_kind_counts: {import: 2}
  sample_callers: [DriverDispatch]
  triage_category: memory_copy
  candidate_operation_kinds: [copy]
  likely_security_relevance: high
  required_capabilities: [source_arg_roles, destination_range_gate]
  recommended_next_actions:
    - classify destination/source/length argument roles
    - prove required gates before packet promotion
""",
        encoding="utf-8",
    )
    return path


def _write_project_facts(tmp_path: Path, project: Path) -> Path:
    path = tmp_path / "pe-project-facts.yaml"
    path.write_text(
        f"""
- id: driver_project
  target_id: driver
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: driver.sys
  project_path: {project}
  project_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  project_size_bytes: 4096
  fact_sources: [unit]
  fact_coverage: [function_names, call_xrefs, cfg, cfg_dominance]
  missing_facts: []
  counts:
    function_name_count: 3
    call_xref_count: 2
    basic_block_count: 3
    cfg_edge_count: 2
    cfg_dominance_count: 3
""",
        encoding="utf-8",
    )
    return path


def test_windows_target_pipeline_runs_target_to_evidence_review(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = _write_project(tmp_path)
    (tmp_path / "driver.sys").write_bytes(b"MZdriver")

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1008, "mov", ["r8d", "0x20"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    result = run_windows_target_pipeline(
        WindowsTargetPipelineConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            build_corpus=WindowsBuildCorpusArgs(
                manifest_path=str(_write_build_corpus_manifest(tmp_path)),
                corpus_root=str(tmp_path),
                project_root=str(tmp_path),
                max_matches=1,
            ),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            build_label="win11-ltsc-v4",
            attacker_class="windows-local-user",
            source_role="buffer",
            source_arg="arg1",
            call_symbol="RtlCopyMemory",
            sinks_path=str(_write_project_sinks(tmp_path)),
            gates_path=str(_write_project_gates(tmp_path)),
            project_facts_path=str(_write_project_facts(tmp_path, project)),
            vulnerability_seeds_path=str(_write_vulnerability_seeds(tmp_path)),
            operation_backlog_path=str(_write_operation_backlog(tmp_path)),
            max_targets=1,
            max_packets_per_target=4,
            max_candidates=6,
            candidate_packets_export_path=str(tmp_path / "candidate-packets.json"),
            evidence_operator_markdown_path=str(tmp_path / "evidence-review.md"),
            evidence_export_manifest_path=str(tmp_path / "evidence-export.json"),
            evidence_candidate_packets_export_path=str(
                tmp_path / "evidence-candidate-packets.json"
            ),
            pipeline_export_manifest_path=str(tmp_path / "pipeline-export.json"),
            blocker_worklist_path=str(tmp_path / "blocker-worklist.json"),
        )
    )

    assert result.claim_level == "target_pipeline_not_finding"
    assert result.selected_target_count == 1
    assert result.ready_fanout_count == 1
    assert result.candidate_count == 3
    assert result.planned_count == 3
    assert result.sink_review_count == 3
    assert result.evidence_review_count == 3
    assert result.validation.candidate_packets[0].project_facts is not None
    assert result.validation.vulnerability_seed_packet_count == 1
    assert result.validation.operation_backlog_packet_count == 1
    assert result.validation.operation_backlog_batch_count == 1
    assert "windows_vulnerability_seed_packets" in result.tool_sequence
    assert "windows_operation_backlog_packets" in result.tool_sequence
    assert result.validation.candidate_packets_export_path == str(
        tmp_path / "candidate-packets.json"
    )
    assert result.sink_review.results[0].packet.candidate_id == (
        result.validation.candidate_packets[0].candidate_id
    )
    assert result.evidence_review.review_items[0].candidate_id == (
        result.validation.candidate_packets[0].candidate_id
    )
    assert "windows_target_pipeline" in result.tool_sequence
    assert "windows_target_pipeline:write_export_manifest" in result.tool_sequence
    assert "windows_target_pipeline:write_blocker_worklist" in result.tool_sequence
    assert "windows_validation_planning_batch" in result.tool_sequence
    assert "windows_sink_to_gate_review_batch" in result.tool_sequence
    assert result.evidence_bundle.subject.attributes["candidate_count"] == 3
    blocker_work_item_count = result.evidence_bundle.subject.attributes[
        "blocker_work_item_count"
    ]
    assert isinstance(blocker_work_item_count, int)
    assert blocker_work_item_count >= 3
    assert result.export_manifest_path == str(tmp_path / "pipeline-export.json")
    assert result.blocker_worklist_path == str(tmp_path / "blocker-worklist.json")
    kinds = {item.kind for item in result.blocker_worklist}
    assert "project_cache" in kinds
    assert "source_gate_metadata" in kinds
    assert "validation_inventory" in kinds
    assert "harness" in kinds
    assert any(
        item.kind == "project_cache" and item.blocker == "branch_conditions"
        for item in result.blocker_worklist
    )
    assert any(
        item.kind == "source_gate_metadata"
        and "destination_range_valid" in item.blocker
        for item in result.blocker_worklist
    )
    blocker_manifest = json.loads(
        (tmp_path / "blocker-worklist.json").read_text(encoding="utf-8")
    )
    assert blocker_manifest["claim_level"] == "target_pipeline_blocker_worklist_not_finding"
    assert blocker_manifest["blocker_work_item_count"] == len(result.blocker_worklist)
    assert blocker_manifest["work_items"][0]["candidate_ids"]
    manifest = json.loads(
        (tmp_path / "pipeline-export.json").read_text(encoding="utf-8")
    )
    assert manifest["claim_level"] == "target_pipeline_export_manifest_not_finding"
    assert manifest["candidate_count"] == 3
    assert manifest["target_ids"] == ["driver"]
    assert manifest["candidate_packets_path"] == str(
        tmp_path / "candidate-packets.json"
    )
    assert manifest["evidence_export_manifest_path"] == str(
        tmp_path / "evidence-export.json"
    )
    assert manifest["blocker_worklist_path"] == str(tmp_path / "blocker-worklist.json")
    assert manifest["blocker_work_item_count"] == len(result.blocker_worklist)


def test_windows_target_pipeline_includes_patch_diff_packets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = _write_project(tmp_path)
    (tmp_path / "driver.sys").write_bytes(b"MZdriver")
    patch_a = _need(_SWITCHY_V1)
    patch_b = _need(_SWITCHY_V2)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1008, "mov", ["r8d", "0x20"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    result = run_windows_target_pipeline(
        WindowsTargetPipelineConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            build_corpus=WindowsBuildCorpusArgs(
                manifest_path=str(_write_build_corpus_manifest(tmp_path)),
                corpus_root=str(tmp_path),
                project_root=str(tmp_path),
                max_matches=1,
            ),
            validation_inventory_path=str(_write_inventory(tmp_path)),
            build_label="win11-ltsc-v4",
            attacker_class="windows-local-user",
            source_role="buffer",
            source_arg="arg1",
            call_symbol="RtlCopyMemory",
            sinks_path=str(_write_project_sinks(tmp_path)),
            gates_path=str(_write_project_gates(tmp_path)),
            project_facts_path=str(_write_project_facts(tmp_path, project)),
            patch_diff_binary_a=str(patch_a),
            patch_diff_binary_b=str(patch_b),
            patch_diff_max_diff_rows=16,
            patch_diff_max_items=4,
            max_targets=1,
            max_packets_per_target=1,
            max_candidates=4,
        )
    )

    assert result.candidate_count == 2
    assert result.validation.patch_diff_packet_count == 1
    assert result.planned_count == 2
    assert result.sink_review_count == 2
    assert result.evidence_review_count == 2
    assert "windows_patch_diff_packets" in result.tool_sequence
    assert any(
        packet.candidate_id.startswith("patchdiff-")
        for packet in result.validation.candidate_packets
    )
    assert (
        result.validation.evidence_bundle.subject.attributes["patch_diff_packet_count"]
        == 1
    )


def test_windows_cli_target_pipeline_json(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    project = _write_project(tmp_path)
    (tmp_path / "driver.sys").write_bytes(b"MZdriver")

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1008, "mov", ["r8d", "0x20"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    rc = GlaurungCLI().run(
        [
            "windows",
            "target-pipeline",
            "--build-corpus-manifest",
            str(_write_build_corpus_manifest(tmp_path)),
            "--corpus-root",
            str(tmp_path),
            "--project-root",
            str(tmp_path),
            "--validation-inventory-path",
            str(_write_inventory(tmp_path)),
            "--build-label",
            "win11-ltsc-v4",
            "--attacker-class",
            "windows-local-user",
            "--source-role",
            "buffer",
            "--source-arg",
            "arg1",
            "--call-symbol",
            "RtlCopyMemory",
            "--sinks-path",
            str(_write_project_sinks(tmp_path)),
            "--gates-path",
            str(_write_project_gates(tmp_path)),
            "--project-facts-path",
            str(_write_project_facts(tmp_path, project)),
            "--vulnerability-seeds-path",
            str(_write_vulnerability_seeds(tmp_path)),
            "--operation-backlog-path",
            str(_write_operation_backlog(tmp_path)),
            "--max-targets",
            "1",
            "--max-packets-per-target",
            "6",
            "--max-candidates",
            "4",
            "--candidate-packets-export-path",
            str(tmp_path / "candidate-packets.json"),
            "--pipeline-export-manifest-path",
            str(tmp_path / "pipeline-export.json"),
            "--blocker-worklist-path",
            str(tmp_path / "blocker-worklist.json"),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["claim_level"] == "target_pipeline_not_finding"
    assert output["candidate_count"] == 3
    assert output["sink_review_count"] == 3
    assert output["evidence_review_count"] == 3
    assert output["blocker_work_item_count"] >= 3
    assert output["blocker_worklist_path"] == str(tmp_path / "blocker-worklist.json")
    assert any(
        item["kind"] == "project_cache" and item["blocker"] == "branch_conditions"
        for item in output["blocker_worklist"]
    )
    assert output["export_manifest_path"] == str(tmp_path / "pipeline-export.json")
    assert "windows_target_pipeline" in output["tool_sequence"]
    assert "windows_vulnerability_seed_packets" in output["tool_sequence"]
    assert "windows_operation_backlog_packets" in output["tool_sequence"]
    assert "windows_target_pipeline:write_export_manifest" in output["tool_sequence"]
    assert "windows_target_pipeline:write_blocker_worklist" in output["tool_sequence"]


def test_windows_cli_target_pipeline_accepts_patch_diff_packets(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    project = _write_project(tmp_path)
    (tmp_path / "driver.sys").write_bytes(b"MZdriver")
    patch_a = _need(_SWITCHY_V1)
    patch_b = _need(_SWITCHY_V2)

    def fake_disassemble_window_at(*_args, **_kwargs):
        return [
            _Insn(0x1000, "mov", ["rcx", "rdi"]),
            _Insn(0x1004, "mov", ["rdx", "rsi"]),
            _Insn(0x1008, "mov", ["r8d", "0x20"]),
            _Insn(0x1200, "call", ["0x5000"]),
        ]

    monkeypatch.setattr(
        cast(Any, g).disasm,
        "disassemble_window_at",
        fake_disassemble_window_at,
    )

    rc = GlaurungCLI().run(
        [
            "windows",
            "target-pipeline",
            "--build-corpus-manifest",
            str(_write_build_corpus_manifest(tmp_path)),
            "--corpus-root",
            str(tmp_path),
            "--project-root",
            str(tmp_path),
            "--validation-inventory-path",
            str(_write_inventory(tmp_path)),
            "--build-label",
            "win11-ltsc-v4",
            "--attacker-class",
            "windows-local-user",
            "--source-role",
            "buffer",
            "--source-arg",
            "arg1",
            "--call-symbol",
            "RtlCopyMemory",
            "--sinks-path",
            str(_write_project_sinks(tmp_path)),
            "--gates-path",
            str(_write_project_gates(tmp_path)),
            "--project-facts-path",
            str(_write_project_facts(tmp_path, project)),
            "--patch-diff-binary-a",
            str(patch_a),
            "--patch-diff-binary-b",
            str(patch_b),
            "--patch-diff-max-diff-rows",
            "16",
            "--patch-diff-max-items",
            "4",
            "--max-targets",
            "1",
            "--max-packets-per-target",
            "1",
            "--max-candidates",
            "4",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["candidate_count"] == 2
    assert output["validation"]["patch_diff_packet_count"] == 1
    assert "windows_patch_diff_packets" in output["tool_sequence"]
