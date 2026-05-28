from __future__ import annotations

import sqlite3
from pathlib import Path

from glaurung.llm.agents.windows_triage_worklist import (
    WindowsChangedFunctionFact,
    WindowsTriageWorklistConfig,
    run_windows_triage_worklist,
)
from glaurung.llm.tools.windows_build_corpus import WindowsBuildCorpusArgs
from glaurung.llm.tools.windows_project_fact_manifest import (
    ProjectFactCounts,
    ProjectFactRecord,
)
from glaurung.llm.tools.windows_project_operation_risk_summary import (
    WindowsProjectOperationRiskGroup,
)


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
                (0x2000, "OtherDispatch"),
                (0x4000, "ProbeForWrite"),
                (0x5000, "RtlCopyMemory"),
            ],
        )
        conn.executemany(
            "INSERT INTO xrefs VALUES (?, 1, 'call', ?, ?, ?)",
            [
                (1, 0x1100, 0x1000, 0x4000),
                (2, 0x1200, 0x1000, 0x5000),
                (3, 0x2100, 0x2000, 0x5000),
            ],
        )
        conn.executemany(
            "INSERT INTO basic_blocks VALUES (1, ?, ?, ?, ?)",
            [
                (0x1000, "entry", 0x1000, 0x1100),
                (0x1000, "gate", 0x1100, 0x1180),
                (0x1000, "sink", 0x1180, 0x1280),
                (0x2000, "entry2", 0x2000, 0x2200),
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
  corpus_globs: ["switchy-c-gcc-O2", "switchy-c-gcc-O2-v2"]
  project_globs: ["driver.glaurung"]
  notes: Synthetic manifest target for triage resolution.
""",
        encoding="utf-8",
    )
    return manifest


def _write_high_volume_build_corpus_manifest(tmp_path: Path) -> Path:
    manifest = tmp_path / "pe-build-corpus-high-volume.yaml"
    manifest.write_text(
        """
- id: ntoskrnl
  filename: ntoskrnl.exe
  binary_kind: kernel
  priority: critical
  scan_roles: [syscall_dispatch, object_manager]
  surfaces: [syscall, local_service]
  architectures: [x64]
  corpus_globs: ["ntoskrnl.exe"]
  project_globs: ["ntoskrnl.glaurung"]
  notes: Kernel target.
- id: win32kfull
  filename: win32kfull.sys
  binary_kind: win32k
  priority: high
  scan_roles: [gui_syscall_dispatch]
  surfaces: [syscall]
  architectures: [x64]
  corpus_globs: ["win32kfull.sys"]
  project_globs: ["win32kfull.glaurung"]
  notes: GUI kernel target.
- id: notepad
  filename: notepad.exe
  binary_kind: exe
  priority: low
  scan_roles: [app]
  surfaces: [local_ui]
  architectures: [x64]
  corpus_globs: ["notepad.exe"]
  project_globs: ["notepad.glaurung"]
  notes: Low-priority app target.
""",
        encoding="utf-8",
    )
    return manifest


def test_windows_triage_worklist_ranks_bounded_agent_queue() -> None:
    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=10,
            max_tool_rows=8,
        )
    )

    assert result.claim_level == "triage_worklist_not_finding"
    assert len(result.queue) == 10
    assert result.file_count_total == 30
    assert result.total_missing_entries == 1041
    assert result.total_extra_entries == 3116
    assert [item.rank for item in result.queue] == list(range(1, 11))
    assert result.queue[0].priority >= result.queue[-1].priority
    assert any(item.kind == "functionization_precision" for item in result.queue)
    assert any(item.kind == "uncertain_start" for item in result.queue)
    assert all(item.next_tool for item in result.queue)
    assert result.evidence_bundle.claim_level == "triage_evidence_bundle_not_finding"


def test_windows_triage_worklist_keeps_exact_next_args() -> None:
    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=20,
            max_tool_rows=10,
        )
    )

    addressed = [item for item in result.queue if item.address]
    assert addressed
    assert all("file" in item.next_args for item in addressed)
    assert all("address" in item.next_args for item in addressed)
    assert "windows_candidate_start_worklist" in result.evidence_bundle.next_actions


def test_windows_triage_worklist_includes_project_fact_and_patch_queues() -> None:
    project_record = ProjectFactRecord(
        id="cldflt_project",
        target_id="cldflt",
        build_label="win11-ltsc-v4",
        build_number="26100.1742",
        architecture="x64",
        binary_filename="cldflt.sys",
        project_path="/projects/cldflt.glaurung",
        project_sha256="a" * 64,
        project_size_bytes=1024,
        fact_sources=["unit"],
        fact_coverage=["function_names", "call_xrefs", "cfg"],
        missing_facts=["function_prototypes", "data_labels"],
        counts=ProjectFactCounts(
            function_name_count=974,
            call_xref_count=4666,
            data_read_xref_count=5223,
        ),
    )
    risk_group = WindowsProjectOperationRiskGroup(
        rank=1,
        score=83.0,
        priority="high",
        sink_kind="copy",
        sink_symbol="RtlCopyMemory",
        packet_count=42,
        missing_required_gates=["destination_range_valid"],
        source_refinement_status_counts={"missing": 42},
        reasons=["memory write/copy operation", "missing required gate"],
        blockers=["source refinement missing"],
        provenance=["cldflt.sys"],
    )
    changed = WindowsChangedFunctionFact(
        file="cldflt.sys",
        function="0x140012340",
        status="changed",
        match_basis="pdb_backed_identity",
        security_signals=["sink_delta"],
        functionization_blockers=["boundary_uncertain"],
    )

    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=10,
            max_tool_rows=4,
            changed_functions=[changed],
            project_fact_records=[project_record],
            operation_risk_groups=[risk_group],
        )
    )

    kinds = {item.kind for item in result.queue}
    assert {"changed_function", "gate_source_blocker", "untyped_global"} <= kinds
    changed_item = next(
        item for item in result.queue if item.kind == "changed_function"
    )
    assert changed_item.next_tool == "windows_patch_diff_review"
    assert changed_item.next_args["function"] == "0x140012340"
    blocker = next(item for item in result.queue if item.kind == "gate_source_blocker")
    assert blocker.next_tool == "windows_sink_to_gate_review"
    assert "destination_range_valid" in blocker.reason_codes
    untyped = next(item for item in result.queue if item.kind == "untyped_global")
    assert untyped.next_tool == "windows_project_fact_manifest"
    assert "data_labels" in untyped.reason_codes
    assert "provided_changed_function_facts" in result.tool_sequence
    assert "provided_project_fact_records" in result.tool_sequence
    assert "provided_operation_risk_groups" in result.tool_sequence


def test_windows_triage_worklist_loads_project_fact_manifest(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "pe-project-facts.yaml"
    manifest.write_text(
        """
- id: cldflt_project
  target_id: cldflt
  build_label: win11-ltsc-v4
  build_number: "26100.1742"
  architecture: x64
  binary_filename: cldflt.sys
  project_path: /projects/cldflt.glaurung
  project_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  project_size_bytes: 1024
  fact_sources: [unit]
  fact_coverage: [function_names, call_xrefs, cfg]
  missing_facts: [function_prototypes, data_labels]
  counts:
    function_name_count: 974
    call_xref_count: 4666
    data_read_xref_count: 5223
""",
        encoding="utf-8",
    )

    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=8,
            max_tool_rows=4,
            project_fact_manifest_path=str(manifest),
        )
    )

    assert result.project_fact_manifest_path == str(manifest)
    assert result.project_fact_record_count == 1
    assert "windows_project_fact_manifest" in result.tool_sequence
    assert "provided_project_fact_records" not in result.tool_sequence
    untyped = next(item for item in result.queue if item.kind == "untyped_global")
    assert untyped.file == "cldflt.sys"
    assert untyped.next_tool == "windows_project_fact_manifest"
    assert "function_prototypes" in untyped.reason_codes


def test_windows_triage_worklist_derives_project_and_diff_queues(
    tmp_path: Path,
) -> None:
    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=12,
            max_tool_rows=4,
            diff_binary_a=str(_SWITCHY_V1),
            diff_binary_b=str(_SWITCHY_V2),
            max_changed_function_rows=10,
            project_path=str(_write_project(tmp_path)),
            project_binary="driver.sys",
            project_build="unit-test",
            sinks_path=str(_write_sinks(tmp_path)),
            gates_path=str(_write_gates(tmp_path)),
            sources_path=str(_write_sources(tmp_path)),
            max_operation_risk_groups=4,
        )
    )

    kinds = {item.kind for item in result.queue}
    assert "changed_function" in kinds
    assert "gate_source_blocker" in kinds
    assert result.changed_function_fact_count >= 3
    assert result.operation_risk_group_count == 1
    assert "windows_binary_diff_summary:changed" in result.tool_sequence
    assert "windows_project_operation_risk_summary" in result.tool_sequence
    changed = next(item for item in result.queue if item.kind == "changed_function")
    assert changed.file == _SWITCHY_V2.name
    assert changed.next_tool == "windows_patch_diff_review"
    assert "binary_diff_delta" in changed.reason_codes
    blocker = next(item for item in result.queue if item.kind == "gate_source_blocker")
    assert blocker.next_tool == "windows_sink_to_gate_review"
    assert "byte_count_bounded" in blocker.reason_codes
    assert "windows_project_operation_risk_summary" in (
        result.evidence_bundle.coverage.fact_coverage
    )


def test_windows_triage_worklist_resolves_paths_from_build_corpus(
    tmp_path: Path,
) -> None:
    project = _write_project(tmp_path)

    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=12,
            max_tool_rows=4,
            build_corpus=WindowsBuildCorpusArgs(
                manifest_path=str(_write_build_corpus_manifest(tmp_path)),
                corpus_root=str(_SWITCHY_V1.parent),
                project_root=str(tmp_path),
                target_id="driver",
                max_matches=4,
            ),
            project_build="unit-test",
            sinks_path=str(_write_sinks(tmp_path)),
            gates_path=str(_write_gates(tmp_path)),
            sources_path=str(_write_sources(tmp_path)),
            max_operation_risk_groups=4,
            max_changed_function_rows=10,
        )
    )

    assert result.build_corpus_resolution is not None
    assert result.build_corpus_resolution.resolved_binary == "driver.sys"
    assert result.build_corpus_resolution.resolved_project_path == str(project)
    assert result.build_corpus_resolution.resolved_diff_binary_a == str(_SWITCHY_V1)
    assert result.build_corpus_resolution.resolved_diff_binary_b == str(_SWITCHY_V2)
    assert result.changed_function_fact_count >= 3
    assert result.operation_risk_group_count == 1
    assert "windows_build_corpus" in result.tool_sequence
    assert "windows_binary_diff_summary:changed" in result.tool_sequence
    assert "windows_project_operation_risk_summary" in result.tool_sequence
    assert result.evidence_bundle.subject.attributes["resolved_project_path"] == str(
        project
    )
    assert result.evidence_bundle.subject.attributes["resolved_diff_binary_b"] == str(
        _SWITCHY_V2
    )
    kinds = {item.kind for item in result.queue}
    assert "changed_function" in kinds
    assert "gate_source_blocker" in kinds


def test_windows_triage_worklist_auto_selects_high_volume_corpus_targets(
    tmp_path: Path,
) -> None:
    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=12,
            max_tool_rows=3,
            build_corpus=WindowsBuildCorpusArgs(
                manifest_path=str(_write_high_volume_build_corpus_manifest(tmp_path)),
                max_matches=0,
            ),
            auto_project_from_build_corpus=False,
            auto_diff_from_build_corpus=False,
            auto_select_high_volume_targets=True,
            max_build_corpus_target_items=2,
        )
    )

    assert result.build_corpus_resolution is not None
    assert result.build_corpus_resolution.target_count == 3
    assert [
        target.target_id for target in result.build_corpus_resolution.selected_targets
    ] == [
        "ntoskrnl",
        "win32kfull",
    ]
    assert "windows_build_corpus:auto_select_targets" in result.tool_sequence
    selected = [item for item in result.queue if item.kind == "high_volume_target"]
    assert [item.next_args["target_id"] for item in selected] == [
        "ntoskrnl",
        "win32kfull",
    ]
    assert selected[0].next_tool == "windows_triage_worklist"
    assert "priority:critical" in selected[0].reason_codes
    assert (
        result.evidence_bundle.subject.attributes["selected_build_corpus_target_count"]
        == 2
    )
    assert (
        result.evidence_bundle.subject.attributes["selected_build_corpus_targets"]
        == "ntoskrnl,win32kfull"
    )


def test_windows_triage_worklist_fans_out_high_volume_targets_to_batches(
    tmp_path: Path,
) -> None:
    (tmp_path / "ntoskrnl.exe").write_bytes(b"MZ")
    (tmp_path / "ntoskrnl.glaurung").write_bytes(b"SQLite placeholder")

    result = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=8,
            max_tool_rows=3,
            build_corpus=WindowsBuildCorpusArgs(
                manifest_path=str(_write_high_volume_build_corpus_manifest(tmp_path)),
                corpus_root=str(tmp_path),
                project_root=str(tmp_path),
                max_matches=1,
            ),
            auto_project_from_build_corpus=False,
            auto_diff_from_build_corpus=False,
            auto_select_high_volume_targets=True,
            fanout_high_volume_target_batches=True,
            max_build_corpus_target_items=1,
            fanout_max_packets_per_target=7,
            fanout_attacker_class="local_unprivileged",
            fanout_source_role="user_buffer",
            sinks_path=str(_write_sinks(tmp_path)),
            gates_path=str(_write_gates(tmp_path)),
            sources_path=str(_write_sources(tmp_path)),
        )
    )

    assert len(result.target_fanout_batches) == 1
    fanout = result.target_fanout_batches[0]
    assert fanout.target_id == "ntoskrnl"
    assert fanout.status == "ready"
    assert fanout.next_tool == "windows_validation_planning_batch"
    assert fanout.next_args["target_id"] == "ntoskrnl"
    assert fanout.next_args["max_packets"] == 7
    assert fanout.next_args["attacker_class"] == "local_unprivileged"
    assert fanout.next_args["source_role"] == "user_buffer"
    assert fanout.resolved_project_path == str(tmp_path / "ntoskrnl.glaurung")
    selected = next(item for item in result.queue if item.kind == "high_volume_target")
    assert selected.next_tool == "windows_validation_planning_batch"
    assert selected.next_args["target_id"] == "ntoskrnl"
    assert selected.next_args["project_path"] == str(tmp_path / "ntoskrnl.glaurung")
    assert "fanout:validation_batch_ready" in selected.reason_codes
    assert "windows_triage_worklist:target_fanout_batches" in result.tool_sequence
    assert result.evidence_bundle.subject.attributes["target_fanout_batch_count"] == 1
    assert result.evidence_bundle.subject.attributes["target_fanout_ready_count"] == 1
    assert (
        result.evidence_bundle.subject.attributes["target_fanout_targets"] == "ntoskrnl"
    )
