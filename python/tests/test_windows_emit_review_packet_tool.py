from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_emit_review_packet import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _write_packet_manifests(tmp_path: Path) -> tuple[Path, Path]:
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
  fact_coverage: [function_names, call_xrefs]
  missing_facts: [cfg]
  counts:
    function_name_count: 9
    xref_count: 12
    call_xref_count: 4
    data_read_xref_count: 2
    data_write_xref_count: 0
    data_label_count: 0
    function_prototype_count: 0
    basic_block_count: 0
    cfg_edge_count: 0
    cfg_dominance_count: 0
    cfg_branch_fact_count: 0
""",
        encoding="utf-8",
    )
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
  glaurung_status: Unit test context is sufficient.
  current_capabilities: [rcx_rdx_r8_r9_argument_snapshots]
  missing_capabilities: [path_sensitive_argument_values]
  next_actions: [add helper summaries]
  evidence: [unit-test]
- id: driver_type_layout
  target_id: driver
  component: driver.sys
  build_label: unit-test
  fact_class: type_layout
  coverage_state: missing
  blocking: true
  ghidra_baseline: Ghidra applies field names.
  glaurung_status: Type layouts are absent.
  current_capabilities: [pdb_identity]
  missing_capabilities: [field_offsets]
  next_actions: [import PDB type layouts]
  evidence: [unit-test]
""",
        encoding="utf-8",
    )
    return project_facts, ghidra_delta


def test_windows_emit_review_packet_normalizes_candidate(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary="ntoskrnl.exe",
            build="26100.1",
            entrypoint="nt!NtExample",
            attacker_class="local_unprivileged",
            source_role="length",
            source_arg="arg2",
            sink_symbol="RtlCopyMemory",
            sink_kind="copy",
            required_gates=["byte_count_bounded", "destination_range_valid"],
            gate_status="missing",
            path=[
                {
                    "function": "nt!NtExample",
                    "symbol": "nt!Helper",
                    "arg_index": 2,
                    "role": "length",
                    "evidence": "arg2 passed to helper",
                },
                {
                    "function": "nt!Helper",
                    "symbol": "RtlCopyMemory",
                    "arg_index": 2,
                    "role": "byte_count",
                    "evidence": "helper count reaches copy",
                },
            ],
            evidence=[
                {
                    "source": "windows_trace_onehop_flow",
                    "summary": "source arg reaches helper-local copy length",
                    "provenance": ["asb_pe_sink_metadata", "supplied_pseudocode"],
                },
                {
                    "source": "windows_check_gate_to_sink",
                    "summary": "no matching gate around copy sink",
                    "provenance": ["asb_pe_gate_metadata"],
                },
            ],
            provenance=["pdb_public_symbol"],
            pdb_identity={
                "target_id": "ntoskrnl",
                "expected_pdb_name": "ntkrnlmp.pdb",
                "codeview_guid_age": "ABCDEF0123456789ABCDEF01234567891",
                "cache_status": "cached",
                "symbol_cache_path": (
                    "/nas4/data/symbol-cache/microsoft/ntkrnlmp.pdb/"
                    "ABCDEF0123456789ABCDEF01234567891/ntkrnlmp.pdb"
                ),
                "fact_coverage": ["pdb_public_symbols", "pdb_type_layouts"],
            },
            component_profile={
                "profile_id": "ntoskrnl-core",
                "target_id": "ntoskrnl",
                "component": "kernel",
                "entrypoint_kinds": ["syscall"],
                "required_gates": ["user_pointer_captured"],
                "validation_requirements": ["vm_bugcheck_or_reject"],
                "harness_strategy": "syscall harness in checked VM",
                "evidence_packet_fields": ["pdb_identity", "source", "sink"],
            },
            diff_context={
                "seed_id": "public-regression-shape",
                "public_ids": ["CVE-2026-0000"],
                "pre_build": "26100.1",
                "post_build": "26100.2",
                "changed_functions": ["nt!NtExample"],
                "diff_signals": ["added bounds gate"],
            },
            project_facts={
                "target_id": "ntoskrnl",
                "build_label": "win11-ltsc-v4",
                "project_path": "/projects/ntoskrnl.glaurung",
                "fact_coverage": ["function_names", "call_xrefs", "cfg"],
                "missing_facts": ["data_labels"],
                "counts": {"function_name_count": 10, "call_xref_count": 7},
            },
            ghidra_delta={
                "target_id": "ntoskrnl",
                "component": "ntoskrnl.exe",
                "build_label": "win11-ltsc-v4",
                "blocking_fact_classes": ["type_layout"],
                "current_capabilities": ["cfg_path"],
                "missing_capabilities": ["field_names"],
                "notes": ["type layouts not imported"],
            },
            add_to_kb=True,
        ),
    )

    packet = result.packet
    assert packet.claim_level == "candidate_not_finding"
    assert packet.candidate_id == (
        "ntoskrnl.exe-26100.1-nt-ntexample-length-rtlcopymemory"
    )
    assert packet.priority == "high"
    assert packet.confidence >= 0.6
    assert packet.pdb_identity is not None
    assert packet.pdb_identity.expected_pdb_name == "ntkrnlmp.pdb"
    assert packet.component_profile is not None
    assert packet.component_profile.profile_id == "ntoskrnl-core"
    assert packet.diff_context is not None
    assert packet.diff_context.changed_functions == ["nt!NtExample"]
    assert packet.project_facts is not None
    assert packet.project_facts.counts["call_xref_count"] == 7
    assert packet.required_project_facts == ["function_names", "call_xrefs"]
    assert packet.ghidra_delta is not None
    assert packet.ghidra_delta.blocking_fact_classes == ["type_layout"]
    assert packet.promotion_preconditions_met is False
    assert any("blocking Ghidra-parity gaps" in item for item in packet.promotion_blockers)
    assert "asb_pdb_identity_manifest" in packet.provenance
    assert "asb_component_profile" in packet.provenance
    assert "patch_diff_context" in packet.provenance
    assert "asb_pe_project_facts_manifest" in packet.provenance
    assert "asb_pe_ghidra_delta_manifest" in packet.provenance
    assert "user_pointer_captured" in packet.required_gates
    assert "VM validation" in " ".join(packet.next_validation)
    assert any("component validation" in step for step in packet.next_validation)
    assert any("patch-diff" in step for step in packet.next_validation)
    assert any("missing project facts" in step for step in packet.next_validation)
    assert any("Ghidra-parity gaps" in step for step in packet.next_validation)
    assert any("size/count units" in q for q in packet.false_positive_questions)
    assert any("Ghidra-parity gap" in q for q in packet.false_positive_questions)
    assert "review packet only" in packet.notes[0]
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_emit_review_packet"
        for node in ctx.kb.nodes()
    )


def test_windows_emit_review_packet_keeps_safe_gate_lower_priority(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="manual-id",
            binary="driver.sys",
            entrypoint="DriverEntry",
            attacker_class="kernel_internal",
            source_role="handle",
            sink_symbol="ObDereferenceObject",
            sink_kind="refcount",
            gate_status="dominated",
            evidence=[
                {
                    "source": "windows_check_gate_to_sink",
                    "summary": "gate dominates sink in CFG evidence",
                    "provenance": ["cfg", "asb_pe_gate_metadata"],
                }
            ],
        ),
    )

    assert result.packet.candidate_id == "manual-id"
    assert result.packet.priority == "low"
    assert result.packet.confidence_reason
    assert result.packet.promotion_preconditions_met is False
    assert "missing project fact coverage context" in result.packet.promotion_blockers
    assert any("ownership transfer" in q for q in result.packet.false_positive_questions)


def test_windows_emit_review_packet_blocks_missing_required_project_facts(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary="driver.sys",
            entrypoint="Dispatch",
            attacker_class="local_unprivileged",
            source_role="buffer",
            sink_symbol="RtlCopyMemory",
            sink_kind="copy",
            gate_status="not_dominated",
            required_project_facts=["function_names", "call_xrefs", "cfg"],
            project_facts={
                "target_id": "driver",
                "build_label": "unit-test",
                "project_path": "/projects/driver.glaurung",
                "fact_coverage": ["function_names"],
                "missing_facts": ["cfg"],
                "counts": {"function_name_count": 5, "call_xref_count": 0},
            },
            evidence=[
                {
                    "source": "windows_cfg_gate_to_sink",
                    "summary": "gate does not dominate sink",
                    "provenance": ["cfg", "asb_pe_gate_metadata"],
                }
            ],
        ),
    )

    packet = result.packet
    assert packet.required_project_facts == ["function_names", "call_xrefs", "cfg"]
    assert packet.promotion_preconditions_met is False
    assert any("missing required project fact coverage" in item for item in packet.promotion_blockers)
    assert any("required project fact count is zero" in item for item in packet.promotion_blockers)
    assert "promotion blocked" in packet.confidence_reason
    assert any("clear promotion blockers" in step for step in packet.next_validation)


def test_windows_emit_review_packet_blocks_unresolved_required_gates(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary="driver.sys",
            entrypoint="Dispatch",
            attacker_class="local_unprivileged",
            source_role="buffer",
            sink_symbol="RtlCopyMemory",
            sink_kind="copy",
            required_gates=["destination_range_valid", "byte_count_bounded"],
            gate_status="unknown",
            required_project_facts=["function_names", "call_xrefs", "cfg"],
            project_facts={
                "target_id": "driver",
                "build_label": "unit-test",
                "project_path": "/projects/driver.glaurung",
                "fact_coverage": ["function_names", "call_xrefs", "cfg"],
                "missing_facts": [],
                "counts": {
                    "function_name_count": 5,
                    "call_xref_count": 4,
                    "basic_block_count": 9,
                    "cfg_edge_count": 8,
                },
            },
            ghidra_delta={
                "target_id": "driver",
                "component": "driver.sys",
                "build_label": "unit-test",
                "blocking_fact_classes": [],
                "current_capabilities": ["cfg_path"],
                "missing_capabilities": [],
            },
            evidence=[
                {
                    "source": "windows_project_gate_requirement_coverage",
                    "summary": (
                        "ProbeForWrite@0x1100 proves [destination_range_valid]; "
                        "missing required gates [byte_count_bounded]"
                    ),
                    "provenance": ["asb_pe_gate_metadata", "asb_pe_sink_metadata"],
                }
            ],
        ),
    )

    packet = result.packet
    assert packet.promotion_preconditions_met is False
    assert any("required gate coverage unresolved" in item for item in packet.promotion_blockers)
    assert "promotion blocked" in packet.confidence_reason


def test_windows_emit_review_packet_auto_joins_manifest_context(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    project_facts_path, ghidra_delta_path = _write_packet_manifests(tmp_path)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            binary="driver.sys",
            entrypoint="Dispatch",
            attacker_class="local_unprivileged",
            source_role="buffer",
            sink_symbol="RtlCopyMemory",
            sink_kind="copy",
            gate_status="missing",
            required_project_facts=["function_names", "call_xrefs"],
            evidence=[
                {
                    "source": "windows_project_call_argument_snapshot",
                    "summary": "call argument snapshot came from project facts",
                    "provenance": ["cfg", "asb_pe_sink_metadata"],
                }
            ],
            auto_join_manifest_context=True,
            project_facts_path=str(project_facts_path),
            ghidra_delta_path=str(ghidra_delta_path),
            manifest_target_id="driver",
            manifest_build_label="unit-test",
            manifest_component="driver.sys",
        ),
    )

    packet = result.packet
    assert packet.project_facts is not None
    assert packet.project_facts.project_path == "/projects/driver.glaurung"
    assert packet.project_facts.counts["call_xref_count"] == 4
    assert packet.ghidra_delta is not None
    assert packet.ghidra_delta.blocking_fact_classes == ["type_layout"]
    assert "rcx_rdx_r8_r9_argument_snapshots" in packet.ghidra_delta.current_capabilities
    assert "asb_pe_project_facts_manifest" in packet.provenance
    assert "asb_pe_ghidra_delta_manifest" in packet.provenance
    assert packet.promotion_preconditions_met is False
    assert any("blocking Ghidra-parity gaps" in item for item in packet.promotion_blockers)


def test_memory_agent_registers_windows_emit_review_packet() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_emit_review_packet" in agent._function_toolset.tools
