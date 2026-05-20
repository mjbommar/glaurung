from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.agents.windows_interactive_analyst import (
    WindowsInteractiveAnalystConfig,
    WindowsInteractiveAnalystSessionState,
    run_windows_interactive_analyst,
)
from glaurung.llm.agents.windows_analyst_command_loop import (
    WindowsAnalystLoopCommand,
    WindowsAnalystLoopConfig,
    run_windows_analyst_command_loop,
)
from glaurung.llm.agents.windows_target_pipeline import (
    WindowsTargetPipelineBlockerWorkItem,
    WindowsTargetPipelineBlockerWorklist,
)
from glaurung.llm.tools.windows_emit_review_packet import (
    WindowsProjectFactContext,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from glaurung.llm.tools.windows_interactive_analyst import build_tool
from glaurung.llm.tools.windows_pipeline_blocker_task_plan import (
    build_tool as build_task_plan_tool,
)


COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)
DIAGNOSTICS = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    return MemoryContext(file_path=str(path), artifact=artifact)


def _packet() -> WindowsReviewPacket:
    return WindowsReviewPacket(
        candidate_id="candidate-1",
        binary="ntoskrnl.exe",
        build="26100.1",
        entrypoint="nt!NtExample",
        attacker_class="local_unprivileged",
        source_role="output_buffer",
        source_arg="arg1",
        sink_symbol="RtlCopyMemory",
        sink_kind="copy",
        required_gates=["destination_range_valid"],
        proven_gates=[],
        missing_required_gates=[],
        gate_status="missing",
        path=[
            WindowsReviewPathStep(
                function="nt!NtExample",
                symbol="RtlCopyMemory",
                arg_index=0,
                role="destination_buffer",
            )
        ],
        evidence=[
            WindowsReviewEvidence(
                source="unit",
                summary="synthetic packet",
                provenance=["cfg", "asb_pe_sink_metadata"],
            )
        ],
        provenance=["cfg", "asb_pe_sink_metadata"],
        project_facts=WindowsProjectFactContext(
            target_id="ntoskrnl",
            build_label="win11-ltsc-v4",
            project_path="/projects/ntoskrnl.glaurung",
            fact_coverage=["function_names", "call_xrefs", "cfg"],
            missing_facts=[],
            counts={"function_name_count": 10},
        ),
        required_project_facts=["function_names", "call_xrefs", "cfg"],
        promotion_preconditions_met=True,
        priority="high",
        confidence=0.85,
        confidence_reason="unit",
        next_validation=["build a VM validation plan"],
        false_positive_questions=["is caller context actually low privilege?"],
    )


def test_windows_interactive_analyst_explains_address_with_uncertainty() -> None:
    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="explain_function",
            question="why is this address a function?",
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            file="windows-update-intel-wifi-NETwtw10.sys",
            address="0x1400041a6",
        )
    )

    assert result.claim_level == "interactive_analysis_not_finding"
    assert result.addresses == ["0x1400041a6"]
    assert "glaurung_only" in result.answer
    assert "demote_to_rejected_start" in result.answer
    assert "padding_run" in result.known_uncertainty
    assert result.tool_sequence == ["windows_function_start_explain"]
    assert result.evidence_bundle.claim_level == "triage_evidence_bundle_not_finding"
    assert result.session_state.file == "windows-update-intel-wifi-NETwtw10.sys"
    assert result.session_state.address == "0x1400041a6"
    assert result.session_state.last_intent == "explain_function"


def test_windows_interactive_analyst_hands_off_review_packet_with_coverage() -> None:
    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="candidate_handoff",
            question="turn this navigation result into a review handoff",
            candidate_packet=_packet(),
        )
    )

    assert result.review_packet_handoff is not None
    assert result.review_packet_handoff.candidate_id == "candidate-1"
    assert result.project_fact_coverage == ["function_names", "call_xrefs", "cfg"]
    assert any(
        item.startswith("validation_ready=") for item in result.known_uncertainty
    )
    assert "windows_evidence_review" in result.next_tools
    assert result.tool_sequence == ["windows_rank_candidate_packets"]
    assert result.evidence_bundle.subject.candidate_id == "candidate-1"
    assert result.session_state.file == "ntoskrnl.exe"
    assert result.session_state.review_packet_candidate_id == "candidate-1"


def test_windows_interactive_analyst_writes_review_packet_handoff(
    tmp_path: Path,
) -> None:
    handoff_path = tmp_path / "review-packet.json"

    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="candidate_handoff",
            question="persist this review handoff",
            candidate_packet=_packet(),
            review_packet_output_path=str(handoff_path),
        )
    )

    assert result.review_packet_handoff_path == str(handoff_path)
    assert handoff_path.exists()
    assert '"candidate_id": "candidate-1"' in handoff_path.read_text(encoding="utf-8")
    assert (
        "windows_interactive_analyst:write_review_packet_handoff"
        in result.tool_sequence
    )


def test_windows_interactive_analyst_loads_evidence_export_handoff(
    tmp_path: Path,
) -> None:
    packet_artifact = tmp_path / "candidate-packets.json"
    export_manifest = tmp_path / "evidence-export.json"
    packet = _packet().model_copy(update={"candidate_id": "candidate-from-export"})
    packet_artifact.write_text(
        json.dumps(
            {
                "claim_level": "candidate_packet_export_not_finding",
                "candidate_count": 1,
                "candidate_packets": [packet.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )
    export_manifest.write_text(
        json.dumps(
            {
                "claim_level": "evidence_review_export_manifest_not_finding",
                "candidate_count": 1,
                "candidate_ids": ["candidate-from-export"],
                "candidate_packets_path": str(packet_artifact),
            }
        ),
        encoding="utf-8",
    )

    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="candidate_handoff",
            question="load the durable evidence handoff",
            evidence_export_manifest_path=str(export_manifest),
            candidate_id="candidate-from-export",
        )
    )

    assert result.review_packet_handoff is not None
    assert result.review_packet_handoff.candidate_id == "candidate-from-export"
    assert "evidence_export_manifest_loader" in result.tool_sequence
    assert "evidence_export_candidate_packet_loader" in result.tool_sequence
    assert any(
        item == f"evidence_export_manifest={export_manifest}"
        for item in result.known_uncertainty
    )
    assert result.evidence_bundle.subject.attributes[
        "evidence_export_manifest_path"
    ] == str(export_manifest)


def test_windows_interactive_analyst_tool_exposes_deterministic_workflow(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            intent="candidate_handoff",
            question="turn this packet into a durable review handoff",
            candidate_packet=_packet(),
        ),
    )

    assert result.claim_level == "interactive_analysis_not_finding"
    assert result.review_packet_handoff is not None
    assert result.review_packet_handoff.candidate_id == "candidate-1"
    assert result.tool_sequence == ["windows_rank_candidate_packets"]
    assert result.evidence_bundle.subject.candidate_id == "candidate-1"


def test_windows_interactive_analyst_summarizes_pipeline_blockers(
    tmp_path: Path,
) -> None:
    worklist_path = tmp_path / "blocker-worklist.json"
    worklist = WindowsTargetPipelineBlockerWorklist(
        blocker_work_item_count=2,
        work_items=[
            WindowsTargetPipelineBlockerWorkItem(
                rank=1,
                kind="project_cache",
                blocker="branch_conditions",
                count=4,
                candidate_ids=["candidate-1", "candidate-2"],
                target_ids=["driver"],
                stages=["evidence_review:missing_static_fact"],
                required_artifact=".glaurung project cache and project-fact manifest",
                next_action="refresh project cache",
                reason_codes=["missing_static_fact"],
            ),
            WindowsTargetPipelineBlockerWorkItem(
                rank=2,
                kind="source_gate_metadata",
                blocker="required gate coverage unresolved: destination_range_valid",
                count=2,
                candidate_ids=["candidate-3"],
                target_ids=["driver"],
                stages=["sink_to_gate:blocker"],
                required_artifact="ASB source/gate/operation metadata",
                next_action="refine gate metadata",
                reason_codes=["project_fact_blocker"],
            ),
        ],
        tool_sequence=["windows_target_pipeline"],
    )
    worklist_path.write_text(worklist.model_dump_json(indent=2), encoding="utf-8")

    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="pipeline_blockers",
            question="what should we fix from the high-volume run?",
            blocker_worklist_path=str(worklist_path),
            max_items=1,
        )
    )

    assert result.claim_level == "interactive_analysis_not_finding"
    assert "Pipeline blocker worklist has 2 item" in result.answer
    assert "branch_conditions" in result.answer
    assert result.known_uncertainty == [
        "project_cache:branch_conditions:count=4:candidates=2"
    ]
    assert result.next_tools == ["windows_project_fact_manifest"]
    assert result.tool_sequence == ["windows_target_pipeline_blocker_worklist"]
    assert result.evidence_bundle.subject.attributes["blocker_worklist_path"] == str(
        worklist_path
    )


def test_windows_interactive_analyst_summarizes_pipeline_task_plan(
    tmp_path: Path,
) -> None:
    worklist_path = tmp_path / "blocker-worklist.json"
    task_plan_path = tmp_path / "blocker-task-plan.json"
    worklist = WindowsTargetPipelineBlockerWorklist(
        blocker_work_item_count=1,
        work_items=[
            WindowsTargetPipelineBlockerWorkItem(
                rank=1,
                kind="project_cache",
                blocker="branch_conditions",
                count=4,
                candidate_ids=["candidate-1", "candidate-2"],
                target_ids=["driver"],
                stages=["evidence_review:missing_static_fact"],
                required_artifact=".glaurung project cache and project-fact manifest",
                next_action="refresh project cache",
                reason_codes=["missing_static_fact"],
            )
        ],
        tool_sequence=["windows_target_pipeline"],
    )
    worklist_path.write_text(worklist.model_dump_json(indent=2), encoding="utf-8")
    ctx = _ctx(tmp_path)
    task_tool = build_task_plan_tool()
    task_tool.run(
        ctx,
        ctx.kb,
        task_tool.input_model(
            blocker_worklist_path=str(worklist_path),
            output_path=str(task_plan_path),
        ),
    )

    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="pipeline_blockers",
            question="which remediation task should I run?",
            blocker_task_plan_path=str(task_plan_path),
            max_items=1,
        )
    )

    assert "Pipeline blocker task plan has 1 task" in result.answer
    assert "project_cache_refresh" in result.answer
    assert result.next_tools == ["windows_bootstrap_project_facts"]
    assert result.tool_sequence == ["windows_pipeline_blocker_task_plan:artifact"]
    assert result.known_uncertainty == [
        "project_cache_refresh:priority=100:targets=driver:blockers=4"
    ]
    assert result.evidence_bundle.subject.attributes["blocker_task_plan_path"] == str(
        task_plan_path
    )


def test_memory_agent_registers_windows_interactive_analyst() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_interactive_analyst" in agent._function_toolset.tools


def test_windows_interactive_analyst_builds_bounded_triage_queue() -> None:
    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="triage_queue",
            question="what should I inspect next?",
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            max_items=5,
        )
    )

    assert "Triage queue has 5 bounded item" in result.answer
    assert result.addresses
    assert len(result.known_uncertainty) >= 2
    assert result.next_tools
    assert result.tool_sequence == ["windows_triage_worklist"]
    assert result.session_state.addresses[: len(result.addresses)] == result.addresses


def test_windows_interactive_analyst_uses_session_state_file_and_address() -> None:
    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="explain_function",
            question="explain the prior address",
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            session_state=WindowsInteractiveAnalystSessionState(
                file="windows-update-intel-wifi-NETwtw10.sys",
                address="0x1400041a6",
                addresses=["0x1400041a6"],
                last_intent="boundary_gap",
            ),
        )
    )

    assert result.addresses == ["0x1400041a6"]
    assert "windows-update-intel-wifi-NETwtw10.sys" in result.answer
    assert result.session_state.file == "windows-update-intel-wifi-NETwtw10.sys"
    assert result.session_state.address == "0x1400041a6"
    assert result.session_state.last_intent == "explain_function"


def test_windows_interactive_analyst_routes_patch_diff_question() -> None:
    result = run_windows_interactive_analyst(
        WindowsInteractiveAnalystConfig(
            intent="patch_diff",
            question="what changed between these two builds?",
            binary_a="samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2",
            binary_b="samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2-v2",
            max_items=4,
            pdb_backed=True,
        )
    )

    assert "Patch diff ranked" in result.answer
    assert "changed=" in result.answer
    assert "windows_patch_diff_review" in result.tool_sequence
    assert result.known_uncertainty
    assert result.next_tools


def test_windows_analyst_command_loop_carries_session_state_between_turns() -> None:
    result = run_windows_analyst_command_loop(
        WindowsAnalystLoopConfig(
            comparison_path=str(COMPARISON),
            diagnostics_path=str(DIAGNOSTICS),
            commands=[
                WindowsAnalystLoopCommand(
                    intent="explain_function",
                    question="explain this uncertain start",
                    file="windows-update-intel-wifi-NETwtw10.sys",
                    address="0x1400041a6",
                ),
                WindowsAnalystLoopCommand(
                    intent="explain_function",
                    question="explain the same start from session state",
                ),
            ],
        )
    )

    assert result.claim_level == "interactive_command_loop_not_finding"
    assert result.turn_count == 2
    assert result.completed_turn_count == 2
    assert result.failed_turn_count == 0
    assert all(turn.result is not None for turn in result.turns)
    turn_results = [turn.result for turn in result.turns if turn.result is not None]
    assert [turn.addresses for turn in turn_results] == [
        ["0x1400041a6"],
        ["0x1400041a6"],
    ]
    assert result.final_session_state.file == "windows-update-intel-wifi-NETwtw10.sys"
    assert result.final_session_state.address == "0x1400041a6"
    assert "windows_function_start_explain" in result.tool_sequence
