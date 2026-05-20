from __future__ import annotations

import hashlib
import json
from pathlib import Path

from glaurung.cli.main import GlaurungCLI
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
from glaurung.llm.tools.windows_agent_evidence_bundle import (
    WindowsEvidenceSubject,
    make_windows_evidence_bundle,
)
from glaurung.llm.tools.windows_pipeline_blocker_task_plan import (
    WindowsPipelineBlockerTask,
    WindowsPipelineBlockerTaskPlanResult,
)


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


def test_windows_cli_exposes_interactive_analyst_json(capsys) -> None:
    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "triage_queue",
            "--question",
            "what should I review next?",
            "--max-items",
            "2",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["claim_level"] == "interactive_analysis_not_finding"
    assert output["intent"] == "triage_queue"
    assert output["tool_sequence"] == ["windows_triage_worklist"]
    assert output["next_tools"]


def test_windows_cli_analyst_summarizes_pipeline_blockers(
    tmp_path: Path,
    capsys,
) -> None:
    worklist_path = tmp_path / "blocker-worklist.json"
    worklist = WindowsTargetPipelineBlockerWorklist(
        blocker_work_item_count=1,
        work_items=[
            WindowsTargetPipelineBlockerWorkItem(
                rank=1,
                kind="source_gate_metadata",
                blocker="required gate coverage unresolved: byte_count_bounded",
                count=3,
                candidate_ids=["candidate-1"],
                target_ids=["driver"],
                stages=["sink_to_gate:blocker"],
                required_artifact="ASB source/gate/operation metadata",
                next_action="refine gate metadata",
                reason_codes=["project_fact_blocker"],
            )
        ],
        tool_sequence=["windows_target_pipeline"],
    )
    worklist_path.write_text(worklist.model_dump_json(indent=2), encoding="utf-8")

    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "pipeline_blockers",
            "--question",
            "what blocked the run?",
            "--blocker-worklist-path",
            str(worklist_path),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["intent"] == "pipeline_blockers"
    assert "byte_count_bounded" in output["answer"]
    assert output["next_tools"] == [
        "windows_operation_metadata",
        "windows_source_sink_operand_match",
    ]
    assert output["tool_sequence"] == ["windows_target_pipeline_blocker_worklist"]


def test_windows_cli_analyst_summarizes_pipeline_task_plan(
    tmp_path: Path,
    capsys,
) -> None:
    task_plan_path = tmp_path / "blocker-task-plan.json"
    plan = WindowsPipelineBlockerTaskPlanResult(
        task_count=1,
        tasks=[
            WindowsPipelineBlockerTask(
                rank=1,
                kind="project_cache_refresh",
                source_kind="target_pipeline",
                title="Refresh project cache for driver",
                priority=100,
                target_ids=["driver"],
                candidate_ids=["candidate-1"],
                stages=["evidence_review:missing_static_fact"],
                blocker_count=2,
                blockers=["branch_conditions"],
                required_artifacts=[".glaurung project cache"],
                next_tool_name="windows_bootstrap_project_facts",
                next_tool_args={"target_ids": ["driver"]},
                reason_codes=["task:project_cache_refresh"],
            )
        ],
        source_paths=["blocker-worklist.json"],
        tool_sequence=["windows_pipeline_blocker_task_plan"],
        evidence_bundle=make_windows_evidence_bundle(
            claim_level="triage_evidence_bundle_not_finding",
            subject=WindowsEvidenceSubject(kind="generic"),
            source_tools=["windows_pipeline_blocker_task_plan"],
            tool_sequence=["windows_pipeline_blocker_task_plan"],
        ),
    )
    task_plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")

    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "pipeline_blockers",
            "--question",
            "what task should I run?",
            "--blocker-task-plan-path",
            str(task_plan_path),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert "Pipeline blocker task plan has 1 task" in output["answer"]
    assert output["next_tools"] == ["windows_bootstrap_project_facts"]
    assert output["tool_sequence"] == ["windows_pipeline_blocker_task_plan:artifact"]
    assert output["evidence_bundle"]["subject"]["attributes"][
        "blocker_task_plan_path"
    ] == str(task_plan_path)


def test_windows_cli_exposes_interactive_analyst_plain(capsys) -> None:
    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "boundary_gap",
            "--question",
            "summarize boundary gaps",
            "--file",
            "win11-webservices.dll",
            "--max-items",
            "1",
        ]
    )

    assert rc == 0
    output = capsys.readouterr().out
    assert "Windows analyst (boundary_gap)" in output
    assert "Tool sequence: windows_function_boundary_diff" in output


def test_windows_cli_analyst_reads_and_writes_session_state(
    tmp_path: Path,
    capsys,
) -> None:
    state = tmp_path / "analyst-state.json"
    state.write_text(
        json.dumps(
            {
                "file": "windows-update-intel-wifi-NETwtw10.sys",
                "address": "0x1400041a6",
                "addresses": ["0x1400041a6"],
                "last_intent": "boundary_gap",
            }
        ),
        encoding="utf-8",
    )

    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "explain_function",
            "--question",
            "explain prior address",
            "--state-path",
            str(state),
            "--write-state",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["addresses"] == ["0x1400041a6"]
    assert output["session_state"]["file"] == "windows-update-intel-wifi-NETwtw10.sys"
    assert output["session_state"]["last_intent"] == "explain_function"
    stored = json.loads(state.read_text(encoding="utf-8"))
    assert stored["address"] == "0x1400041a6"
    assert stored["last_intent"] == "explain_function"


def test_windows_cli_analyst_resumes_named_session(
    tmp_path: Path,
    capsys,
) -> None:
    session_dir = tmp_path / "sessions"
    first_rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "explain_function",
            "--question",
            "seed named session",
            "--file",
            "windows-update-intel-wifi-NETwtw10.sys",
            "--address",
            "0x1400041a6",
            "--session-id",
            "wifi-gap",
            "--session-dir",
            str(session_dir),
            "--format",
            "json",
        ]
    )

    assert first_rc == 0
    first_output = json.loads(capsys.readouterr().out)
    state_path = session_dir / "wifi-gap.json"
    assert first_output["analyst_state_path"] == str(state_path)
    assert state_path.exists()

    second_rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "explain_function",
            "--question",
            "resume named session",
            "--session-id",
            "wifi-gap",
            "--session-dir",
            str(session_dir),
            "--format",
            "json",
        ]
    )

    assert second_rc == 0
    second_output = json.loads(capsys.readouterr().out)
    assert second_output["addresses"] == ["0x1400041a6"]
    assert second_output["session_state"]["file"] == (
        "windows-update-intel-wifi-NETwtw10.sys"
    )
    assert second_output["analyst_state_path"] == str(state_path)


def test_windows_cli_analyst_writes_review_packet_handoff(
    tmp_path: Path,
    capsys,
) -> None:
    packet_path = tmp_path / "candidate-packet.json"
    handoff_path = tmp_path / "handoff.json"
    packet_path.write_text(_packet().model_dump_json(indent=2), encoding="utf-8")

    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "candidate_handoff",
            "--question",
            "persist candidate handoff",
            "--candidate-packet-path",
            str(packet_path),
            "--review-packet-output-path",
            str(handoff_path),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["review_packet_handoff_path"] == str(handoff_path)
    assert handoff_path.exists()
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    assert handoff["candidate_id"] == "candidate-1"
    assert (
        "windows_interactive_analyst:write_review_packet_handoff"
        in output["tool_sequence"]
    )


def test_windows_cli_analyst_loads_evidence_export_manifest(
    tmp_path: Path,
    capsys,
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

    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst",
            "--intent",
            "candidate_handoff",
            "--question",
            "load evidence export handoff",
            "--evidence-export-manifest-path",
            str(export_manifest),
            "--candidate-id",
            "candidate-from-export",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["review_packet_handoff"]["candidate_id"] == "candidate-from-export"
    assert "evidence_export_manifest_loader" in output["tool_sequence"]
    assert output["evidence_bundle"]["subject"]["attributes"][
        "evidence_export_manifest_path"
    ] == str(export_manifest)


def test_windows_cli_analyst_loop_runs_script_and_persists_named_session(
    tmp_path: Path,
    capsys,
) -> None:
    script = tmp_path / "analyst-loop.json"
    session_dir = tmp_path / "sessions"
    script.write_text(
        json.dumps(
            {
                "commands": [
                    {
                        "intent": "explain_function",
                        "question": "explain this uncertain start",
                        "file": "windows-update-intel-wifi-NETwtw10.sys",
                        "address": "0x1400041a6",
                    },
                    {
                        "intent": "explain_function",
                        "question": "repeat from session state",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst-loop",
            "--script-path",
            str(script),
            "--session-id",
            "wifi-loop",
            "--session-dir",
            str(session_dir),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    state_path = session_dir / "wifi-loop.json"
    assert output["claim_level"] == "interactive_command_loop_not_finding"
    assert output["completed_turn_count"] == 2
    assert output["failed_turn_count"] == 0
    assert output["analyst_state_path"] == str(state_path)
    assert output["turns"][1]["result"]["addresses"] == ["0x1400041a6"]
    assert json.loads(state_path.read_text(encoding="utf-8"))["address"] == (
        "0x1400041a6"
    )


def test_windows_cli_corpus_guard_json_passes_current_corpus(capsys) -> None:
    rc = GlaurungCLI().run(
        [
            "windows",
            "corpus-guard",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["claim_level"] == "corpus_curation_not_analysis"
    assert output["fixture_count"] == 30
    assert output["drift_guard_passed"] is True
    assert output["manifest_drift_count"] == 0


def test_windows_cli_corpus_guard_fails_on_manifest_drift(
    tmp_path: Path,
    capsys,
) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    (corpus_root / "app.exe").write_bytes(b"MZcli-drift")
    comparison = tmp_path / "comparison.json"
    comparison.write_text(
        json.dumps(
            [
                {
                    "file": "app.exe",
                    "glaurung": {"functions": 3},
                    "ghidra": {"metrics": {"internal_functions": 4}},
                    "address_gap": {"missing_entries": 0, "extra_entries": 0},
                }
            ]
        ),
        encoding="utf-8",
    )
    (corpus_root / "MANIFEST.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "fixtures": [
                    {
                        "file": "app.exe",
                        "path": "stale/app.exe",
                        "suite": "stress",
                        "binary_kind": "exe",
                        "architecture": "x64-pe",
                        "size_bytes": 1,
                        "sha256": "stale",
                        "pdb_status": "unknown",
                        "stress_purpose": ["stale"],
                        "ghidra_internal_functions": 0,
                        "glaurung_functions": 0,
                        "missing_entries": 0,
                        "extra_entries": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc = GlaurungCLI().run(
        [
            "windows",
            "corpus-guard",
            "--corpus-root",
            str(corpus_root),
            "--comparison-path",
            str(comparison),
            "--format",
            "json",
        ]
    )

    assert rc == 1
    output = json.loads(capsys.readouterr().out)
    assert output["drift_guard_passed"] is False
    assert output["manifest_drift_count"] > 0
    assert any(item["field"] == "sha256" for item in output["manifest_drift"])


def test_windows_cli_corpus_guard_allows_accepted_manifest_drift(
    tmp_path: Path,
    capsys,
) -> None:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    payload = b"MZcli-accepted-drift"
    binary = corpus_root / "app.exe"
    binary.write_bytes(payload)
    comparison = tmp_path / "comparison.json"
    comparison.write_text(
        json.dumps(
            [
                {
                    "file": "app.exe",
                    "glaurung": {"functions": 3},
                    "ghidra": {"metrics": {"internal_functions": 4}},
                    "address_gap": {"missing_entries": 0, "extra_entries": 0},
                }
            ]
        ),
        encoding="utf-8",
    )
    (corpus_root / "MANIFEST.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "fixtures": [
                    {
                        "file": "app.exe",
                        "path": str(binary),
                        "suite": "stress",
                        "binary_kind": "exe",
                        "architecture": "x64-pe",
                        "size_bytes": len(payload),
                        "sha256": "stale",
                        "pdb_status": "unknown",
                        "stress_purpose": ["general_windows_pe_coverage"],
                        "ghidra_internal_functions": 4,
                        "glaurung_functions": 3,
                        "missing_entries": 0,
                        "extra_entries": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    accepted = tmp_path / "accepted-drift.json"
    accepted.write_text(
        json.dumps(
            {
                "accepted_drift": [
                    {
                        "file": "app.exe",
                        "field": "sha256",
                        "current": hashlib.sha256(payload).hexdigest(),
                        "recorded": "stale",
                        "reason": "Intentional fixture refresh during corpus review.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    review_notes = tmp_path / "corpus-review.md"

    rc = GlaurungCLI().run(
        [
            "windows",
            "corpus-guard",
            "--corpus-root",
            str(corpus_root),
            "--comparison-path",
            str(comparison),
            "--accepted-drift-path",
            str(accepted),
            "--review-notes-path",
            str(review_notes),
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["manifest_drift_count"] == 1
    assert output["accepted_drift_count"] == 1
    assert output["unaccepted_manifest_drift_count"] == 0
    assert output["drift_guard_passed"] is True
    assert output["review_notes_path"] == str(review_notes)
    assert "Intentional fixture refresh" in review_notes.read_text(encoding="utf-8")
