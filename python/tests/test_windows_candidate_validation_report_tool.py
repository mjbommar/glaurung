from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_candidate_validation_report import build_tool
from glaurung.llm.tools.windows_emit_review_packet import (
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from glaurung.llm.tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from glaurung.llm.tools.windows_rank_candidate_packets import RankedWindowsCandidate


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _ranked_candidate(
    candidate_id: str,
    *,
    validation_ready: bool,
    validation_blockers: list[str] | None = None,
) -> RankedWindowsCandidate:
    packet = WindowsReviewPacket(
        candidate_id=candidate_id,
        binary="cldflt.sys",
        build="26100.1742",
        entrypoint="HsmOsBlockPlaceholderAccess",
        attacker_class="windows-local-user",
        source_role="registry_policy_value",
        source_arg="caller_arg1",
        sink_symbol="ZwSetValueKey",
        sink_kind="registry",
        required_gates=["caller_identity_or_impersonation_gate"],
        proven_gates=[],
        missing_required_gates=["caller_identity_or_impersonation_gate"],
        gate_status="missing",
        path=[
            WindowsReviewPathStep(
                function="HsmOsBlockPlaceholderAccess",
                symbol="ZwSetValueKey",
                arg_index=1,
                role="registry_policy_value",
            )
        ],
        evidence=[
            WindowsReviewEvidence(
                source="unit",
                summary="synthetic ranked packet",
                provenance=["cfg", "asb_pe_sink_metadata"],
            )
        ],
        provenance=["cfg", "asb_pe_sink_metadata"],
        required_project_facts=["function_names", "call_xrefs"],
        promotion_preconditions_met=True,
        priority="high",
        confidence=0.8,
        confidence_reason="unit",
        next_validation=["build a VM validation plan"],
        false_positive_questions=["is caller context actually low privilege?"],
    )
    blockers = validation_blockers or []
    plan = WindowsVmValidationPlan(
        candidate_id=candidate_id,
        binary="cldflt.sys",
        build="26100.1742",
        validation_id="win11_ltsc_v4_cold_postlogon",
        build_label="win11-ltsc-v4",
        snapshot_name="cold-postlogon",
        image_path="/images/win11-ltsc-v4.qcow2",
        ovmf_vars_path="/images/win11-ltsc-v4.OVMF_VARS.fd",
        qmp_endpoint="127.0.0.1:4447",
        rdp_endpoint="server0:3390",
        kdnet_port=51000,
        kdnet_status="attach_validated" if validation_ready else "not_configured",
        debugger_status="attached_once" if validation_ready else "not_attached",
        harness_strategy=["exercise placeholder policy sequence"],
        validation_requirements=["pre_post_build_guard_comparison"],
        expected_artifacts=["C:\\Windows\\MEMORY.DMP"],
        stock_current_comparison=["Run stock", "Run current"],
        operator_steps=["Boot VM", "Run harness", "Capture dump"],
        blockers=blockers,
        ready_for_validation=validation_ready,
    )
    return RankedWindowsCandidate(
        rank=1,
        score=87.5,
        packet=packet,
        validation_plan=plan,
        validation_blockers=blockers,
        reasons=["packet priority is high", "VM validation plan is ready"],
        validation_ready=validation_ready,
    )


def test_windows_candidate_validation_report_renders_and_writes_markdown(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    report_path = tmp_path / "validation-report.md"

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            ranked_candidates=[
                _ranked_candidate("ready-candidate", validation_ready=True),
                _ranked_candidate(
                    "blocked-candidate",
                    validation_ready=False,
                    validation_blockers=["KDNET attach is not validated: not_configured"],
                ),
            ],
            markdown_path=str(report_path),
            add_to_kb=True,
        ),
    )

    assert result.candidate_count == 2
    assert result.validation_ready_count == 1
    assert result.blocked_count == 1
    assert result.markdown_path == str(report_path)
    assert "# Windows Candidate Validation Report" in result.markdown
    assert "Claim level: operator validation handoff, not reproduction." in result.markdown
    assert "## Rank 1: ready-candidate" in result.markdown
    assert "Validation substrate: win11_ltsc_v4_cold_postlogon" in result.markdown
    assert "KDNET attach is not validated" in result.markdown
    assert report_path.read_text(encoding="utf-8") == result.markdown
    assert result.report_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label.startswith("windows candidate validation report")
        and node.text == result.markdown
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_windows_candidate_validation_report() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")
    assert "windows_candidate_validation_report" in agent._function_toolset.tools
