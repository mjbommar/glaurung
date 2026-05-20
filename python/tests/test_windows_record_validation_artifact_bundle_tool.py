from __future__ import annotations

import hashlib
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from glaurung.llm.tools.windows_record_validation_artifact_bundle import (
    WindowsValidationArtifact,
    build_tool,
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _plan(candidate_id: str = "candidate-1") -> WindowsVmValidationPlan:
    return WindowsVmValidationPlan(
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
        kdnet_status="attach_validated",
        debugger_status="attached_once",
        kdnet_attach_proof="/evidence/kdnet-attach.log",
        kdnet_last_attach_utc="2026-05-18T20:00:00Z",
        harness_strategy=["exercise placeholder policy sequence"],
        validation_requirements=["pre_post_build_guard_comparison"],
        expected_artifacts=["C:\\Windows\\MEMORY.DMP"],
        stock_current_comparison=["Run stock", "Run current"],
        operator_steps=["Boot VM", "Run harness", "Capture dump"],
        blockers=[],
        ready_for_validation=True,
    )


def test_windows_record_validation_artifact_bundle_blocks_missing_required_hash(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="candidate-1",
            validation_plan=_plan(),
            execution_status="partial",
            artifacts=[
                WindowsValidationArtifact(
                    kind="kdnet_attach_log",
                    path="/evidence/kdnet-attach.log",
                    required=True,
                )
            ],
        ),
    )

    bundle = result.bundle
    assert bundle.claim_level == "runtime_artifact_bundle_not_finding"
    assert bundle.validation_id == "win11_ltsc_v4_cold_postlogon"
    assert result.evidence_bundle.claim_level == "runtime_artifact_bundle_not_finding"
    assert result.evidence_bundle.subject.candidate_id == "candidate-1"
    assert result.evidence_bundle.coverage.validation_status == "partial"
    assert result.evidence_bundle.coverage.runtime_artifact_count == 1
    assert bundle.ready_for_review is False
    assert "kdnet_attach_log: missing sha256" in bundle.missing_required_artifacts
    assert any(
        "validation execution is not complete" in blocker
        for blocker in bundle.runtime_blockers
    )
    assert any(
        "required runtime artifacts" in blocker for blocker in bundle.runtime_blockers
    )


def test_windows_record_validation_artifact_bundle_hashes_existing_artifact_and_adds_kb(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    artifact_path = tmp_path / "kdnet-attach.log"
    artifact_path.write_text("kdnet connected\n", encoding="utf-8")
    expected_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="candidate-1",
            validation_plan=_plan(),
            execution_status="executed",
            artifacts=[
                WindowsValidationArtifact(
                    kind="kdnet_attach_log",
                    path=str(artifact_path),
                    required=True,
                    summary="debugger attached before harness run",
                )
            ],
            hash_existing_paths=True,
            require_existing_paths=True,
            add_to_kb=True,
        ),
    )

    bundle = result.bundle
    assert result.hashed_count == 1
    assert bundle.ready_for_review is True
    assert bundle.missing_required_artifacts == []
    assert bundle.runtime_blockers == []
    assert bundle.artifacts[0].sha256 == expected_sha
    assert bundle.artifacts[0].exists is True
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_record_validation_artifact_bundle"
        and node.props["candidate_id"] == "candidate-1"
        and node.props["ready_for_review"] is True
        for node in ctx.kb.nodes()
    )


def test_windows_record_validation_artifact_bundle_blocks_plan_candidate_mismatch(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="candidate-1",
            validation_plan=_plan(candidate_id="other-candidate"),
            execution_status="executed",
            artifacts=[
                WindowsValidationArtifact(
                    kind="stock_transcript",
                    path="/evidence/stock.log",
                    sha256="0" * 64,
                    required=True,
                )
            ],
        ),
    )

    assert result.bundle.ready_for_review is False
    assert any(
        "candidate_id does not match" in blocker
        for blocker in result.bundle.runtime_blockers
    )


def test_memory_agent_registers_windows_record_validation_artifact_bundle() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")
    assert "windows_record_validation_artifact_bundle" in agent._function_toolset.tools
