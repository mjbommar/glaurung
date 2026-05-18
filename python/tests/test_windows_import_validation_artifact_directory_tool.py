from __future__ import annotations

import hashlib
from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from glaurung.llm.tools.windows_import_validation_artifact_directory import build_tool


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


def _write_artifact_tree(root: Path) -> dict[str, Path]:
    paths = {
        "kdnet": root / "kdnet-attach.log",
        "stock": root / "stock" / "cldflt-placeholder-policy-Stock.log",
        "current": root / "current" / "cldflt-placeholder-policy-Current.log",
        "stdout": root / "stock" / "harness.stdout.txt",
        "stderr": root / "current" / "harness.stderr.txt",
        "identity": root / "stock" / "cldflt.sys.identity.txt",
        "manifest": root / "sha256-manifest.txt",
    }
    for name, path in paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{name}\n", encoding="utf-8")
    return paths


def test_windows_import_validation_artifact_directory_builds_ready_bundle(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    artifact_dir = tmp_path / "artifacts"
    paths = _write_artifact_tree(artifact_dir)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="candidate-1",
            validation_plan=_plan(),
            artifact_dir=str(artifact_dir),
            add_to_kb=True,
        ),
    )

    bundle = result.bundle
    assert bundle.claim_level == "runtime_artifact_bundle_not_finding"
    assert bundle.validation_id == "win11_ltsc_v4_cold_postlogon"
    assert bundle.ready_for_review is True
    assert bundle.runtime_blockers == []
    assert bundle.missing_required_artifacts == []
    assert result.imported_count == len(paths)
    assert result.skipped_count == 0
    kinds = {artifact.kind for artifact in bundle.artifacts}
    assert {
        "kdnet_attach_log",
        "stock_transcript",
        "current_transcript",
        "harness_stdout",
        "harness_stderr",
        "binary_identity",
    } <= kinds
    kdnet = next(artifact for artifact in bundle.artifacts if artifact.kind == "kdnet_attach_log")
    assert kdnet.sha256 == hashlib.sha256(paths["kdnet"].read_bytes()).hexdigest()
    assert kdnet.exists is True
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_import_validation_artifact_directory"
        and node.props["ready_for_review"] is True
        for node in ctx.kb.nodes()
    )


def test_windows_import_validation_artifact_directory_reports_missing_required_kind(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "harness.stdout.txt").write_text("stdout\n", encoding="utf-8")

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="candidate-1",
            validation_plan=_plan(),
            artifact_dir=str(artifact_dir),
            required_kinds=["harness_stdout", "kdnet_attach_log"],
        ),
    )

    assert result.bundle.ready_for_review is False
    assert "kdnet_attach_log: no artifact of this required kind was imported" in (
        result.bundle.missing_required_artifacts
    )
    assert any("required artifact kinds are missing" in blocker for blocker in result.bundle.runtime_blockers)


def test_windows_import_validation_artifact_directory_blocks_plan_candidate_mismatch(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    artifact_dir = tmp_path / "artifacts"
    _write_artifact_tree(artifact_dir)

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            candidate_id="candidate-1",
            validation_plan=_plan(candidate_id="other-candidate"),
            artifact_dir=str(artifact_dir),
        ),
    )

    assert result.bundle.ready_for_review is False
    assert any("candidate_id does not match" in blocker for blocker in result.bundle.runtime_blockers)


def test_memory_agent_registers_windows_import_validation_artifact_directory() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")
    assert "windows_import_validation_artifact_directory" in agent._function_toolset.tools
