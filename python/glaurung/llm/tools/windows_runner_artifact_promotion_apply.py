"""Verify and optionally apply Windows runner artifact promotion plans."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)


WindowsPromotionApplyStatus = Literal["dry_run", "applied", "unchanged", "blocked"]


class WindowsRunnerArtifactPromotionApplyArgs(BaseModel):
    plan_path: str = Field(..., description="runner-artifact-promotion-plan JSON path.")
    apply_changes: bool = Field(
        False,
        description="If true, copy verified artifacts into destination paths.",
    )
    output_path: str | None = Field(
        None,
        description="Optional JSON path to persist apply/verification results.",
    )
    review_markdown_path: str | None = Field(
        None,
        description=(
            "Optional markdown path to write a maintainer-facing promotion "
            "commit readiness report."
        ),
    )
    add_to_kb: bool = False


class WindowsRunnerArtifactPromotionApplyAction(BaseModel):
    source_path: str
    destination_path: str
    operation: str
    expected_source_sha256: str | None = None
    actual_source_sha256: str | None = None
    source_hash_verified: bool = False
    destination_exists_before: bool = False
    destination_sha256_before: str | None = None
    destination_sha256_after: str | None = None
    destination_would_change: bool = False
    applied: bool = False
    status: WindowsPromotionApplyStatus
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class WindowsRunnerArtifactPromotionApplyResult(BaseModel):
    claim_level: str = "runner_artifact_promotion_apply_not_finding"
    plan_path: str
    apply_requested: bool
    verification_passed: bool
    action_count: int
    applied_count: int
    changed_destination_count: int
    baseline_commit_ready: bool
    actions: list[WindowsRunnerArtifactPromotionApplyAction]
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    output_path: str | None = None
    review_markdown_path: str | None = None
    tool_sequence: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsRunnerArtifactPromotionApplyTool(
    MemoryTool[
        WindowsRunnerArtifactPromotionApplyArgs,
        WindowsRunnerArtifactPromotionApplyResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_runner_artifact_promotion_apply",
                description=(
                    "Verify source hashes in a Windows runner artifact promotion "
                    "plan and optionally copy the artifacts into baseline "
                    "destinations. Dry-run is the default."
                ),
                tags=("windows", "runner", "artifacts", "promotion", "baseline"),
            ),
            WindowsRunnerArtifactPromotionApplyArgs,
            WindowsRunnerArtifactPromotionApplyResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRunnerArtifactPromotionApplyArgs,
    ) -> WindowsRunnerArtifactPromotionApplyResult:
        plan_path = Path(args.plan_path).expanduser()
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        blockers: list[str] = []
        warnings: list[str] = []
        if not bool(plan.get("promotion_allowed", False)):
            blockers.append("promotion plan is not promotion_allowed")
            blockers.extend(str(item) for item in plan.get("blockers") or [])
        actions = [
            _action_result(raw, apply_changes=args.apply_changes)
            for raw in plan.get("actions") or []
            if isinstance(raw, dict)
        ] if not blockers else []
        blockers.extend(blocker for action in actions for blocker in action.blockers)
        warnings.extend(warning for action in actions for warning in action.warnings)
        verification_passed = not blockers and all(
            action.source_hash_verified for action in actions
        )
        baseline_commit_ready = (
            verification_passed
            and args.apply_changes
            and all(action.status in {"applied", "unchanged"} for action in actions)
        )
        output_path = _write_result(
            args.output_path,
            plan_path=str(plan_path),
            apply_requested=args.apply_changes,
            verification_passed=verification_passed,
            baseline_commit_ready=baseline_commit_ready,
            actions=actions,
            blockers=_dedupe(blockers),
            warnings=_dedupe(warnings),
        )
        review_markdown_path = _write_review_markdown(
            args.review_markdown_path,
            plan_path=str(plan_path),
            apply_requested=args.apply_changes,
            verification_passed=verification_passed,
            baseline_commit_ready=baseline_commit_ready,
            actions=actions,
            blockers=_dedupe(blockers),
            warnings=_dedupe(warnings),
        )
        tool_sequence = ["windows_runner_artifact_promotion_apply"]
        if output_path:
            tool_sequence.append("windows_runner_artifact_promotion_apply:write_output")
        if review_markdown_path:
            tool_sequence.append(
                "windows_runner_artifact_promotion_apply:write_review_markdown"
            )
        notes = [
            "Promotion apply verifies artifact hashes before copying.",
            "Dry-run mode does not modify destination files.",
        ]
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_runner_artifact_promotion_apply",
                    props={
                        "plan_path": str(plan_path),
                        "apply_requested": args.apply_changes,
                        "verification_passed": verification_passed,
                        "baseline_commit_ready": baseline_commit_ready,
                        "applied_count": sum(action.applied for action in actions),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
        return WindowsRunnerArtifactPromotionApplyResult(
            plan_path=str(plan_path),
            apply_requested=args.apply_changes,
            verification_passed=verification_passed,
            action_count=len(actions),
            applied_count=sum(action.applied for action in actions),
            changed_destination_count=sum(
                action.destination_would_change for action in actions
            ),
            baseline_commit_ready=baseline_commit_ready,
            actions=actions,
            blockers=_dedupe(blockers),
            warnings=_dedupe(warnings),
            output_path=output_path,
            review_markdown_path=review_markdown_path,
            tool_sequence=tool_sequence,
            evidence_bundle=_evidence_bundle(
                plan_path=str(plan_path),
                apply_requested=args.apply_changes,
                verification_passed=verification_passed,
                baseline_commit_ready=baseline_commit_ready,
                actions=actions,
                blockers=_dedupe(blockers),
                warnings=_dedupe(warnings),
                tool_sequence=tool_sequence,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _action_result(
    raw: dict[str, Any],
    *,
    apply_changes: bool,
) -> WindowsRunnerArtifactPromotionApplyAction:
    source = Path(str(raw.get("source_path") or "")).expanduser()
    destination = Path(str(raw.get("destination_path") or "")).expanduser()
    expected_sha = str(raw.get("source_sha256") or "") or None
    operation = str(raw.get("operation") or "copy")
    blockers: list[str] = []
    warnings: list[str] = []
    actual_sha = _sha256(source) if source.is_file() else None
    if not source.is_file():
        blockers.append(f"source artifact missing: {source}")
    if expected_sha and actual_sha != expected_sha:
        blockers.append(
            f"source sha256 mismatch for {source}: expected {expected_sha}, got {actual_sha}"
        )
    if operation != "copy":
        blockers.append(f"unsupported promotion operation: {operation}")
    destination_exists = destination.exists()
    before_sha = _sha256(destination) if destination.is_file() else None
    destination_would_change = actual_sha is not None and actual_sha != before_sha
    applied = False
    after_sha = before_sha
    status: WindowsPromotionApplyStatus
    if blockers:
        status = "blocked"
    elif not destination_would_change:
        status = "unchanged"
    elif not apply_changes:
        status = "dry_run"
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        after_sha = _sha256(destination)
        if after_sha != actual_sha:
            blockers.append(
                f"destination sha256 mismatch after copy for {destination}: {after_sha}"
            )
            status = "blocked"
        else:
            applied = True
            status = "applied"
    return WindowsRunnerArtifactPromotionApplyAction(
        source_path=str(source),
        destination_path=str(destination),
        operation=operation,
        expected_source_sha256=expected_sha,
        actual_source_sha256=actual_sha,
        source_hash_verified=actual_sha is not None and actual_sha == expected_sha,
        destination_exists_before=destination_exists,
        destination_sha256_before=before_sha,
        destination_sha256_after=after_sha if apply_changes else None,
        destination_would_change=destination_would_change,
        applied=applied,
        status=status,
        blockers=blockers,
        warnings=warnings,
    )


def _write_result(
    path_text: str | None,
    *,
    plan_path: str,
    apply_requested: bool,
    verification_passed: bool,
    baseline_commit_ready: bool,
    actions: list[WindowsRunnerArtifactPromotionApplyAction],
    blockers: list[str],
    warnings: list[str],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "claim_level": "runner_artifact_promotion_apply_not_finding",
        "plan_path": plan_path,
        "apply_requested": apply_requested,
        "verification_passed": verification_passed,
        "baseline_commit_ready": baseline_commit_ready,
        "action_count": len(actions),
        "applied_count": sum(action.applied for action in actions),
        "changed_destination_count": sum(
            action.destination_would_change for action in actions
        ),
        "actions": [action.model_dump(mode="json") for action in actions],
        "blockers": blockers,
        "warnings": warnings,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _write_review_markdown(
    path_text: str | None,
    *,
    plan_path: str,
    apply_requested: bool,
    verification_passed: bool,
    baseline_commit_ready: bool,
    actions: list[WindowsRunnerArtifactPromotionApplyAction],
    blockers: list[str],
    warnings: list[str],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _review_markdown(
            plan_path=plan_path,
            apply_requested=apply_requested,
            verification_passed=verification_passed,
            baseline_commit_ready=baseline_commit_ready,
            actions=actions,
            blockers=blockers,
            warnings=warnings,
        ),
        encoding="utf-8",
    )
    return str(path)


def _review_markdown(
    *,
    plan_path: str,
    apply_requested: bool,
    verification_passed: bool,
    baseline_commit_ready: bool,
    actions: list[WindowsRunnerArtifactPromotionApplyAction],
    blockers: list[str],
    warnings: list[str],
) -> str:
    lines = [
        "# Windows Runner Artifact Promotion Apply",
        "",
        f"- Plan: `{plan_path}`",
        f"- Apply Requested: {'yes' if apply_requested else 'no'}",
        f"- Verification Passed: {'yes' if verification_passed else 'no'}",
        f"- Baseline Commit Ready: {'yes' if baseline_commit_ready else 'no'}",
        f"- Actions: {len(actions)}",
        f"- Applied: {sum(action.applied for action in actions)}",
        (
            "- Changed Destinations: "
            f"{sum(action.destination_would_change for action in actions)}"
        ),
        "",
        "| Status | Source | Destination | Source SHA256 | Destination SHA256 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for action in actions:
        lines.append(
            "| "
            + " | ".join(
                [
                    action.status,
                    f"`{action.source_path}`",
                    f"`{action.destination_path}`",
                    _short_hash(action.actual_source_sha256),
                    _short_hash(
                        action.destination_sha256_after
                        or action.destination_sha256_before
                    ),
                ]
            )
            + " |"
        )
    if blockers:
        lines.extend(["", "## Blockers", ""])
        lines.extend(f"- {blocker}" for blocker in blockers)
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in warnings)
    lines.extend(["", "## Next Actions", ""])
    if baseline_commit_ready:
        lines.append("- Review the destination diffs and commit the promoted baselines.")
    elif verification_passed and not apply_requested:
        lines.append("- Rerun with `--apply-changes` after reviewing this dry run.")
    else:
        lines.append("- Resolve blockers before applying or committing promoted baselines.")
    return "\n".join(lines) + "\n"


def _evidence_bundle(
    *,
    plan_path: str,
    apply_requested: bool,
    verification_passed: bool,
    baseline_commit_ready: bool,
    actions: list[WindowsRunnerArtifactPromotionApplyAction],
    blockers: list[str],
    warnings: list[str],
    tool_sequence: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "plan_path": plan_path,
                "apply_requested": apply_requested,
                "verification_passed": verification_passed,
                "baseline_commit_ready": baseline_commit_ready,
                "action_count": len(actions),
                "applied_count": sum(action.applied for action in actions),
                "warning_count": len(warnings),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_runner_artifact_promotion_apply",
                summary=(
                    f"verified {len(actions)} promotion action(s), "
                    f"applied {sum(action.applied for action in actions)}"
                ),
                reason_codes=["runner_artifact_promotion_apply_not_finding"],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[action.source_path for action in actions],
            missing_facts=warnings,
            stale_or_blocking_facts=blockers,
            validation_ready=baseline_commit_ready,
        ),
        reason_codes=["runner_artifact_promotion_apply_not_finding"],
        blockers=blockers,
        next_actions=[] if apply_requested else ["Rerun with apply_changes=true to copy verified artifacts."],
        notes=notes,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _short_hash(value: str | None) -> str:
    return "-" if not value else f"`{value[:12]}`"


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsRunnerArtifactPromotionApplyTool:
    return WindowsRunnerArtifactPromotionApplyTool()
