"""Plan promotion of reviewed Windows runner artifacts into baselines."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex
from typing import Literal

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


WindowsArtifactPromotionOperation = Literal["copy", "archive"]


class WindowsRunnerArtifactPromotionPlanArgs(BaseModel):
    artifact_dir: str = Field(..., description="Directory containing reviewed artifacts.")
    review_path: str | None = Field(
        None,
        description="Optional runner-artifact-review JSON path. Defaults inside artifact_dir.",
    )
    docs_root: str = "docs/windows-port"
    output_path: str | None = Field(
        None,
        description="Optional JSON path to persist the promotion plan.",
    )
    add_to_kb: bool = False


class WindowsRunnerArtifactPromotionAction(BaseModel):
    operation: WindowsArtifactPromotionOperation
    source_artifact: str
    source_path: str
    destination_path: str
    source_sha256: str
    destination_exists: bool
    command: str
    reason_codes: list[str] = Field(default_factory=list)


class WindowsRunnerArtifactPromotionPlanResult(BaseModel):
    claim_level: str = "runner_artifact_promotion_plan_not_finding"
    artifact_dir: str
    review_path: str
    docs_root: str
    promotion_allowed: bool
    action_count: int
    actions: list[WindowsRunnerArtifactPromotionAction]
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    output_path: str | None = None
    tool_sequence: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsRunnerArtifactPromotionPlanTool(
    MemoryTool[
        WindowsRunnerArtifactPromotionPlanArgs,
        WindowsRunnerArtifactPromotionPlanResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_runner_artifact_promotion_plan",
                description=(
                    "Convert a promotion-ready Windows runner artifact review "
                    "into explicit copy/archive actions for docs and metadata "
                    "baselines. This plans artifact promotion only; it does not "
                    "promote vulnerability claims."
                ),
                tags=("windows", "runner", "artifacts", "promotion", "baseline"),
            ),
            WindowsRunnerArtifactPromotionPlanArgs,
            WindowsRunnerArtifactPromotionPlanResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRunnerArtifactPromotionPlanArgs,
    ) -> WindowsRunnerArtifactPromotionPlanResult:
        artifact_dir = Path(args.artifact_dir).expanduser()
        review_path = Path(
            args.review_path or artifact_dir / "runner-artifact-review.json"
        ).expanduser()
        docs_root = Path(args.docs_root).expanduser()
        review = json.loads(review_path.read_text(encoding="utf-8"))
        blockers: list[str] = []
        warnings: list[str] = []
        promotion_ready = bool(review.get("promotion_ready", False))
        review_blockers = [str(item) for item in review.get("blockers") or []]
        review_mode = str(review.get("mode") or "auto")
        promotable_artifacts = [
            str(item) for item in review.get("promotable_artifacts") or []
        ]
        if not promotion_ready:
            blockers.append("runner artifact review is not promotion-ready")
            blockers.extend(review_blockers)
        actions = (
            _promotion_actions(
                mode=review_mode,
                promotable_artifacts=promotable_artifacts,
                artifact_dir=artifact_dir,
                docs_root=docs_root,
                warnings=warnings,
            )
            if not blockers
            else []
        )
        if not actions and not blockers:
            warnings.append("no promotable artifact mappings matched this review")
        output_path = _write_result(
            args.output_path,
            artifact_dir=str(artifact_dir),
            review_path=str(review_path),
            docs_root=str(docs_root),
            promotion_allowed=not blockers and bool(actions),
            actions=actions,
            blockers=blockers,
            warnings=warnings,
        )
        tool_sequence = ["windows_runner_artifact_promotion_plan"]
        if output_path:
            tool_sequence.append("windows_runner_artifact_promotion_plan:write_output")
        notes = [
            "Promotion plan is for runner artifacts and docs baselines only.",
            "Apply commands manually or in a reviewed commit after checking diffs.",
        ]
        promotion_allowed = not blockers and bool(actions)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_runner_artifact_promotion_plan",
                    props={
                        "artifact_dir": str(artifact_dir),
                        "promotion_allowed": promotion_allowed,
                        "action_count": len(actions),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
        return WindowsRunnerArtifactPromotionPlanResult(
            artifact_dir=str(artifact_dir),
            review_path=str(review_path),
            docs_root=str(docs_root),
            promotion_allowed=promotion_allowed,
            action_count=len(actions),
            actions=actions,
            blockers=_dedupe(blockers),
            warnings=_dedupe(warnings),
            output_path=output_path,
            tool_sequence=tool_sequence,
            evidence_bundle=_evidence_bundle(
                artifact_dir=str(artifact_dir),
                review_path=str(review_path),
                docs_root=str(docs_root),
                promotion_allowed=promotion_allowed,
                actions=actions,
                blockers=_dedupe(blockers),
                warnings=_dedupe(warnings),
                tool_sequence=tool_sequence,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _promotion_actions(
    *,
    mode: str,
    promotable_artifacts: list[str],
    artifact_dir: Path,
    docs_root: Path,
    warnings: list[str],
) -> list[WindowsRunnerArtifactPromotionAction]:
    actions: list[WindowsRunnerArtifactPromotionAction] = []
    for artifact in promotable_artifacts:
        source = artifact_dir / artifact
        if not source.exists() or not source.is_file():
            warnings.append(f"promotable artifact missing: {artifact}")
            continue
        destination = _destination_for(mode, artifact, docs_root)
        if destination is None:
            warnings.append(f"no promotion mapping for artifact: {artifact}")
            continue
        actions.append(
            WindowsRunnerArtifactPromotionAction(
                operation="copy",
                source_artifact=artifact,
                source_path=str(source),
                destination_path=str(destination),
                source_sha256=_sha256(source),
                destination_exists=destination.exists(),
                command=f"cp {shlex.quote(str(source))} {shlex.quote(str(destination))}",
                reason_codes=["artifact_baseline_promotion", mode],
            )
        )
    return actions


def _destination_for(
    mode: str,
    artifact: str,
    docs_root: Path,
) -> Path | None:
    if mode == "ghidra_parity":
        if artifact.endswith("_refresh.json"):
            return docs_root / "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
        if artifact.endswith("_refresh.md"):
            return docs_root / "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.md"
        if artifact == "glaurung_vs_ghidra_vendor_windows_30.json":
            return docs_root / "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
        if artifact == "glaurung_vs_ghidra_vendor_windows_30.md":
            return docs_root / "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.md"
    if mode == "target_pipeline":
        if artifact.endswith(".json") or artifact.endswith(".md"):
            return docs_root / "runner-artifacts" / artifact
    return None


def _write_result(
    path_text: str | None,
    *,
    artifact_dir: str,
    review_path: str,
    docs_root: str,
    promotion_allowed: bool,
    actions: list[WindowsRunnerArtifactPromotionAction],
    blockers: list[str],
    warnings: list[str],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "claim_level": "runner_artifact_promotion_plan_not_finding",
        "artifact_dir": artifact_dir,
        "review_path": review_path,
        "docs_root": docs_root,
        "promotion_allowed": promotion_allowed,
        "action_count": len(actions),
        "actions": [action.model_dump(mode="json") for action in actions],
        "blockers": blockers,
        "warnings": warnings,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _evidence_bundle(
    *,
    artifact_dir: str,
    review_path: str,
    docs_root: str,
    promotion_allowed: bool,
    actions: list[WindowsRunnerArtifactPromotionAction],
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
                "artifact_dir": artifact_dir,
                "review_path": review_path,
                "docs_root": docs_root,
                "promotion_allowed": promotion_allowed,
                "action_count": len(actions),
                "warning_count": len(warnings),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_runner_artifact_promotion_plan",
                summary=f"planned {len(actions)} runner artifact promotion action(s)",
                reason_codes=["runner_artifact_promotion_plan_not_finding"],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[action.source_path for action in actions],
            missing_facts=warnings,
            stale_or_blocking_facts=blockers,
            validation_ready=promotion_allowed,
        ),
        reason_codes=["runner_artifact_promotion_plan_not_finding"],
        blockers=blockers,
        next_actions=[action.command for action in actions],
        notes=notes,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsRunnerArtifactPromotionPlanTool:
    return WindowsRunnerArtifactPromotionPlanTool()
