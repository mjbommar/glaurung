from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_vm_validation_plan import WindowsVmValidationPlan


WindowsValidationArtifactKind = Literal[
    "serial_log",
    "kdnet_attach_log",
    "crash_dump",
    "harness_stdout",
    "harness_stderr",
    "screenshot",
    "binary_identity",
    "pdb_identity",
    "stock_transcript",
    "current_transcript",
    "operator_note",
    "other",
]

WindowsValidationExecutionStatus = Literal[
    "not_run",
    "partial",
    "executed",
    "inconclusive",
    "crash_observed",
    "rejected_cleanly",
]


class WindowsValidationArtifact(BaseModel):
    kind: WindowsValidationArtifactKind = Field(
        ...,
        description="Artifact class captured during VM validation.",
    )
    path: str = Field(
        ...,
        description="Operator-supplied local or guest artifact path.",
    )
    sha256: str | None = Field(
        None,
        description="SHA256 digest for the artifact. Required for required artifacts.",
    )
    summary: str | None = Field(
        None,
        description="Short operator summary of what this artifact proves.",
    )
    required: bool = Field(
        True,
        description="If true, missing path/hash blocks the bundle from review.",
    )
    exists: bool | None = Field(
        None,
        description="Local filesystem existence if checked by the tool.",
    )


class WindowsRecordValidationArtifactBundleArgs(BaseModel):
    candidate_id: str = Field(
        ...,
        description="Candidate id that the runtime artifacts validate or reject.",
    )
    validation_plan: WindowsVmValidationPlan | None = Field(
        None,
        description="Optional VM validation plan this bundle was collected against.",
    )
    execution_status: WindowsValidationExecutionStatus = Field(
        ...,
        description="Observed validation execution outcome.",
    )
    artifacts: list[WindowsValidationArtifact] = Field(
        default_factory=list,
        description="Runtime artifacts captured by the operator.",
    )
    operator_notes: list[str] = Field(
        default_factory=list,
        description="Short notes about setup, deviations, or interpretation.",
    )
    hash_existing_paths: bool = Field(
        False,
        description="If true, compute SHA256 for local existing artifact paths missing hashes.",
    )
    require_existing_paths: bool = Field(
        False,
        description="If true, required artifacts must exist on this filesystem.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add the artifact bundle as a KB evidence node.",
    )


class WindowsValidationArtifactBundle(BaseModel):
    candidate_id: str
    claim_level: str = "runtime_artifact_bundle_not_finding"
    validation_id: str | None = None
    execution_status: WindowsValidationExecutionStatus
    artifact_count: int
    artifacts: list[WindowsValidationArtifact] = Field(default_factory=list)
    missing_required_artifacts: list[str] = Field(default_factory=list)
    runtime_blockers: list[str] = Field(default_factory=list)
    ready_for_review: bool
    operator_notes: list[str] = Field(default_factory=list)


class WindowsRecordValidationArtifactBundleResult(BaseModel):
    bundle: WindowsValidationArtifactBundle
    hashed_count: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsRecordValidationArtifactBundleTool(
    MemoryTool[
        WindowsRecordValidationArtifactBundleArgs,
        WindowsRecordValidationArtifactBundleResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_record_validation_artifact_bundle",
                description=(
                    "Record runtime artifacts collected while executing a Windows "
                    "VM validation plan. This only accounts for evidence paths and "
                    "hashes; it does not claim reproduction or finding promotion."
                ),
                tags=("windows", "pe", "validation", "artifact", "evidence"),
            ),
            WindowsRecordValidationArtifactBundleArgs,
            WindowsRecordValidationArtifactBundleResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRecordValidationArtifactBundleArgs,
    ) -> WindowsRecordValidationArtifactBundleResult:
        artifacts, hashed_count = _normalize_artifacts(
            args.artifacts,
            hash_existing_paths=args.hash_existing_paths,
            require_existing_paths=args.require_existing_paths,
        )
        missing = _missing_required_artifacts(
            artifacts,
            require_existing_paths=args.require_existing_paths,
        )
        runtime_blockers = _runtime_blockers(args, missing)
        bundle = WindowsValidationArtifactBundle(
            candidate_id=args.candidate_id,
            validation_id=(
                args.validation_plan.validation_id if args.validation_plan is not None else None
            ),
            execution_status=args.execution_status,
            artifact_count=len(artifacts),
            artifacts=artifacts,
            missing_required_artifacts=missing,
            runtime_blockers=runtime_blockers,
            ready_for_review=not runtime_blockers,
            operator_notes=list(args.operator_notes),
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_record_validation_artifact_bundle",
                    props={
                        "candidate_id": bundle.candidate_id,
                        "validation_id": bundle.validation_id,
                        "execution_status": bundle.execution_status,
                        "ready_for_review": bundle.ready_for_review,
                        "artifact_count": bundle.artifact_count,
                        "missing_required_artifact_count": len(
                            bundle.missing_required_artifacts
                        ),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsRecordValidationArtifactBundleResult(
            bundle=bundle,
            hashed_count=hashed_count,
            evidence_node_id=evidence_node_id,
            notes=[
                "artifact bundle only; human review and promotion gates still decide finding status"
            ],
        )


def _normalize_artifacts(
    artifacts: list[WindowsValidationArtifact],
    *,
    hash_existing_paths: bool,
    require_existing_paths: bool,
) -> tuple[list[WindowsValidationArtifact], int]:
    out: list[WindowsValidationArtifact] = []
    hashed_count = 0
    for artifact in artifacts:
        updated = artifact.model_copy(deep=True)
        local_path = _local_existing_path(updated.path)
        updated.exists = local_path is not None
        if (
            hash_existing_paths
            and not updated.sha256
            and local_path is not None
            and local_path.is_file()
        ):
            updated.sha256 = _sha256_file(local_path)
            hashed_count += 1
        if require_existing_paths and local_path is None:
            updated.exists = False
        out.append(updated)
    return out, hashed_count


def _local_existing_path(path_text: str) -> Path | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    if path.exists():
        return path
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _missing_required_artifacts(
    artifacts: list[WindowsValidationArtifact],
    *,
    require_existing_paths: bool,
) -> list[str]:
    missing: list[str] = []
    for artifact in artifacts:
        if not artifact.required:
            continue
        prefix = artifact.kind
        if not artifact.path:
            missing.append(f"{prefix}: missing path")
        if not artifact.sha256:
            missing.append(f"{prefix}: missing sha256")
        if require_existing_paths and artifact.exists is not True:
            missing.append(f"{prefix}: local path does not exist")
    return _dedupe(missing)


def _runtime_blockers(
    args: WindowsRecordValidationArtifactBundleArgs,
    missing_required_artifacts: list[str],
) -> list[str]:
    blockers: list[str] = []
    if args.validation_plan is not None and args.validation_plan.candidate_id != args.candidate_id:
        blockers.append(
            "validation plan candidate_id does not match artifact bundle candidate_id"
        )
    if args.execution_status in {"not_run", "partial", "inconclusive"}:
        blockers.append(f"validation execution is not complete: {args.execution_status}")
    if missing_required_artifacts:
        blockers.append(
            "required runtime artifacts are incomplete: "
            + "; ".join(missing_required_artifacts[:8])
        )
    if not args.artifacts:
        blockers.append("no runtime artifacts were supplied")
    return _dedupe(blockers)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out


def build_tool() -> WindowsRecordValidationArtifactBundleTool:
    return WindowsRecordValidationArtifactBundleTool()
