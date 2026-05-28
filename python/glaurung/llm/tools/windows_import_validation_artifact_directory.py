from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_vm_validation_plan import WindowsVmValidationPlan
from .windows_record_validation_artifact_bundle import (
    WindowsValidationArtifact,
    WindowsValidationArtifactBundle,
    WindowsValidationArtifactKind,
    WindowsValidationExecutionStatus,
)


class WindowsImportValidationArtifactDirectoryArgs(BaseModel):
    candidate_id: str = Field(
        ...,
        description="Candidate id associated with the harness output directory.",
    )
    artifact_dir: str = Field(
        ...,
        description="Local directory containing collected validation artifacts.",
    )
    validation_plan: WindowsVmValidationPlan | None = Field(
        None,
        description="Optional VM validation plan associated with these artifacts.",
    )
    execution_status: WindowsValidationExecutionStatus = Field(
        "executed",
        description="Observed validation execution outcome for the imported directory.",
    )
    required_kinds: list[WindowsValidationArtifactKind] = Field(
        default_factory=lambda: [
            "kdnet_attach_log",
            "harness_stdout",
            "harness_stderr",
            "binary_identity",
            "stock_transcript",
            "current_transcript",
        ],
        description="Artifact kinds required before the bundle is ready for review.",
    )
    max_files: int = Field(
        200,
        ge=1,
        le=2000,
        description="Maximum files to import from the artifact directory.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add the imported bundle as a KB evidence node.",
    )


class WindowsImportValidationArtifactDirectoryResult(BaseModel):
    bundle: WindowsValidationArtifactBundle
    artifact_dir: str
    imported_count: int
    skipped_count: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsImportValidationArtifactDirectoryTool(
    MemoryTool[
        WindowsImportValidationArtifactDirectoryArgs,
        WindowsImportValidationArtifactDirectoryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_import_validation_artifact_directory",
                description=(
                    "Import a Windows validation harness output directory as a "
                    "hashed runtime artifact bundle. Files are classified by "
                    "name/path into common validation artifact kinds. This does "
                    "not claim reproduction."
                ),
                tags=("windows", "pe", "validation", "artifact", "harness"),
            ),
            WindowsImportValidationArtifactDirectoryArgs,
            WindowsImportValidationArtifactDirectoryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsImportValidationArtifactDirectoryArgs,
    ) -> WindowsImportValidationArtifactDirectoryResult:
        root = Path(args.artifact_dir).expanduser()
        if not root.is_dir():
            raise ValueError(f"{root}: artifact_dir is not a directory")

        artifacts, skipped_count = _import_artifacts(root, args)
        missing_required = _missing_required_kinds(artifacts, args.required_kinds)
        runtime_blockers = _runtime_blockers(args, missing_required, artifacts)
        bundle = WindowsValidationArtifactBundle(
            candidate_id=args.candidate_id,
            validation_id=(
                args.validation_plan.validation_id if args.validation_plan is not None else None
            ),
            execution_status=args.execution_status,
            artifact_count=len(artifacts),
            artifacts=artifacts,
            missing_required_artifacts=missing_required,
            runtime_blockers=runtime_blockers,
            ready_for_review=not runtime_blockers,
            operator_notes=[
                f"imported from artifact directory {root}",
                "artifact kinds are filename/path heuristics; review before promotion",
            ],
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_import_validation_artifact_directory",
                    props={
                        "candidate_id": bundle.candidate_id,
                        "validation_id": bundle.validation_id,
                        "artifact_dir": str(root),
                        "imported_count": len(artifacts),
                        "skipped_count": skipped_count,
                        "ready_for_review": bundle.ready_for_review,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsImportValidationArtifactDirectoryResult(
            bundle=bundle,
            artifact_dir=str(root),
            imported_count=len(artifacts),
            skipped_count=skipped_count,
            evidence_node_id=evidence_node_id,
            notes=[
                "directory import only; human review and promotion gates still decide finding status"
            ],
        )


def _import_artifacts(
    root: Path,
    args: WindowsImportValidationArtifactDirectoryArgs,
) -> tuple[list[WindowsValidationArtifact], int]:
    artifacts: list[WindowsValidationArtifact] = []
    files = sorted(path for path in root.rglob("*") if path.is_file())
    skipped_count = max(0, len(files) - args.max_files)
    required = set(args.required_kinds)
    for path in files[: args.max_files]:
        kind = _classify_artifact(path, root)
        artifacts.append(
            WindowsValidationArtifact(
                kind=kind,
                path=str(path),
                sha256=_sha256_file(path),
                summary=_summary_for(path, root, kind),
                required=kind in required,
                exists=True,
            )
        )
    return artifacts, skipped_count


def _classify_artifact(path: Path, root: Path) -> WindowsValidationArtifactKind:
    rel = path.relative_to(root).as_posix().lower()
    name = path.name.lower()
    suffix = path.suffix.lower()
    if "kdnet" in rel or "windbg" in rel or "debugger" in rel:
        return "kdnet_attach_log"
    if "serial" in rel or "com1" in rel:
        return "serial_log"
    if suffix in {".dmp", ".mdmp"} or "memory.dmp" in rel or "crash" in rel:
        return "crash_dump"
    if suffix in {".png", ".ppm", ".jpg", ".jpeg"} or "screen" in rel:
        return "screenshot"
    if "pdb" in rel and "identity" in rel:
        return "pdb_identity"
    if "identity" in rel or "authenticode" in rel or "driverquery" in rel:
        return "binary_identity"
    if "stderr" in rel or name.endswith(".err") or "error" in rel:
        return "harness_stderr"
    if "stdout" in rel or name.endswith(".out"):
        return "harness_stdout"
    if _has_part(path, root, "stock"):
        return "stock_transcript"
    if _has_part(path, root, "current"):
        return "current_transcript"
    if "sha256" in rel or "manifest" in rel or "note" in rel or suffix in {".md", ".json"}:
        return "operator_note"
    if suffix in {".log", ".txt"}:
        return "harness_stdout"
    return "other"


def _has_part(path: Path, root: Path, part: str) -> bool:
    return any(piece.lower() == part for piece in path.relative_to(root).parts)


def _summary_for(path: Path, root: Path, kind: WindowsValidationArtifactKind) -> str:
    return f"{kind} imported from {path.relative_to(root).as_posix()}"


def _missing_required_kinds(
    artifacts: list[WindowsValidationArtifact],
    required_kinds: list[WindowsValidationArtifactKind],
) -> list[str]:
    present = {artifact.kind for artifact in artifacts}
    return [
        f"{kind}: no artifact of this required kind was imported"
        for kind in required_kinds
        if kind not in present
    ]


def _runtime_blockers(
    args: WindowsImportValidationArtifactDirectoryArgs,
    missing_required: list[str],
    artifacts: list[WindowsValidationArtifact],
) -> list[str]:
    blockers: list[str] = []
    if args.validation_plan is not None and args.validation_plan.candidate_id != args.candidate_id:
        blockers.append(
            "validation plan candidate_id does not match artifact directory candidate_id"
        )
    if args.execution_status in {"not_run", "partial", "inconclusive"}:
        blockers.append(f"validation execution is not complete: {args.execution_status}")
    if not artifacts:
        blockers.append("no runtime artifacts were imported")
    if missing_required:
        blockers.append(
            "required artifact kinds are missing: " + "; ".join(missing_required[:8])
        )
    return _dedupe(blockers)


def _sha256_file(path: Path) -> str:
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
            out.append(value)
            seen.add(value)
    return out


def build_tool() -> WindowsImportValidationArtifactDirectoryTool:
    return WindowsImportValidationArtifactDirectoryTool()
