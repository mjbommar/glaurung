"""Preflight checks for high-volume Windows target-pipeline runners."""

from __future__ import annotations

from pathlib import Path
import shlex
import shutil

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
from .windows_build_corpus import WindowsBuildCorpusArgs, WindowsBuildCorpusTool


REQUIRED_METADATA = (
    "pe-sinks.yaml",
    "pe-sources.yaml",
    "pe-gates.yaml",
    "pe-project-facts.yaml",
    "pe-validation-inventory.yaml",
    "pe-ghidra-delta.yaml",
)
OPTIONAL_METADATA = (
    "pe-vulnerability-seeds.yaml",
    "pe-operation-classification-backlog.yaml",
)


class WindowsHighVolumePreflightArgs(BaseModel):
    build_corpus_manifest: str
    corpus_root: str
    project_root: str
    metadata_root: str | None = Field(
        None,
        description=(
            "Directory containing ASB PE metadata files. Defaults to the build "
            "corpus manifest directory."
        ),
    )
    target_id: str | None = None
    filename: str | None = None
    surface: str | None = None
    priority: str | None = None
    binary_kind: str | None = None
    max_targets: int = Field(8, ge=1, le=256)
    max_matches_per_target: int = Field(4, ge=1, le=64)
    require_ghidra: bool = False
    analyze_headless_path: str | None = None
    require_bsim: bool = False
    bsim_path: str | None = None
    artifacts_dir: str = "artifacts/windows-target-pipeline/high-volume"
    add_to_kb: bool = False


class WindowsHighVolumePreflightTarget(BaseModel):
    target_id: str
    filename: str
    priority: str
    binary_kind: str
    surfaces: list[str] = Field(default_factory=list)
    scan_roles: list[str] = Field(default_factory=list)
    corpus_match_count: int = 0
    project_match_count: int = 0
    ready: bool = False
    blockers: list[str] = Field(default_factory=list)
    corpus_paths: list[str] = Field(default_factory=list)
    project_paths: list[str] = Field(default_factory=list)


class WindowsHighVolumePreflightMetadata(BaseModel):
    path: str
    required: bool
    exists: bool
    size_bytes: int | None = None


class WindowsHighVolumePreflightResult(BaseModel):
    claim_level: str = "high_volume_preflight_not_analysis"
    ready: bool
    target_count: int
    ready_target_count: int
    blocked_target_count: int
    metadata_ready: bool
    optional_metadata_ready: bool
    ghidra_ready: bool | None = None
    bsim_ready: bool | None = None
    build_corpus_manifest: str
    corpus_root: str
    project_root: str
    metadata_root: str
    targets: list[WindowsHighVolumePreflightTarget]
    metadata: list[WindowsHighVolumePreflightMetadata]
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    high_volume_command: str | None = None
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsHighVolumePreflightTool(
    MemoryTool[WindowsHighVolumePreflightArgs, WindowsHighVolumePreflightResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_high_volume_preflight",
                description=(
                    "Check whether a runner has the Windows corpus, cached "
                    ".glaurung projects, ASB metadata, and optional Ghidra/BSim "
                    "tools required for high-volume target-pipeline runs."
                ),
                tags=("windows", "pipeline", "preflight", "corpus", "ci"),
            ),
            WindowsHighVolumePreflightArgs,
            WindowsHighVolumePreflightResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsHighVolumePreflightArgs,
    ) -> WindowsHighVolumePreflightResult:
        manifest = Path(args.build_corpus_manifest).expanduser()
        corpus_root = Path(args.corpus_root).expanduser()
        project_root = Path(args.project_root).expanduser()
        metadata_root = (
            Path(args.metadata_root).expanduser()
            if args.metadata_root
            else manifest.parent
        )
        blockers: list[str] = []
        warnings: list[str] = []
        for path, label in (
            (manifest, "build corpus manifest"),
            (corpus_root, "corpus root"),
            (project_root, "project root"),
            (metadata_root, "metadata root"),
        ):
            if not path.exists():
                blockers.append(f"{label} missing: {path}")
        metadata = _metadata_status(metadata_root)
        blockers.extend(
            f"required metadata missing: {Path(item.path).name}"
            for item in metadata
            if item.required and not item.exists
        )
        warnings.extend(
            f"optional metadata missing: {Path(item.path).name}"
            for item in metadata
            if not item.required and not item.exists
        )
        ghidra_ready = _tool_ready(args.analyze_headless_path, "analyzeHeadless")
        if args.require_ghidra and not ghidra_ready:
            blockers.append("required Ghidra analyzeHeadless is not available")
        bsim_ready = _tool_ready(args.bsim_path, "bsim")
        if args.require_bsim and not bsim_ready:
            blockers.append("required BSim command is not available")

        targets: list[WindowsHighVolumePreflightTarget] = []
        if manifest.exists() and corpus_root.exists() and project_root.exists():
            corpus = WindowsBuildCorpusTool().run(
                ctx,
                kb,
                WindowsBuildCorpusArgs(
                    manifest_path=str(manifest),
                    corpus_root=str(corpus_root),
                    project_root=str(project_root),
                    target_id=args.target_id,
                    filename=args.filename,
                    surface=args.surface,
                    priority=args.priority,
                    binary_kind=args.binary_kind,
                    max_matches=args.max_matches_per_target,
                ),
            )
            targets = [_target_status(target) for target in corpus.targets[: args.max_targets]]
            for target in targets:
                blockers.extend(target.blockers)
        if not targets:
            blockers.append("no build-corpus targets matched the preflight filters")

        blockers = _dedupe(blockers)
        warnings = _dedupe(warnings)
        ready_targets = sum(1 for target in targets if target.ready)
        metadata_ready = all(item.exists for item in metadata if item.required)
        optional_ready = all(item.exists for item in metadata if not item.required)
        ready = (
            not blockers
            and bool(targets)
            and ready_targets == len(targets)
            and metadata_ready
            and (ghidra_ready or not args.require_ghidra)
            and (bsim_ready or not args.require_bsim)
        )
        command = _high_volume_command(args, manifest, corpus_root, project_root, metadata_root)
        notes = [
            "High-volume preflight checks runner readiness only; it does not run analysis.",
            "Optional metadata absence is a warning unless the target pipeline explicitly needs it.",
        ]
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_high_volume_preflight",
                    props={
                        "ready": ready,
                        "target_count": len(targets),
                        "ready_target_count": ready_targets,
                        "blocker_count": len(blockers),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
        return WindowsHighVolumePreflightResult(
            ready=ready,
            target_count=len(targets),
            ready_target_count=ready_targets,
            blocked_target_count=sum(1 for target in targets if not target.ready),
            metadata_ready=metadata_ready,
            optional_metadata_ready=optional_ready,
            ghidra_ready=ghidra_ready,
            bsim_ready=bsim_ready,
            build_corpus_manifest=str(manifest),
            corpus_root=str(corpus_root),
            project_root=str(project_root),
            metadata_root=str(metadata_root),
            targets=targets,
            metadata=metadata,
            blockers=blockers,
            warnings=warnings,
            high_volume_command=command,
            evidence_bundle=_evidence_bundle(
                ready=ready,
                targets=targets,
                metadata=metadata,
                blockers=blockers,
                warnings=warnings,
                command=command,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _metadata_status(root: Path) -> list[WindowsHighVolumePreflightMetadata]:
    out: list[WindowsHighVolumePreflightMetadata] = []
    for name in REQUIRED_METADATA:
        out.append(_metadata_item(root / name, required=True))
    for name in OPTIONAL_METADATA:
        out.append(_metadata_item(root / name, required=False))
    return out


def _metadata_item(path: Path, *, required: bool) -> WindowsHighVolumePreflightMetadata:
    exists = path.is_file()
    return WindowsHighVolumePreflightMetadata(
        path=str(path),
        required=required,
        exists=exists,
        size_bytes=path.stat().st_size if exists else None,
    )


def _tool_ready(path_text: str | None, executable: str) -> bool:
    if path_text:
        return Path(path_text).expanduser().is_file()
    return shutil.which(executable) is not None


def _target_status(target) -> WindowsHighVolumePreflightTarget:
    blockers: list[str] = []
    if not target.corpus_matches:
        blockers.append(f"corpus binary missing for target {target.id}")
    if not target.project_matches:
        blockers.append(f"project cache missing for target {target.id}")
    return WindowsHighVolumePreflightTarget(
        target_id=target.id,
        filename=target.filename,
        priority=target.priority,
        binary_kind=target.binary_kind,
        surfaces=list(target.surfaces),
        scan_roles=list(target.scan_roles),
        corpus_match_count=len(target.corpus_matches),
        project_match_count=len(target.project_matches),
        ready=not blockers,
        blockers=blockers,
        corpus_paths=[item.path for item in target.corpus_matches],
        project_paths=[item.path for item in target.project_matches],
    )


def _high_volume_command(
    args: WindowsHighVolumePreflightArgs,
    manifest: Path,
    corpus_root: Path,
    project_root: Path,
    metadata_root: Path,
) -> str:
    artifacts = args.artifacts_dir.rstrip("/")
    cmd = [
        "uv",
        "run",
        "glaurung",
        "windows",
        "target-pipeline",
        "--format",
        "json",
        "--build-corpus-manifest",
        str(manifest),
        "--corpus-root",
        str(corpus_root),
        "--project-root",
        str(project_root),
        "--sinks-path",
        str(metadata_root / "pe-sinks.yaml"),
        "--sources-path",
        str(metadata_root / "pe-sources.yaml"),
        "--gates-path",
        str(metadata_root / "pe-gates.yaml"),
        "--project-facts-path",
        str(metadata_root / "pe-project-facts.yaml"),
        "--validation-inventory-path",
        str(metadata_root / "pe-validation-inventory.yaml"),
        "--ghidra-delta-path",
        str(metadata_root / "pe-ghidra-delta.yaml"),
        "--vulnerability-seeds-path",
        str(metadata_root / "pe-vulnerability-seeds.yaml"),
        "--max-targets",
        str(args.max_targets),
        "--candidate-packets-export-path",
        f"{artifacts}/candidate-packets.json",
        "--evidence-operator-markdown-path",
        f"{artifacts}/evidence-review.md",
        "--evidence-export-manifest-path",
        f"{artifacts}/evidence-export.json",
        "--evidence-candidate-packets-export-path",
        f"{artifacts}/evidence-candidate-packets.json",
        "--pipeline-export-manifest-path",
        f"{artifacts}/pipeline-export.json",
        "--blocker-worklist-path",
        f"{artifacts}/blocker-worklist.json",
    ]
    if args.target_id:
        cmd.extend(["--target-id", args.target_id])
    if (metadata_root / "pe-operation-classification-backlog.yaml").is_file():
        cmd.extend(
            [
                "--operation-backlog-path",
                str(metadata_root / "pe-operation-classification-backlog.yaml"),
            ]
        )
    return " ".join(shlex.quote(part) for part in cmd)


def _evidence_bundle(
    *,
    ready: bool,
    targets: list[WindowsHighVolumePreflightTarget],
    metadata: list[WindowsHighVolumePreflightMetadata],
    blockers: list[str],
    warnings: list[str],
    command: str,
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "preflight_ready": ready,
                "target_count": len(targets),
                "ready_target_count": sum(1 for target in targets if target.ready),
                "metadata_count": len(metadata),
                "warning_count": len(warnings),
            },
        ),
        source_tools=["windows_high_volume_preflight"],
        tool_sequence=["windows_high_volume_preflight"],
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_high_volume_preflight",
                summary=(
                    f"preflight ready={ready} targets={len(targets)} "
                    f"blockers={len(blockers)}"
                ),
                reason_codes=[
                    "high_volume_preflight_not_analysis",
                    "ready" if ready else "blocked",
                ],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[
                item.path for item in metadata if item.required and item.exists
            ],
            missing_facts=[
                item.path for item in metadata if item.required and not item.exists
            ],
            stale_or_blocking_facts=blockers,
            validation_ready=ready,
        ),
        reason_codes=["high_volume_preflight_not_analysis"],
        blockers=blockers,
        next_actions=[command] if not ready else [],
        notes=notes,
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsHighVolumePreflightTool:
    return WindowsHighVolumePreflightTool()
