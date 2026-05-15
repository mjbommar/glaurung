from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_detect_security_sensitive_behavior import (
    JavaSensitiveFinding,
    build_tool as build_sensitive_tool,
)
from .minecraft_detect_archive import build_tool as build_minecraft_tool


class JavaAuditArchiveSetArgs(BaseModel):
    paths: list[str] = Field(
        default_factory=list,
        description=(
            "JAR/ZIP files or directories to scan; defaults to the current artifact"
        ),
    )
    recursive: bool = True
    max_archives: int = Field(128, ge=0)
    max_classes_per_archive: int = Field(20_000, ge=0)
    max_findings_per_archive: int = Field(128, ge=0)
    max_top_findings_per_archive: int = Field(8, ge=0, le=64)
    include_minecraft_metadata: bool = True


class JavaAuditArchiveSummary(BaseModel):
    path: str
    sha256: str | None = None
    is_zip: bool
    is_minecraft: bool = False
    loader: str = "unknown"
    side: str = "unknown"
    minecraft_version: str | None = None
    finding_count: int = 0
    summary_by_category: dict[str, int] = Field(default_factory=dict)
    highest_severity: str = "none"
    top_findings: list[JavaSensitiveFinding] = Field(default_factory=list)
    error: str | None = None


class JavaAuditArchiveSetResult(BaseModel):
    roots: list[str]
    archive_count: int
    scanned_archive_count: int
    skipped_count: int
    finding_count: int
    summary_by_category: dict[str, int]
    highest_severity: str
    archives: list[JavaAuditArchiveSummary]
    truncated: bool = False
    note_node_id: str | None = None


class JavaAuditArchiveSetTool(
    MemoryTool[JavaAuditArchiveSetArgs, JavaAuditArchiveSetResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_audit_archive_set",
                description=(
                    "Scan a set of Java archives or directories of archives for "
                    "Minecraft metadata and security-sensitive Java API sinks."
                ),
                tags=("java", "jar", "audit", "minecraft", "security", "kb"),
            ),
            JavaAuditArchiveSetArgs,
            JavaAuditArchiveSetResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaAuditArchiveSetArgs,
    ) -> JavaAuditArchiveSetResult:
        roots = [str(Path(p)) for p in (args.paths or [ctx.file_path])]
        candidates = _archive_candidates(
            [Path(root) for root in roots],
            recursive=args.recursive,
        )
        archive_count = len(candidates)
        truncated = archive_count > args.max_archives
        summaries: list[JavaAuditArchiveSummary] = []
        scanned_archive_count = 0
        skipped_count = 0
        summary_by_category: dict[str, int] = {}
        highest_severity = "none"

        for archive_path in candidates[: args.max_archives]:
            summary = _scan_archive(
                ctx=ctx,
                kb=kb,
                archive_path=archive_path,
                max_classes=args.max_classes_per_archive,
                max_findings=args.max_findings_per_archive,
                max_top_findings=args.max_top_findings_per_archive,
                include_minecraft_metadata=args.include_minecraft_metadata,
            )
            summaries.append(summary)
            if summary.is_zip:
                scanned_archive_count += 1
            else:
                skipped_count += 1
            highest_severity = _max_severity(
                highest_severity,
                summary.highest_severity,
            )
            for category, count in summary.summary_by_category.items():
                summary_by_category[category] = (
                    summary_by_category.get(category, 0) + count
                )

        finding_count = sum(summary.finding_count for summary in summaries)
        note = kb.add_node(
            Node(
                kind=NodeKind.note,
                label="Java archive-set audit",
                text=(
                    f"Scanned {scanned_archive_count}/{archive_count} Java archive "
                    f"candidates; findings={finding_count}; "
                    f"highest_severity={highest_severity}."
                ),
                props={
                    "tool": "java_audit_archive_set",
                    "roots": roots,
                    "archive_count": archive_count,
                    "scanned_archive_count": scanned_archive_count,
                    "skipped_count": skipped_count,
                    "finding_count": finding_count,
                    "summary_by_category": summary_by_category,
                    "highest_severity": highest_severity,
                    "truncated": truncated,
                },
                tags=["java", "java-audit", "archive-set"],
            )
        )

        return JavaAuditArchiveSetResult(
            roots=roots,
            archive_count=archive_count,
            scanned_archive_count=scanned_archive_count,
            skipped_count=skipped_count,
            finding_count=finding_count,
            summary_by_category=summary_by_category,
            highest_severity=highest_severity,
            archives=summaries,
            truncated=truncated,
            note_node_id=note.id,
        )


def _archive_candidates(roots: list[Path], *, recursive: bool) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        if root.is_dir():
            iterator = root.rglob("*") if recursive else root.glob("*")
            candidates = [
                path
                for path in iterator
                if path.is_file() and path.suffix.lower() in {".jar", ".zip"}
            ]
        elif root.is_file():
            candidates = [root]
        else:
            candidates = []
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            out.append(candidate)
    return sorted(out)


def _scan_archive(
    *,
    ctx: MemoryContext,
    kb: KnowledgeBase,
    archive_path: Path,
    max_classes: int,
    max_findings: int,
    max_top_findings: int,
    include_minecraft_metadata: bool,
) -> JavaAuditArchiveSummary:
    is_zip = zipfile.is_zipfile(archive_path)
    if not is_zip:
        return JavaAuditArchiveSummary(
            path=str(archive_path),
            sha256=_sha256_or_none(archive_path),
            is_zip=False,
            error="Input is not a ZIP/JAR archive.",
        )

    minecraft = None
    if include_minecraft_metadata:
        minecraft_tool = build_minecraft_tool()
        minecraft = minecraft_tool.run(
            ctx,
            kb,
            minecraft_tool.input_model(path=str(archive_path)),
        )

    sensitive_tool = build_sensitive_tool()
    sensitive = sensitive_tool.run(
        ctx,
        kb,
        sensitive_tool.input_model(
            path=str(archive_path),
            max_classes=max_classes,
            max_findings=max_findings,
        ),
    )
    highest_severity = "none"
    for finding in sensitive.findings:
        highest_severity = _max_severity(highest_severity, finding.severity)

    return JavaAuditArchiveSummary(
        path=str(archive_path),
        sha256=sensitive.sha256,
        is_zip=True,
        is_minecraft=minecraft.is_minecraft if minecraft else False,
        loader=minecraft.loader if minecraft else "unknown",
        side=minecraft.side if minecraft else "unknown",
        minecraft_version=minecraft.minecraft_version if minecraft else None,
        finding_count=sensitive.finding_count,
        summary_by_category=sensitive.summary_by_category,
        highest_severity=highest_severity,
        top_findings=sensitive.findings[:max_top_findings],
    )


_SEVERITY_RANK = {
    "none": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _max_severity(left: str, right: str) -> str:
    return (
        left if _SEVERITY_RANK.get(left, 0) >= _SEVERITY_RANK.get(right, 0) else right
    )


def _sha256_or_none(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_tool() -> MemoryTool[JavaAuditArchiveSetArgs, JavaAuditArchiveSetResult]:
    return JavaAuditArchiveSetTool()
