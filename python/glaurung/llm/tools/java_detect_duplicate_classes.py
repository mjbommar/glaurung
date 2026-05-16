from __future__ import annotations

import hashlib
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaDetectDuplicateClassesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_filter: str | None = Field(None, description="Optional class substring")
    include_identical: bool = True
    include_multi_release: bool = True
    max_classes_scan: int = Field(100_000, ge=1)
    limit: int = Field(256, ge=0)


class JavaDuplicateClassEntry(BaseModel):
    entry_name: str
    version: int | None = None
    size: int
    sha256: str


class JavaDuplicateClassSummary(BaseModel):
    class_name: str
    dotted_class_name: str
    entry_count: int
    hash_count: int
    same_hash: bool
    divergent_hashes: bool
    multi_release_only: bool
    entries: list[JavaDuplicateClassEntry] = Field(default_factory=list)


class JavaDetectDuplicateClassesResult(BaseModel):
    archive_path: str
    class_count_scanned: int = 0
    duplicate_class_count: int = 0
    identical_duplicate_count: int = 0
    divergent_duplicate_count: int = 0
    multi_release_duplicate_count: int = 0
    duplicates: list[JavaDuplicateClassSummary] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaDetectDuplicateClassesTool(
    MemoryTool[JavaDetectDuplicateClassesArgs, JavaDetectDuplicateClassesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_detect_duplicate_classes",
                description=(
                    "Detect duplicate class definitions in a Java archive, including "
                    "multi-release variants and same/different byte hashes."
                ),
                tags=("java", "jar", "duplicate", "multi-release", "kb"),
            ),
            JavaDetectDuplicateClassesArgs,
            JavaDetectDuplicateClassesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDetectDuplicateClassesArgs,
    ) -> JavaDetectDuplicateClassesResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaDetectDuplicateClassesResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )
        java_analysis = getattr(g, "analysis")
        grouped: dict[str, list[JavaDuplicateClassEntry]] = defaultdict(list)
        result = JavaDetectDuplicateClassesResult(archive_path=str(archive_path))
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".class"):
                    continue
                result.class_count_scanned += 1
                if result.class_count_scanned > args.max_classes_scan:
                    result.truncated = True
                    result.stop_reasons.append("max_classes_scan")
                    break
                data = zf.read(info)
                class_name = _class_name(info.filename, data, java_analysis)
                if args.class_filter and args.class_filter not in class_name.replace(
                    "/", "."
                ):
                    continue
                grouped[class_name].append(
                    JavaDuplicateClassEntry(
                        entry_name=info.filename,
                        version=_multi_release_version(info.filename),
                        size=info.file_size,
                        sha256=hashlib.sha256(data).hexdigest(),
                    )
                )

        summaries = [_summary(name, entries) for name, entries in grouped.items()]
        summaries = [summary for summary in summaries if summary.entry_count > 1]
        if not args.include_identical:
            summaries = [summary for summary in summaries if summary.divergent_hashes]
        if not args.include_multi_release:
            summaries = [
                summary for summary in summaries if not summary.multi_release_only
            ]
        summaries.sort(
            key=lambda summary: (
                not summary.divergent_hashes,
                -summary.entry_count,
                summary.class_name,
            )
        )
        result.duplicate_class_count = len(summaries)
        result.identical_duplicate_count = sum(
            1 for item in summaries if item.same_hash
        )
        result.divergent_duplicate_count = sum(
            1 for item in summaries if item.divergent_hashes
        )
        result.multi_release_duplicate_count = sum(
            1 for item in summaries if item.multi_release_only
        )
        if len(summaries) > args.limit:
            result.truncated = True
            result.stop_reasons.append("limit")
        result.duplicates = summaries[: args.limit]
        for summary in result.duplicates:
            _add_duplicate_node(kb, archive_path, summary)
        return result


def _class_name(entry_name: str, data: bytes, java_analysis: Any) -> str:
    parsed = java_analysis.parse_java_class_bytes(data)
    if isinstance(parsed, dict) and isinstance(parsed.get("class_name"), str):
        return parsed["class_name"]
    normalized = _strip_multi_release_prefix(entry_name).removesuffix(".class")
    return normalized


def _summary(
    class_name: str,
    entries: list[JavaDuplicateClassEntry],
) -> JavaDuplicateClassSummary:
    hashes = {entry.sha256 for entry in entries}
    has_base = any(entry.version is None for entry in entries)
    has_versioned = any(entry.version is not None for entry in entries)
    return JavaDuplicateClassSummary(
        class_name=class_name,
        dotted_class_name=class_name.replace("/", "."),
        entry_count=len(entries),
        hash_count=len(hashes),
        same_hash=len(hashes) == 1,
        divergent_hashes=len(hashes) > 1,
        multi_release_only=has_base and has_versioned and len(entries) == 2,
        entries=sorted(
            entries,
            key=lambda entry: (
                entry.version if entry.version is not None else -1,
                entry.entry_name,
            ),
        ),
    )


def _multi_release_version(entry_name: str) -> int | None:
    parts = entry_name.split("/")
    if len(parts) >= 4 and parts[0] == "META-INF" and parts[1] == "versions":
        try:
            return int(parts[2])
        except ValueError:
            return None
    return None


def _strip_multi_release_prefix(entry_name: str) -> str:
    version = _multi_release_version(entry_name)
    if version is None:
        return entry_name
    return "/".join(entry_name.split("/")[3:])


def _add_duplicate_node(
    kb: KnowledgeBase,
    archive_path: Path,
    summary: JavaDuplicateClassSummary,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_class,
            label=summary.dotted_class_name,
            props={
                "tool": "java_detect_duplicate_classes",
                "archive_path": str(archive_path),
                **summary.model_dump(),
            },
            tags=["java", "duplicate_class"],
        )
    )


def build_tool() -> MemoryTool[
    JavaDetectDuplicateClassesArgs, JavaDetectDuplicateClassesResult
]:
    return JavaDetectDuplicateClassesTool()
