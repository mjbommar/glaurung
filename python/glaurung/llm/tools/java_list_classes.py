from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)


class JavaListClassesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    package_prefix: str | None = Field(
        None,
        description="Optional package prefix in dotted, internal, or mapped namespace.",
    )
    name_filter: str | None = Field(
        None,
        description="Optional substring filter over internal, dotted, or mapped names.",
    )
    mapping_path: str | None = Field(
        None, description="Optional ProGuard/Mojang mapping file"
    )
    include_annotations: bool = False
    access_flags_all: int = Field(
        0,
        ge=0,
        description="Require all of these JVM access-flag bits to be present.",
    )
    access_flags_any: int = Field(
        0,
        ge=0,
        description="Require at least one of these JVM access-flag bits if nonzero.",
    )
    access_flags_none: int = Field(
        0,
        ge=0,
        description="Require none of these JVM access-flag bits to be present.",
    )
    max_classes_scan: int = Field(50_000, ge=1)
    limit: int = Field(256, ge=0)


class JavaListedClass(BaseModel):
    entry_name: str
    class_name: str
    dotted_class_name: str
    mapped_class_name: str | None = None
    package_name: str
    simple_name: str
    super_class: str
    source_file: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    interface_count: int = 0
    access_flags: int
    major_version: int
    minor_version: int
    method_count: int
    field_count: int
    methods_with_code: int
    annotation_descriptors: list[str] = Field(default_factory=list)


class JavaListClassesResult(BaseModel):
    archive_path: str
    class_count_scanned: int = 0
    matched_class_count: int = 0
    classes: list[JavaListedClass] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaListClassesTool(MemoryTool[JavaListClassesArgs, JavaListClassesResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_classes",
                description=(
                    "List classes from a Java archive with package/name/access-flag "
                    "filters, optional annotation descriptors, optional "
                    "ProGuard/Mojang mapped names, and KB evidence."
                ),
                tags=("java", "class", "jar", "mapping", "kb"),
            ),
            JavaListClassesArgs,
            JavaListClassesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListClassesArgs,
    ) -> JavaListClassesResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListClassesResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )
        mappings = (
            parse_proguard_mappings(Path(args.mapping_path))
            if args.mapping_path is not None
            else None
        )
        result = JavaListClassesResult(archive_path=str(archive_path))
        java_analysis = getattr(g, "analysis")
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".class"):
                    continue
                if info.filename.startswith("META-INF/versions/"):
                    continue
                result.class_count_scanned += 1
                if result.class_count_scanned > args.max_classes_scan:
                    result.truncated = True
                    result.stop_reasons.append("max_classes_scan")
                    break
                parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                if parsed is None:
                    continue
                class_mapping = _lookup_class_mapping(
                    mappings, str(parsed["class_name"])
                )
                summary = _class_summary(
                    entry_name=info.filename,
                    parsed=parsed,
                    class_mapping=class_mapping,
                    include_annotations=args.include_annotations,
                )
                if not _matches_filters(summary, args):
                    continue
                if len(result.classes) >= args.limit:
                    result.truncated = True
                    result.stop_reasons.append("limit")
                    break
                result.classes.append(summary)
                result.matched_class_count += 1
                _add_class_node(kb, archive_path, summary)
        result.stop_reasons = _dedupe(result.stop_reasons)
        return result


def _class_summary(
    *,
    entry_name: str,
    parsed: dict[str, Any],
    class_mapping: ProguardClassMapping | None,
    include_annotations: bool,
) -> JavaListedClass:
    class_name = str(parsed["class_name"])
    methods = [
        method for method in parsed.get("methods", []) if isinstance(method, dict)
    ]
    fields = [field for field in parsed.get("fields", []) if isinstance(field, dict)]
    interfaces = [
        str(interface)
        for interface in parsed.get("interfaces", [])
        if isinstance(interface, str)
    ]
    return JavaListedClass(
        entry_name=entry_name,
        class_name=class_name,
        dotted_class_name=_dotted(class_name),
        mapped_class_name=class_mapping.official_name if class_mapping else None,
        package_name=_package_name(class_name),
        simple_name=class_name.rsplit("/", 1)[-1],
        super_class=str(parsed.get("super_class") or ""),
        source_file=_optional_string(parsed.get("source_file")),
        interfaces=interfaces,
        interface_count=len(interfaces),
        access_flags=int(parsed.get("access_flags", 0)),
        major_version=int(parsed.get("major_version", 0)),
        minor_version=int(parsed.get("minor_version", 0)),
        method_count=len(methods),
        field_count=len(fields),
        methods_with_code=sum(
            1 for method in methods if isinstance(method.get("code"), dict)
        ),
        annotation_descriptors=_annotation_descriptors(parsed)
        if include_annotations
        else [],
    )


def _matches_filters(summary: JavaListedClass, args: JavaListClassesArgs) -> bool:
    if (
        args.access_flags_all
        and (summary.access_flags & args.access_flags_all) != args.access_flags_all
    ):
        return False
    if args.access_flags_any and summary.access_flags & args.access_flags_any == 0:
        return False
    if args.access_flags_none and summary.access_flags & args.access_flags_none != 0:
        return False
    if args.package_prefix and not _matches_package(summary, args.package_prefix):
        return False
    if args.name_filter and not _matches_name(summary, args.name_filter):
        return False
    return True


def _matches_package(summary: JavaListedClass, package_prefix: str) -> bool:
    normalized = package_prefix.replace("/", ".")
    candidates = {
        summary.package_name.replace("/", "."),
        summary.class_name.replace("/", "."),
        summary.dotted_class_name,
    }
    if summary.mapped_class_name:
        candidates.add(summary.mapped_class_name)
    return any(candidate.startswith(normalized) for candidate in candidates)


def _matches_name(summary: JavaListedClass, name_filter: str) -> bool:
    normalized = name_filter.replace("/", ".")
    candidates = {
        summary.class_name,
        summary.class_name.replace("/", "."),
        summary.dotted_class_name,
        summary.simple_name,
    }
    if summary.mapped_class_name:
        candidates.add(summary.mapped_class_name)
    return any(normalized in candidate.replace("/", ".") for candidate in candidates)


def _annotation_descriptors(parsed: dict[str, Any]) -> list[str]:
    annotations = parsed.get("annotations")
    if not isinstance(annotations, list):
        return []
    return [
        str(annotation.get("descriptor"))
        for annotation in annotations
        if isinstance(annotation, dict) and annotation.get("descriptor")
    ]


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _lookup_class_mapping(
    mappings: ProguardMappings | None,
    class_name: str,
) -> ProguardClassMapping | None:
    if mappings is None:
        return None
    class_mapping, _ = mappings.lookup_class(class_name)
    return class_mapping


def _add_class_node(
    kb: KnowledgeBase,
    archive_path: Path,
    summary: JavaListedClass,
) -> None:
    digest = hashlib.sha256(
        "|".join([str(archive_path), summary.class_name]).encode("utf-8")
    ).hexdigest()[:16]
    kb.add_node(
        Node(
            kind=NodeKind.java_class,
            label=summary.mapped_class_name or summary.dotted_class_name,
            props={
                "tool": "java_list_classes",
                "java_class_id": digest,
                "archive_path": str(archive_path),
                **summary.model_dump(),
            },
            tags=["java", "class", "mapping" if summary.mapped_class_name else "raw"],
        )
    )


def _package_name(class_name: str) -> str:
    package, sep, _ = class_name.rpartition("/")
    return package if sep else ""


def _dotted(class_name: str) -> str:
    return class_name.replace("/", ".")


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_tool() -> MemoryTool[JavaListClassesArgs, JavaListClassesResult]:
    return JavaListClassesTool()
