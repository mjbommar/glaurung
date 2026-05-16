from __future__ import annotations

import hashlib
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


JavaAnnotationTargetKind = Literal[
    "class",
    "field",
    "method",
    "record_component",
    "package",
]


class JavaListAnnotationsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    descriptor_filter: str | None = Field(
        None,
        description="Optional substring filter over annotation descriptors.",
    )
    class_filter: str | None = Field(
        None,
        description="Optional substring filter over internal or dotted class names.",
    )
    include_members: bool = True
    max_classes_scan: int = Field(50_000, ge=1)
    limit: int = Field(512, ge=0)


class JavaAnnotationOccurrence(BaseModel):
    descriptor: str
    visibility: str
    target_kind: JavaAnnotationTargetKind
    class_name: str
    dotted_class_name: str
    source_file: str | None = None
    member_name: str | None = None
    member_descriptor: str | None = None
    record_component_name: str | None = None
    element_names: list[str] = Field(default_factory=list)


class JavaListAnnotationsResult(BaseModel):
    archive_path: str
    class_count_scanned: int = 0
    package_info_count: int = 0
    annotation_count_seen: int = 0
    matched_annotation_count: int = 0
    descriptor_counts: dict[str, int] = Field(default_factory=dict)
    annotations: list[JavaAnnotationOccurrence] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaListAnnotationsTool(
    MemoryTool[JavaListAnnotationsArgs, JavaListAnnotationsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_annotations",
                description=(
                    "List archive annotations on classes, fields, methods, record "
                    "components, and package-info classes with descriptor counts "
                    "and KB evidence."
                ),
                tags=("java", "annotation", "jar", "kb"),
            ),
            JavaListAnnotationsArgs,
            JavaListAnnotationsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListAnnotationsArgs,
    ) -> JavaListAnnotationsResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListAnnotationsResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )

        result = JavaListAnnotationsResult(archive_path=str(archive_path))
        descriptor_counts: Counter[str] = Counter()
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
                class_name = str(parsed["class_name"])
                if class_name.endswith("/package-info") or class_name == "package-info":
                    result.package_info_count += 1
                if not _matches_class_filter(class_name, args.class_filter):
                    continue
                for occurrence in _annotation_occurrences(parsed, args.include_members):
                    result.annotation_count_seen += 1
                    descriptor_counts[occurrence.descriptor] += 1
                    if not _matches_descriptor(
                        occurrence.descriptor,
                        args.descriptor_filter,
                    ):
                        continue
                    if len(result.annotations) >= args.limit:
                        result.truncated = True
                        result.stop_reasons.append("limit")
                        break
                    result.annotations.append(occurrence)
                    result.matched_annotation_count += 1
                    _add_annotation_node(kb, archive_path, occurrence)
                if result.truncated and "limit" in result.stop_reasons:
                    break

        result.descriptor_counts = dict(sorted(descriptor_counts.items()))
        result.stop_reasons = _dedupe(result.stop_reasons)
        return result


def _annotation_occurrences(
    parsed: dict[str, Any],
    include_members: bool,
) -> list[JavaAnnotationOccurrence]:
    class_name = str(parsed["class_name"])
    source_file = _optional_string(parsed.get("source_file"))
    target_kind: JavaAnnotationTargetKind = (
        "package"
        if class_name.endswith("/package-info") or class_name == "package-info"
        else "class"
    )
    out = [
        _occurrence(
            annotation,
            target_kind=target_kind,
            class_name=class_name,
            source_file=source_file,
        )
        for annotation in _annotations(parsed)
    ]
    if not include_members:
        return out

    for field in parsed.get("fields", []):
        if not isinstance(field, dict):
            continue
        for annotation in _annotations(field):
            out.append(
                _occurrence(
                    annotation,
                    target_kind="field",
                    class_name=class_name,
                    source_file=source_file,
                    member_name=_optional_string(field.get("name")),
                    member_descriptor=_optional_string(field.get("descriptor")),
                )
            )
    for method in parsed.get("methods", []):
        if not isinstance(method, dict):
            continue
        for annotation in _annotations(method):
            out.append(
                _occurrence(
                    annotation,
                    target_kind="method",
                    class_name=class_name,
                    source_file=source_file,
                    member_name=_optional_string(method.get("name")),
                    member_descriptor=_optional_string(method.get("descriptor")),
                )
            )
    for component in parsed.get("record_components", []):
        if not isinstance(component, dict):
            continue
        for annotation in _annotations(component):
            out.append(
                _occurrence(
                    annotation,
                    target_kind="record_component",
                    class_name=class_name,
                    source_file=source_file,
                    record_component_name=_optional_string(component.get("name")),
                )
            )
    return out


def _occurrence(
    annotation: dict[str, Any],
    *,
    target_kind: JavaAnnotationTargetKind,
    class_name: str,
    source_file: str | None,
    member_name: str | None = None,
    member_descriptor: str | None = None,
    record_component_name: str | None = None,
) -> JavaAnnotationOccurrence:
    return JavaAnnotationOccurrence(
        descriptor=str(annotation.get("descriptor") or ""),
        visibility=str(annotation.get("visibility") or ""),
        target_kind=target_kind,
        class_name=class_name,
        dotted_class_name=_dotted(class_name),
        source_file=source_file,
        member_name=member_name,
        member_descriptor=member_descriptor,
        record_component_name=record_component_name,
        element_names=_element_names(annotation),
    )


def _annotations(value: dict[str, Any]) -> list[dict[str, Any]]:
    annotations = value.get("annotations")
    if not isinstance(annotations, list):
        return []
    return [item for item in annotations if isinstance(item, dict)]


def _element_names(annotation: dict[str, Any]) -> list[str]:
    elements = annotation.get("elements")
    if not isinstance(elements, list):
        return []
    return [
        str(element.get("name"))
        for element in elements
        if isinstance(element, dict) and element.get("name")
    ]


def _matches_descriptor(descriptor: str, descriptor_filter: str | None) -> bool:
    return not descriptor_filter or descriptor_filter in descriptor


def _matches_class_filter(class_name: str, class_filter: str | None) -> bool:
    if not class_filter:
        return True
    needle = class_filter.replace("/", ".")
    return needle in class_name.replace("/", ".")


def _add_annotation_node(
    kb: KnowledgeBase,
    archive_path: Path,
    occurrence: JavaAnnotationOccurrence,
) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                str(archive_path),
                occurrence.descriptor,
                occurrence.target_kind,
                occurrence.class_name,
                occurrence.member_name or "",
                occurrence.member_descriptor or "",
                occurrence.record_component_name or "",
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    kb.add_node(
        Node(
            kind=NodeKind.java_annotation,
            label=f"{occurrence.descriptor} on {occurrence.dotted_class_name}",
            props={
                "tool": "java_list_annotations",
                "java_annotation_id": digest,
                "archive_path": str(archive_path),
                **occurrence.model_dump(),
            },
            tags=["java", "annotation", occurrence.target_kind],
        )
    )


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _dotted(class_name: str) -> str:
    return class_name.replace("/", ".")


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_tool() -> MemoryTool[JavaListAnnotationsArgs, JavaListAnnotationsResult]:
    return JavaListAnnotationsTool()
