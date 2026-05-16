from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g
from glaurung.java_classfile_policy import classfile_policy

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_class_kind import JavaClassKind, class_kind


class JavaListPackagesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    package_prefix: str | None = Field(
        None,
        description="Optional package prefix in dotted or internal JVM form.",
    )
    include_resources: bool = Field(
        False,
        description="Include non-class resource counts and samples by archive directory.",
    )
    max_classes_scan: int = Field(50_000, ge=1)
    max_resources_scan: int = Field(50_000, ge=0)
    limit: int = Field(256, ge=0)
    classes_sample_limit: int = Field(8, ge=0)
    resources_sample_limit: int = Field(8, ge=0)


class JavaPackageSummary(BaseModel):
    package_name: str
    dotted_package_name: str
    class_count: int = 0
    public_class_count: int = 0
    interface_count: int = 0
    annotation_count: int = 0
    enum_count: int = 0
    record_count: int = 0
    sealed_count: int = 0
    module_count: int = 0
    method_count: int = 0
    field_count: int = 0
    methods_with_code: int = 0
    bootstrap_method_count: int = 0
    resource_count: int = 0
    classfile_bytes: int = 0
    resource_bytes: int = 0
    class_kinds: dict[JavaClassKind, int] = Field(default_factory=dict)
    major_versions: list[int] = Field(default_factory=list)
    java_releases: list[int] = Field(default_factory=list)
    java_release_labels: list[str] = Field(default_factory=list)
    classes_sample: list[str] = Field(default_factory=list)
    resources_sample: list[str] = Field(default_factory=list)


class JavaListPackagesResult(BaseModel):
    archive_path: str
    class_count_scanned: int = 0
    parsed_class_count: int = 0
    parse_error_count: int = 0
    resource_count_scanned: int = 0
    package_count: int = 0
    matched_package_count: int = 0
    packages: list[JavaPackageSummary] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


@dataclass
class _PackageAccumulator:
    package_name: str
    class_count: int = 0
    public_class_count: int = 0
    interface_count: int = 0
    annotation_count: int = 0
    enum_count: int = 0
    record_count: int = 0
    sealed_count: int = 0
    module_count: int = 0
    method_count: int = 0
    field_count: int = 0
    methods_with_code: int = 0
    bootstrap_method_count: int = 0
    resource_count: int = 0
    classfile_bytes: int = 0
    resource_bytes: int = 0
    class_kinds: dict[JavaClassKind, int] = field(default_factory=dict)
    major_versions: set[int] = field(default_factory=set)
    java_releases: set[int] = field(default_factory=set)
    java_release_labels: set[str] = field(default_factory=set)
    classes_sample: list[str] = field(default_factory=list)
    resources_sample: list[str] = field(default_factory=list)


class JavaListPackagesTool(MemoryTool[JavaListPackagesArgs, JavaListPackagesResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_packages",
                description=(
                    "Summarize Java archive packages with class kind counts, "
                    "method/field totals, classfile versions, optional resource "
                    "samples, and KB package evidence."
                ),
                tags=("java", "package", "jar", "kb"),
            ),
            JavaListPackagesArgs,
            JavaListPackagesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListPackagesArgs,
    ) -> JavaListPackagesResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListPackagesResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )

        result = JavaListPackagesResult(archive_path=str(archive_path))
        packages: dict[str, _PackageAccumulator] = {}
        java_analysis = getattr(g, "analysis")

        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.filename.endswith(".class"):
                    if info.filename.startswith("META-INF/versions/"):
                        continue
                    result.class_count_scanned += 1
                    if result.class_count_scanned > args.max_classes_scan:
                        result.truncated = True
                        result.stop_reasons.append("max_classes_scan")
                        break
                    parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                    if parsed is None:
                        result.parse_error_count += 1
                        continue
                    result.parsed_class_count += 1
                    _add_class(
                        packages,
                        parsed=parsed,
                        classfile_size=info.file_size,
                        classes_sample_limit=args.classes_sample_limit,
                    )
                    continue

                result.resource_count_scanned += 1
                if not args.include_resources:
                    continue
                if result.resource_count_scanned > args.max_resources_scan:
                    result.truncated = True
                    result.stop_reasons.append("max_resources_scan")
                    continue
                _add_resource(
                    packages,
                    entry_name=info.filename,
                    size=info.file_size,
                    resources_sample_limit=args.resources_sample_limit,
                )

        summaries = [
            _to_summary(package)
            for package in packages.values()
            if _matches_package(package.package_name, args.package_prefix)
        ]
        summaries.sort(
            key=lambda package: (
                -package.class_count,
                -package.resource_count,
                package.package_name,
            )
        )

        result.package_count = len(packages)
        result.matched_package_count = len(summaries)
        if len(summaries) > args.limit:
            result.truncated = True
            result.stop_reasons.append("limit")
        result.packages = summaries[: args.limit]
        result.stop_reasons = _dedupe(result.stop_reasons)
        _add_package_nodes(kb, archive_path, result.packages)
        return result


def _add_class(
    packages: dict[str, _PackageAccumulator],
    *,
    parsed: dict[str, Any],
    classfile_size: int,
    classes_sample_limit: int,
) -> None:
    class_name = str(parsed["class_name"])
    package = _package_name(class_name)
    acc = packages.setdefault(package, _PackageAccumulator(package_name=package))
    methods = [
        method for method in parsed.get("methods", []) if isinstance(method, dict)
    ]
    fields = [field for field in parsed.get("fields", []) if isinstance(field, dict)]
    kind = class_kind(
        class_name=class_name,
        access_flags=int(parsed.get("access_flags", 0)),
        super_class=_optional_string(parsed.get("super_class")),
        record_components=parsed.get("record_components"),
        module_info=parsed.get("module"),
    )
    policy = classfile_policy(
        int(parsed.get("major_version", 0)),
        int(parsed.get("minor_version", 0)),
        size_bytes=classfile_size,
    )

    acc.class_count += 1
    acc.public_class_count += 1 if int(parsed.get("access_flags", 0)) & 0x0001 else 0
    acc.interface_count += 1 if kind in {"interface", "annotation"} else 0
    acc.annotation_count += 1 if kind == "annotation" else 0
    acc.enum_count += 1 if kind == "enum" else 0
    acc.record_count += 1 if kind == "record" else 0
    acc.sealed_count += 1 if _list_count(parsed.get("permitted_subclasses")) > 0 else 0
    acc.module_count += 1 if kind == "module" else 0
    acc.method_count += len(methods)
    acc.field_count += len(fields)
    acc.methods_with_code += sum(
        1 for method in methods if isinstance(method.get("code"), dict)
    )
    acc.bootstrap_method_count += int(parsed.get("bootstrap_method_count", 0))
    acc.classfile_bytes += classfile_size
    acc.class_kinds[kind] = acc.class_kinds.get(kind, 0) + 1
    acc.major_versions.add(policy.major_version)
    if policy.java_release is not None:
        acc.java_releases.add(policy.java_release)
    if policy.java_release_label is not None:
        acc.java_release_labels.add(policy.java_release_label)
    if len(acc.classes_sample) < classes_sample_limit:
        acc.classes_sample.append(class_name)


def _add_resource(
    packages: dict[str, _PackageAccumulator],
    *,
    entry_name: str,
    size: int,
    resources_sample_limit: int,
) -> None:
    package = _resource_package_name(entry_name)
    acc = packages.setdefault(package, _PackageAccumulator(package_name=package))
    acc.resource_count += 1
    acc.resource_bytes += size
    if len(acc.resources_sample) < resources_sample_limit:
        acc.resources_sample.append(entry_name)


def _to_summary(acc: _PackageAccumulator) -> JavaPackageSummary:
    return JavaPackageSummary(
        package_name=acc.package_name,
        dotted_package_name=_dotted_package(acc.package_name),
        class_count=acc.class_count,
        public_class_count=acc.public_class_count,
        interface_count=acc.interface_count,
        annotation_count=acc.annotation_count,
        enum_count=acc.enum_count,
        record_count=acc.record_count,
        sealed_count=acc.sealed_count,
        module_count=acc.module_count,
        method_count=acc.method_count,
        field_count=acc.field_count,
        methods_with_code=acc.methods_with_code,
        bootstrap_method_count=acc.bootstrap_method_count,
        resource_count=acc.resource_count,
        classfile_bytes=acc.classfile_bytes,
        resource_bytes=acc.resource_bytes,
        class_kinds=dict(sorted(acc.class_kinds.items())),
        major_versions=sorted(acc.major_versions),
        java_releases=sorted(acc.java_releases),
        java_release_labels=sorted(acc.java_release_labels),
        classes_sample=acc.classes_sample,
        resources_sample=acc.resources_sample,
    )


def _add_package_nodes(
    kb: KnowledgeBase,
    archive_path: Path,
    packages: list[JavaPackageSummary],
) -> None:
    archive_node = kb.add_node(
        Node(
            kind=NodeKind.java_archive,
            label=archive_path.name,
            props={
                "tool": "java_list_packages",
                "archive_path": str(archive_path),
                "package_count": len(packages),
            },
            tags=["java", "jar", "package"],
        )
    )
    for summary in packages:
        digest = hashlib.sha256(
            "|".join([str(archive_path), summary.package_name]).encode("utf-8")
        ).hexdigest()[:16]
        package_node = kb.add_node(
            Node(
                kind=NodeKind.java_package,
                label=summary.dotted_package_name or "(default package)",
                props={
                    "tool": "java_list_packages",
                    "java_package_id": digest,
                    "archive_path": str(archive_path),
                    **summary.model_dump(),
                },
                tags=["java", "package"],
            )
        )
        kb.add_edge(
            Edge(
                src=archive_node.id,
                dst=package_node.id,
                kind="contains_package",
            )
        )


def _matches_package(package_name: str, package_prefix: str | None) -> bool:
    if not package_prefix:
        return True
    normalized = package_prefix.strip().replace(".", "/").strip("/")
    if normalized == "":
        return True
    return package_name == normalized or package_name.startswith(f"{normalized}/")


def _package_name(class_name: str) -> str:
    package, sep, _ = class_name.rpartition("/")
    return package if sep else ""


def _resource_package_name(entry_name: str) -> str:
    package, sep, _ = entry_name.rpartition("/")
    return package if sep else ""


def _dotted_package(package_name: str) -> str:
    return package_name.replace("/", ".")


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _list_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_tool() -> MemoryTool[JavaListPackagesArgs, JavaListPackagesResult]:
    return JavaListPackagesTool()
