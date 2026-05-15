from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaIndexArchiveArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    max_entries: int = Field(4_096, ge=0)
    max_classes: int = Field(256, ge=0)
    include_resources: bool = False
    max_resources: int = Field(256, ge=0)
    include_nested_indexes: bool = False
    max_nested_archives: int = Field(16, ge=0)
    max_nested_archive_bytes: int = Field(64 * 1024 * 1024, ge=0)
    max_nested_entries: int = Field(4_096, ge=0)


class JavaClassSummary(BaseModel):
    entry_name: str
    class_name: str
    super_class: str
    major_version: int
    minor_version: int
    access_flags: int
    method_count: int
    field_count: int
    methods_with_code: int


class JavaResourceSummary(BaseModel):
    entry_name: str
    size: int


class JavaArchiveEntrySummary(BaseModel):
    entry_name: str
    compressed_size: int
    uncompressed_size: int
    compression_method: int
    crc32: int
    local_header_offset: int
    is_dir: bool
    is_class: bool
    is_resource: bool
    is_nested_archive: bool
    is_multi_release_class: bool
    multi_release_version: int | None = None
    is_signature_file: bool
    is_maven_metadata: bool
    is_service_descriptor: bool
    is_module_info: bool
    is_zip_slip: bool


class JavaNestedArchiveSummary(BaseModel):
    entry_name: str
    compressed_size: int
    uncompressed_size: int


class JavaNestedArchiveIndexSummary(BaseModel):
    entry_name: str
    sha256: str
    size: int
    entry_count: int
    class_count: int
    resource_count: int
    nested_archive_count: int
    multi_release_class_count: int
    multi_release_versions: list[int] = Field(default_factory=list)
    signed: bool
    signature_file_count: int
    maven_metadata_count: int
    service_descriptor_count: int
    module_info_present: bool
    zip_slip_entry_count: int
    truncated: bool


class JavaSkippedNestedArchiveSummary(BaseModel):
    entry_name: str
    size: int
    reason: str


class JavaSignatureFileSummary(BaseModel):
    entry_name: str
    size: int


class JavaMavenArtifactSummary(BaseModel):
    entry_name: str
    group_id: str | None = None
    artifact_id: str | None = None
    version: str | None = None


class JavaServiceDescriptorSummary(BaseModel):
    entry_name: str
    service_name: str
    providers: list[str]


class JavaSuspiciousEntrySummary(BaseModel):
    entry_name: str
    reason: str


class JavaIndexArchiveResult(BaseModel):
    archive_path: str
    archive_format: str
    sha256: str
    entry_count: int = 0
    total_uncompressed_size: int
    total_compressed_size: int = 0
    directory_count: int = 0
    class_count: int
    parsed_class_count: int
    parse_error_count: int
    resource_count: int
    manifest_main_class: str | None = None
    entries: list[JavaArchiveEntrySummary] = Field(default_factory=list)
    classes: list[JavaClassSummary]
    resources: list[JavaResourceSummary]
    nested_archive_count: int = 0
    nested_archives: list[JavaNestedArchiveSummary] = Field(default_factory=list)
    nested_archive_index_count: int = 0
    nested_archive_indexes: list[JavaNestedArchiveIndexSummary] = Field(
        default_factory=list
    )
    skipped_nested_archive_count: int = 0
    skipped_nested_archives: list[JavaSkippedNestedArchiveSummary] = Field(
        default_factory=list
    )
    multi_release_class_count: int = 0
    multi_release_versions: list[int] = Field(default_factory=list)
    signed: bool = False
    signature_file_count: int = 0
    signature_files: list[JavaSignatureFileSummary] = Field(default_factory=list)
    maven_artifact_count: int = 0
    maven_artifacts: list[JavaMavenArtifactSummary] = Field(default_factory=list)
    service_descriptor_count: int = 0
    service_descriptors: list[JavaServiceDescriptorSummary] = Field(
        default_factory=list
    )
    module_info_present: bool = False
    zip_slip_entry_count: int = 0
    suspicious_entries: list[JavaSuspiciousEntrySummary] = Field(default_factory=list)
    zip64_locator_present: bool = False
    truncated: bool = False


class JavaIndexArchiveTool(MemoryTool[JavaIndexArchiveArgs, JavaIndexArchiveResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_index_archive",
                description=(
                    "Index a Java JAR/ZIP archive: manifest, class summaries, "
                    "resource counts, classfile versions, and method body counts."
                ),
                tags=("java", "jar", "jvm", "kb"),
            ),
            JavaIndexArchiveArgs,
            JavaIndexArchiveResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaIndexArchiveArgs,
    ) -> JavaIndexArchiveResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        classes: list[JavaClassSummary] = []
        resources: list[JavaResourceSummary] = []
        entries: list[JavaArchiveEntrySummary] = []
        nested_archives: list[JavaNestedArchiveSummary] = []
        nested_archive_indexes: list[JavaNestedArchiveIndexSummary] = []
        skipped_nested_archives: list[JavaSkippedNestedArchiveSummary] = []
        signature_files: list[JavaSignatureFileSummary] = []
        maven_artifacts: list[JavaMavenArtifactSummary] = []
        service_descriptors: list[JavaServiceDescriptorSummary] = []
        suspicious_entries: list[JavaSuspiciousEntrySummary] = []
        class_count = 0
        parsed_class_count = 0
        parse_error_count = 0
        resource_count = 0
        entry_count = 0
        total_uncompressed_size = 0
        total_compressed_size = 0
        directory_count = 0
        nested_archive_count = 0
        multi_release_class_count = 0
        multi_release_versions: list[int] = []
        signed = False
        signature_file_count = 0
        maven_artifact_count = 0
        service_descriptor_count = 0
        module_info_present = False
        zip_slip_entry_count = 0
        zip64_locator_present = False
        manifest_main_class: str | None = None
        truncated = False
        java_analysis = getattr(g, "analysis")
        native_index = java_analysis.index_java_archive_path(
            str(path),
            max_entries=args.max_entries,
        )

        if not zipfile.is_zipfile(path):
            return JavaIndexArchiveResult(
                archive_path=str(path),
                archive_format="not_zip",
                sha256=digest,
                entry_count=0,
                total_uncompressed_size=path.stat().st_size,
                total_compressed_size=0,
                directory_count=0,
                class_count=0,
                parsed_class_count=0,
                parse_error_count=1,
                resource_count=0,
                manifest_main_class=None,
                entries=[],
                classes=[],
                resources=[],
                truncated=False,
            )
        if native_index is not None:
            entry_count = int(native_index["entry_count"])
            total_uncompressed_size = int(native_index["total_uncompressed_size"])
            total_compressed_size = int(native_index["total_compressed_size"])
            directory_count = int(native_index["directory_count"])
            class_count = int(native_index["class_count"])
            resource_count = int(native_index["resource_count"])
            nested_archive_count = int(native_index["nested_archive_count"])
            multi_release_class_count = int(native_index["multi_release_class_count"])
            multi_release_versions = [
                int(version) for version in native_index["multi_release_versions"]
            ]
            signature_file_count = int(native_index["signature_file_count"])
            signed = bool(native_index["signed"])
            maven_artifact_count = int(native_index["maven_metadata_count"])
            service_descriptor_count = int(native_index["service_descriptor_count"])
            module_info_present = bool(native_index["module_info_present"])
            zip_slip_entry_count = int(native_index["zip_slip_entry_count"])
            zip64_locator_present = bool(native_index["zip64_locator_present"])
            truncated = bool(native_index["truncated"])
            entries = [
                JavaArchiveEntrySummary(**entry)
                for entry in native_index["entries"]
                if isinstance(entry, dict)
            ]
            nested_archives = [
                JavaNestedArchiveSummary(
                    entry_name=entry.entry_name,
                    compressed_size=entry.compressed_size,
                    uncompressed_size=entry.uncompressed_size,
                )
                for entry in entries
                if entry.is_nested_archive
            ]
            signature_files = [
                JavaSignatureFileSummary(
                    entry_name=entry.entry_name,
                    size=entry.uncompressed_size,
                )
                for entry in entries
                if entry.is_signature_file
            ]
            suspicious_entries = [
                JavaSuspiciousEntrySummary(
                    entry_name=entry.entry_name,
                    reason="zip_slip_path",
                )
                for entry in entries
                if entry.is_zip_slip
            ]

        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if native_index is None:
                entry_count = len(infos)
                total_uncompressed_size = sum(info.file_size for info in infos)
            manifest_main_class = _manifest_main_class(zf)
            maven_artifacts = _maven_artifacts(zf, entries)
            service_descriptors = _service_descriptors(zf, entries)
            if args.include_nested_indexes:
                nested_archive_indexes, skipped_nested_archives = (
                    _nested_archive_indexes(
                        zf=zf,
                        java_analysis=java_analysis,
                        max_nested_archives=args.max_nested_archives,
                        max_nested_archive_bytes=args.max_nested_archive_bytes,
                        max_nested_entries=args.max_nested_entries,
                    )
                )
            for info in infos:
                if info.is_dir():
                    continue
                if info.filename.endswith(".class"):
                    if native_index is None:
                        class_count += 1
                    if len(classes) >= args.max_classes:
                        truncated = True
                        continue
                    parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                    if parsed is None:
                        parse_error_count += 1
                        continue
                    methods = parsed["methods"]
                    summary = JavaClassSummary(
                        entry_name=info.filename,
                        class_name=parsed["class_name"],
                        super_class=parsed["super_class"],
                        major_version=parsed["major_version"],
                        minor_version=parsed["minor_version"],
                        access_flags=parsed["access_flags"],
                        method_count=len(methods),
                        field_count=len(parsed["fields"]),
                        methods_with_code=sum(
                            1 for m in methods if m["code"] is not None
                        ),
                    )
                    parsed_class_count += 1
                    classes.append(summary)
                else:
                    if native_index is None:
                        resource_count += 1
                    if args.include_resources and len(resources) < args.max_resources:
                        resources.append(
                            JavaResourceSummary(
                                entry_name=info.filename,
                                size=info.file_size,
                            )
                        )
                    elif args.include_resources:
                        truncated = True

        archive_node = kb.add_node(
            Node(
                kind=NodeKind.java_archive,
                label=path.name,
                props={
                    "path": str(path),
                    "sha256": digest,
                    "entry_count": entry_count,
                    "class_count": class_count,
                    "resource_count": resource_count,
                    "nested_archive_count": nested_archive_count,
                    "nested_archive_index_count": len(nested_archive_indexes),
                    "skipped_nested_archive_count": len(skipped_nested_archives),
                    "multi_release_versions": multi_release_versions,
                    "signed": signed,
                    "maven_artifact_count": maven_artifact_count,
                    "service_descriptor_count": service_descriptor_count,
                    "module_info_present": module_info_present,
                    "zip_slip_entry_count": zip_slip_entry_count,
                    "manifest_main_class": manifest_main_class,
                },
                tags=["java", "jar"],
            )
        )
        for cls in classes:
            class_node = kb.add_node(
                Node(
                    kind=NodeKind.java_class,
                    label=cls.class_name,
                    props=cls.model_dump(),
                    tags=["java", "class"],
                )
            )
            kb.add_edge(Edge(src=archive_node.id, dst=class_node.id, kind="contains"))
        for resource in resources:
            resource_node = kb.add_node(
                Node(
                    kind=NodeKind.java_resource,
                    label=resource.entry_name,
                    props=resource.model_dump(),
                    tags=["java", "resource"],
                )
            )
            kb.add_edge(
                Edge(src=archive_node.id, dst=resource_node.id, kind="contains")
            )

        return JavaIndexArchiveResult(
            archive_path=str(path),
            archive_format="jar",
            sha256=digest,
            entry_count=entry_count,
            total_uncompressed_size=total_uncompressed_size,
            total_compressed_size=total_compressed_size,
            directory_count=directory_count,
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            parse_error_count=parse_error_count,
            resource_count=resource_count,
            manifest_main_class=manifest_main_class,
            entries=entries,
            classes=classes,
            resources=resources,
            nested_archive_count=nested_archive_count,
            nested_archives=nested_archives,
            nested_archive_index_count=len(nested_archive_indexes),
            nested_archive_indexes=nested_archive_indexes,
            skipped_nested_archive_count=len(skipped_nested_archives),
            skipped_nested_archives=skipped_nested_archives,
            multi_release_class_count=multi_release_class_count,
            multi_release_versions=multi_release_versions,
            signed=signed,
            signature_file_count=signature_file_count,
            signature_files=signature_files,
            maven_artifact_count=maven_artifact_count,
            maven_artifacts=maven_artifacts,
            service_descriptor_count=service_descriptor_count,
            service_descriptors=service_descriptors,
            module_info_present=module_info_present,
            zip_slip_entry_count=zip_slip_entry_count,
            suspicious_entries=suspicious_entries,
            zip64_locator_present=zip64_locator_present,
            truncated=truncated,
        )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _manifest_main_class(zf: zipfile.ZipFile) -> str | None:
    try:
        raw = zf.read("META-INF/MANIFEST.MF")
    except KeyError:
        return None
    text = raw.decode("utf-8", errors="replace")
    attrs = _parse_manifest(text)
    return attrs.get("Main-Class")


def _nested_archive_indexes(
    *,
    zf: zipfile.ZipFile,
    java_analysis: Any,
    max_nested_archives: int,
    max_nested_archive_bytes: int,
    max_nested_entries: int,
) -> tuple[list[JavaNestedArchiveIndexSummary], list[JavaSkippedNestedArchiveSummary]]:
    indexes: list[JavaNestedArchiveIndexSummary] = []
    skipped: list[JavaSkippedNestedArchiveSummary] = []
    for info in zf.infolist():
        if info.is_dir() or not _is_nested_archive_name(info.filename):
            continue
        if len(indexes) >= max_nested_archives:
            skipped.append(
                JavaSkippedNestedArchiveSummary(
                    entry_name=info.filename,
                    size=info.file_size,
                    reason="nested_archive_budget_exhausted",
                )
            )
            continue
        if info.file_size > max_nested_archive_bytes:
            skipped.append(
                JavaSkippedNestedArchiveSummary(
                    entry_name=info.filename,
                    size=info.file_size,
                    reason="nested_archive_too_large",
                )
            )
            continue
        try:
            data = zf.read(info)
        except (KeyError, RuntimeError, zipfile.BadZipFile):
            skipped.append(
                JavaSkippedNestedArchiveSummary(
                    entry_name=info.filename,
                    size=info.file_size,
                    reason="nested_archive_read_error",
                )
            )
            continue
        nested_index = java_analysis.index_java_archive_bytes(
            data,
            max_entries=max_nested_entries,
        )
        if nested_index is None:
            skipped.append(
                JavaSkippedNestedArchiveSummary(
                    entry_name=info.filename,
                    size=info.file_size,
                    reason="nested_archive_not_zip",
                )
            )
            continue
        indexes.append(
            JavaNestedArchiveIndexSummary(
                entry_name=info.filename,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                entry_count=int(nested_index["entry_count"]),
                class_count=int(nested_index["class_count"]),
                resource_count=int(nested_index["resource_count"]),
                nested_archive_count=int(nested_index["nested_archive_count"]),
                multi_release_class_count=int(
                    nested_index["multi_release_class_count"]
                ),
                multi_release_versions=[
                    int(version) for version in nested_index["multi_release_versions"]
                ],
                signed=bool(nested_index["signed"]),
                signature_file_count=int(nested_index["signature_file_count"]),
                maven_metadata_count=int(nested_index["maven_metadata_count"]),
                service_descriptor_count=int(nested_index["service_descriptor_count"]),
                module_info_present=bool(nested_index["module_info_present"]),
                zip_slip_entry_count=int(nested_index["zip_slip_entry_count"]),
                truncated=bool(nested_index["truncated"]),
            )
        )
    return indexes, skipped


def _is_nested_archive_name(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith((".jar", ".zip"))


def _maven_artifacts(
    zf: zipfile.ZipFile,
    entries: list[JavaArchiveEntrySummary],
) -> list[JavaMavenArtifactSummary]:
    out: list[JavaMavenArtifactSummary] = []
    for entry in entries:
        if not entry.is_maven_metadata:
            continue
        if entry.entry_name.endswith("/pom.properties"):
            try:
                raw = zf.read(entry.entry_name)
            except KeyError:
                raw = b""
            props = _parse_properties(raw.decode("utf-8", errors="replace"))
            out.append(
                JavaMavenArtifactSummary(
                    entry_name=entry.entry_name,
                    group_id=props.get("groupId"),
                    artifact_id=props.get("artifactId"),
                    version=props.get("version"),
                )
            )
        else:
            out.append(JavaMavenArtifactSummary(entry_name=entry.entry_name))
    return out


def _service_descriptors(
    zf: zipfile.ZipFile,
    entries: list[JavaArchiveEntrySummary],
) -> list[JavaServiceDescriptorSummary]:
    out: list[JavaServiceDescriptorSummary] = []
    for entry in entries:
        if not entry.is_service_descriptor:
            continue
        service_name = entry.entry_name.removeprefix("META-INF/services/")
        try:
            text = zf.read(entry.entry_name).decode("utf-8", errors="replace")
        except KeyError:
            text = ""
        providers = [
            line.split("#", 1)[0].strip()
            for line in text.splitlines()
            if line.split("#", 1)[0].strip()
        ]
        out.append(
            JavaServiceDescriptorSummary(
                entry_name=entry.entry_name,
                service_name=service_name,
                providers=providers,
            )
        )
    return out


def _parse_manifest(text: str) -> dict[str, str]:
    lines: list[str] = []
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw_line.startswith(" ") and lines:
            lines[-1] += raw_line[1:]
        elif raw_line:
            lines.append(raw_line)
    attrs: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep:
            attrs[key] = value.strip()
    return attrs


def _parse_properties(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


def build_tool() -> MemoryTool[JavaIndexArchiveArgs, JavaIndexArchiveResult]:
    return JavaIndexArchiveTool()
