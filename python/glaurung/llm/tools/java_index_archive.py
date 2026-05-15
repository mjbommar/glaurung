from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaIndexArchiveArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    max_classes: int = Field(256, ge=0)
    include_resources: bool = False
    max_resources: int = Field(256, ge=0)


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


class JavaIndexArchiveResult(BaseModel):
    archive_path: str
    archive_format: str
    sha256: str
    total_uncompressed_size: int
    class_count: int
    parsed_class_count: int
    parse_error_count: int
    resource_count: int
    manifest_main_class: str | None = None
    classes: list[JavaClassSummary]
    resources: list[JavaResourceSummary]
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
        class_count = 0
        parsed_class_count = 0
        parse_error_count = 0
        resource_count = 0
        total_uncompressed_size = 0
        manifest_main_class: str | None = None
        truncated = False
        java_analysis = getattr(g, "analysis")

        if not zipfile.is_zipfile(path):
            return JavaIndexArchiveResult(
                archive_path=str(path),
                archive_format="not_zip",
                sha256=digest,
                total_uncompressed_size=path.stat().st_size,
                class_count=0,
                parsed_class_count=0,
                parse_error_count=1,
                resource_count=0,
                manifest_main_class=None,
                classes=[],
                resources=[],
                truncated=False,
            )

        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            total_uncompressed_size = sum(info.file_size for info in infos)
            manifest_main_class = _manifest_main_class(zf)
            for info in infos:
                if info.is_dir():
                    continue
                if info.filename.endswith(".class"):
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
                    "class_count": class_count,
                    "resource_count": resource_count,
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
            total_uncompressed_size=total_uncompressed_size,
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            parse_error_count=parse_error_count,
            resource_count=resource_count,
            manifest_main_class=manifest_main_class,
            classes=classes,
            resources=resources,
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


def build_tool() -> MemoryTool[JavaIndexArchiveArgs, JavaIndexArchiveResult]:
    return JavaIndexArchiveTool()
