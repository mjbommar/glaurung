from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_xrefs_common import JavaXrefRecord, JavaXrefScanResult, scan_xrefs


class JavaXrefsFromArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_name: str | None = Field(
        None,
        description="Optional source class name, internal or dotted",
    )
    method_name: str | None = None
    method_descriptor: str | None = None
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscation",
    )
    kind: str | None = Field(None, description="Optional xref kind filter")
    max_classes: int = Field(50_000, ge=0)
    max_xrefs: int = Field(512, ge=0)


class JavaXrefsFromResult(JavaXrefScanResult):
    method_found: bool = False


class JavaXrefsFromTool(MemoryTool[JavaXrefsFromArgs, JavaXrefsFromResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_xrefs_from",
                description=(
                    "List normalized bytecode xrefs emitted by a Java class or "
                    "method, including source method, BCI, line anchor, target owner, "
                    "name, descriptor, and xref kind."
                ),
                tags=("java", "xref", "bytecode", "kb"),
            ),
            JavaXrefsFromArgs,
            JavaXrefsFromResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaXrefsFromArgs,
    ) -> JavaXrefsFromResult:
        path = Path(args.path or ctx.file_path)
        result = scan_xrefs(
            archive_path=path,
            kb=kb,
            tool_name=self.meta.name,
            source_class_name=args.class_name,
            source_method_name=args.method_name,
            source_method_descriptor=args.method_descriptor,
            mapping_path=Path(args.mapping_path)
            if args.mapping_path is not None
            else None,
            kind=args.kind,
            max_classes=args.max_classes,
            max_xrefs=args.max_xrefs,
        )
        method_found = _method_found(
            result.xrefs,
            method_name=args.method_name,
            method_descriptor=args.method_descriptor,
        )
        return JavaXrefsFromResult(
            **result.model_dump(),
            method_found=method_found,
        )


def _method_found(
    xrefs: list[JavaXrefRecord],
    *,
    method_name: str | None,
    method_descriptor: str | None,
) -> bool:
    if method_name is None and method_descriptor is None:
        return bool(xrefs)
    return any(
        (
            method_name is None
            or xref.source_method_name == method_name
            or method_name in xref.mapped_source_method_names
        )
        and (
            method_descriptor is None
            or xref.source_method_descriptor == method_descriptor
            or method_descriptor in xref.mapped_source_method_descriptors
        )
        for xref in xrefs
    )


def build_tool() -> MemoryTool[JavaXrefsFromArgs, JavaXrefsFromResult]:
    return JavaXrefsFromTool()
