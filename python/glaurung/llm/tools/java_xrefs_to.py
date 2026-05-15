from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_xrefs_common import JavaXrefScanResult, scan_xrefs


class JavaXrefsToArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    target_owner: str | None = Field(
        None,
        description="Target owner class name, internal or dotted",
    )
    target_name: str | None = None
    target_descriptor: str | None = None
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscation",
    )
    kind: str | None = Field(None, description="Optional xref kind filter")
    max_classes: int = Field(50_000, ge=0)
    max_xrefs: int = Field(512, ge=0)


class JavaXrefsToResult(JavaXrefScanResult):
    pass


class JavaXrefsToTool(MemoryTool[JavaXrefsToArgs, JavaXrefsToResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_xrefs_to",
                description=(
                    "Find normalized Java bytecode xrefs targeting a class, method, "
                    "field, descriptor, string, or xref kind across an archive."
                ),
                tags=("java", "xref", "bytecode", "kb"),
            ),
            JavaXrefsToArgs,
            JavaXrefsToResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaXrefsToArgs,
    ) -> JavaXrefsToResult:
        path = Path(args.path or ctx.file_path)
        result = scan_xrefs(
            archive_path=path,
            kb=kb,
            tool_name=self.meta.name,
            target_owner=args.target_owner,
            target_name=args.target_name,
            target_descriptor=args.target_descriptor,
            mapping_path=Path(args.mapping_path)
            if args.mapping_path is not None
            else None,
            kind=args.kind,
            max_classes=args.max_classes,
            max_xrefs=args.max_xrefs,
        )
        return JavaXrefsToResult(**result.model_dump())


def build_tool() -> MemoryTool[JavaXrefsToArgs, JavaXrefsToResult]:
    return JavaXrefsToTool()
