from __future__ import annotations

import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import parse_proguard_mappings


class JavaAnnotateMappingsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    mapping_path: str | None = Field(
        None,
        description="Path to a ProGuard/Mojang mapping file",
    )
    max_classes: int = Field(20_000, ge=0)
    max_examples: int = Field(32, ge=0, le=256)


class JavaMappedClassSummary(BaseModel):
    entry_name: str
    class_name: str
    mapped_class_name: str | None
    field_mapping_count: int = 0
    method_mapping_count: int = 0


class JavaAnnotateMappingsResult(BaseModel):
    archive_path: str
    mapping_path: str
    mapping_format: str
    class_count: int
    parsed_class_count: int
    mapped_class_count: int
    parsed_field_count: int
    mapped_field_count: int
    parsed_method_count: int
    mapped_method_count: int
    truncated: bool
    classes: list[JavaMappedClassSummary]
    note_node_id: str | None = None


class JavaAnnotateMappingsTool(
    MemoryTool[JavaAnnotateMappingsArgs, JavaAnnotateMappingsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_annotate_mappings",
                description=(
                    "Apply ProGuard/Mojang class mappings as KB annotations for "
                    "obfuscated Java archives."
                ),
                tags=("java", "mapping", "deobfuscation", "annotation", "kb"),
            ),
            JavaAnnotateMappingsArgs,
            JavaAnnotateMappingsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaAnnotateMappingsArgs,
    ) -> JavaAnnotateMappingsResult:
        archive_path = Path(args.path or ctx.file_path)
        if args.mapping_path is None:
            return JavaAnnotateMappingsResult(
                archive_path=str(archive_path),
                mapping_path="",
                mapping_format="proguard",
                class_count=0,
                parsed_class_count=0,
                mapped_class_count=0,
                parsed_field_count=0,
                mapped_field_count=0,
                parsed_method_count=0,
                mapped_method_count=0,
                truncated=False,
                classes=[],
                note_node_id=None,
            )

        mapping_path = Path(args.mapping_path)
        mappings = parse_proguard_mappings(mapping_path)
        java_analysis = getattr(g, "analysis")
        classes: list[JavaMappedClassSummary] = []
        class_count = 0
        parsed_class_count = 0
        mapped_class_count = 0
        parsed_field_count = 0
        mapped_field_count = 0
        parsed_method_count = 0
        mapped_method_count = 0
        truncated = False

        if not zipfile.is_zipfile(archive_path):
            return JavaAnnotateMappingsResult(
                archive_path=str(archive_path),
                mapping_path=str(mapping_path),
                mapping_format="proguard",
                class_count=0,
                parsed_class_count=0,
                mapped_class_count=0,
                parsed_field_count=0,
                mapped_field_count=0,
                parsed_method_count=0,
                mapped_method_count=0,
                truncated=False,
                classes=[],
                note_node_id=None,
            )

        with zipfile.ZipFile(archive_path) as zf:
            class_entries = [
                info for info in zf.infolist() if info.filename.endswith(".class")
            ]
            class_count = len(class_entries)
            for info in class_entries[: args.max_classes]:
                parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                if parsed is None:
                    continue
                parsed_class_count += 1
                class_name = str(parsed["class_name"])
                class_mapping, _ = mappings.lookup_class(class_name)
                mapped_class_name = (
                    class_mapping.official_name if class_mapping is not None else None
                )
                if mapped_class_name is not None:
                    mapped_class_count += 1
                fields = parsed["fields"]
                methods = parsed["methods"]
                parsed_field_count += len(fields)
                parsed_method_count += len(methods)
                field_mapping_count = 0
                method_mapping_count = 0
                if class_mapping is not None:
                    field_mapping_count = sum(
                        1
                        for field in fields
                        if mappings.matching_member_mappings(
                            class_mapping,
                            kind="field",
                            obfuscated_name=str(field["name"]),
                            descriptor=str(field["descriptor"]),
                        )
                    )
                    method_mapping_count = sum(
                        1
                        for method in methods
                        if method["name"] not in {"<init>", "<clinit>"}
                        and mappings.matching_member_mappings(
                            class_mapping,
                            kind="method",
                            obfuscated_name=str(method["name"]),
                            descriptor=str(method["descriptor"]),
                        )
                    )
                    mapped_field_count += field_mapping_count
                    mapped_method_count += method_mapping_count

                summary = JavaMappedClassSummary(
                    entry_name=info.filename,
                    class_name=class_name,
                    mapped_class_name=mapped_class_name,
                    field_mapping_count=field_mapping_count,
                    method_mapping_count=method_mapping_count,
                )
                if len(classes) < args.max_examples:
                    classes.append(summary)
                if mapped_class_name is not None:
                    kb.add_node(
                        Node(
                            kind=NodeKind.java_class,
                            label=mapped_class_name,
                            props={
                                "tool": "java_annotate_mappings",
                                "entry_name": info.filename,
                                "class_name": class_name,
                                "mapped_class_name": mapped_class_name,
                                "mapping_path": str(mapping_path),
                                "field_mapping_count": summary.field_mapping_count,
                                "method_mapping_count": summary.method_mapping_count,
                            },
                            tags=["java", "class", "mapping", "deobfuscated"],
                        )
                    )
            truncated = class_count > args.max_classes

        note = kb.add_node(
            Node(
                kind=NodeKind.note,
                label="Java mapping coverage",
                text=(
                    f"Applied ProGuard mappings to {archive_path.name}: "
                    f"{mapped_class_count}/{parsed_class_count} parsed classes mapped."
                ),
                props={
                    "tool": "java_annotate_mappings",
                    "archive_path": str(archive_path),
                    "mapping_path": str(mapping_path),
                    "class_count": class_count,
                    "parsed_class_count": parsed_class_count,
                    "mapped_class_count": mapped_class_count,
                    "parsed_field_count": parsed_field_count,
                    "mapped_field_count": mapped_field_count,
                    "parsed_method_count": parsed_method_count,
                    "mapped_method_count": mapped_method_count,
                    "truncated": truncated,
                },
                tags=["java", "mapping", "deobfuscation", "annotation"],
            )
        )
        return JavaAnnotateMappingsResult(
            archive_path=str(archive_path),
            mapping_path=str(mapping_path),
            mapping_format="proguard",
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            mapped_class_count=mapped_class_count,
            parsed_field_count=parsed_field_count,
            mapped_field_count=mapped_field_count,
            parsed_method_count=parsed_method_count,
            mapped_method_count=mapped_method_count,
            truncated=truncated,
            classes=classes,
            note_node_id=note.id,
        )


def build_tool() -> MemoryTool[JavaAnnotateMappingsArgs, JavaAnnotateMappingsResult]:
    return JavaAnnotateMappingsTool()
