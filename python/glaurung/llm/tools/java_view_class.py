from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)


class JavaViewClassArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_name: str | None = Field(
        None,
        description="Class name in internal, dotted, obfuscated, or official namespace",
    )
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscation",
    )
    include_members: bool = True
    max_classes_scan: int = Field(50_000, ge=1)


class JavaCodeSummary(BaseModel):
    max_stack: int
    max_locals: int
    code_length: int
    exception_table_len: int
    attributes_count: int


class JavaClassMemberSummary(BaseModel):
    kind: Literal["field", "method"]
    name: str
    descriptor: str
    access_flags: int
    mapped_names: list[str] = Field(default_factory=list)
    mapped_signatures: list[str] = Field(default_factory=list)
    code: JavaCodeSummary | None = None


class JavaViewClassResult(BaseModel):
    archive_path: str
    class_found: bool
    matched_by: Literal["input", "official", "obfuscated", "none"]
    entry_name: str | None = None
    class_name: str | None = None
    dotted_class_name: str | None = None
    mapped_class_name: str | None = None
    super_class: str | None = None
    major_version: int | None = None
    minor_version: int | None = None
    access_flags: int | None = None
    fields: list[JavaClassMemberSummary] = Field(default_factory=list)
    methods: list[JavaClassMemberSummary] = Field(default_factory=list)
    class_node_id: str | None = None


class JavaViewClassTool(MemoryTool[JavaViewClassArgs, JavaViewClassResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_view_class",
                description=(
                    "View a class from a Java archive, optionally annotating class, "
                    "field, and method names with ProGuard/Mojang mappings."
                ),
                tags=("java", "class", "mapping", "deobfuscation", "annotation", "kb"),
            ),
            JavaViewClassArgs,
            JavaViewClassResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaViewClassArgs,
    ) -> JavaViewClassResult:
        archive_path = Path(args.path or ctx.file_path)
        class_mapping: ProguardClassMapping | None = None
        mappings: ProguardMappings | None = None
        matched_by: Literal["input", "official", "obfuscated", "none"] = "input"
        if args.class_name is None:
            return JavaViewClassResult(
                archive_path=str(archive_path),
                class_found=False,
                matched_by="none",
            )
        if args.mapping_path is not None:
            mappings = parse_proguard_mappings(Path(args.mapping_path))
            class_mapping, mapping_match = mappings.lookup_class(args.class_name)
            if mapping_match != "none":
                matched_by = mapping_match

        target_names = _candidate_class_names(args.class_name, class_mapping)
        java_analysis = getattr(g, "analysis")
        class_count = 0
        if not zipfile.is_zipfile(archive_path):
            return JavaViewClassResult(
                archive_path=str(archive_path),
                class_found=False,
                matched_by="none",
            )
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if not info.filename.endswith(".class"):
                    continue
                class_count += 1
                if class_count > args.max_classes_scan:
                    break
                entry_class_name = info.filename.removesuffix(".class")
                if entry_class_name not in target_names:
                    continue
                parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                if parsed is None:
                    continue
                return _result_for_class(
                    kb=kb,
                    archive_path=archive_path,
                    entry_name=info.filename,
                    parsed=parsed,
                    matched_by=matched_by,
                    class_mapping=class_mapping,
                    mappings=mappings,
                    include_members=args.include_members,
                    mapping_path=args.mapping_path,
                )

        return JavaViewClassResult(
            archive_path=str(archive_path),
            class_found=False,
            matched_by="none",
        )


def _result_for_class(
    *,
    kb: KnowledgeBase,
    archive_path: Path,
    entry_name: str,
    parsed: dict[str, Any],
    matched_by: Literal["input", "official", "obfuscated", "none"],
    class_mapping: ProguardClassMapping | None,
    mappings: ProguardMappings | None,
    include_members: bool,
    mapping_path: str | None,
) -> JavaViewClassResult:
    class_name = str(parsed["class_name"])
    mapped_class_name = (
        class_mapping.official_name if class_mapping is not None else None
    )
    fields = (
        [
            _member_summary("field", member, class_mapping, mappings)
            for member in parsed["fields"]
        ]
        if include_members
        else []
    )
    methods = (
        [
            _member_summary("method", member, class_mapping, mappings)
            for member in parsed["methods"]
        ]
        if include_members
        else []
    )
    class_node = kb.add_node(
        Node(
            kind=NodeKind.java_class,
            label=mapped_class_name or _dotted(class_name),
            props={
                "tool": "java_view_class",
                "archive_path": str(archive_path),
                "entry_name": entry_name,
                "class_name": class_name,
                "dotted_class_name": _dotted(class_name),
                "mapped_class_name": mapped_class_name,
                "mapping_path": mapping_path,
                "super_class": parsed["super_class"],
                "major_version": parsed["major_version"],
                "minor_version": parsed["minor_version"],
                "access_flags": parsed["access_flags"],
            },
            tags=["java", "class", "deobfuscated" if mapped_class_name else "raw"],
        )
    )
    for member in [*fields, *methods]:
        member_node = kb.add_node(
            Node(
                kind=(
                    NodeKind.java_method
                    if member.kind == "method"
                    else NodeKind.java_field
                ),
                label=(
                    f"{mapped_class_name or _dotted(class_name)}#"
                    f"{member.mapped_names[0] if member.mapped_names else member.name}"
                    f"{member.descriptor}"
                ),
                props={
                    "tool": "java_view_class",
                    "archive_path": str(archive_path),
                    "entry_name": entry_name,
                    "class_name": class_name,
                    "mapped_class_name": mapped_class_name,
                    "name": member.name,
                    "descriptor": member.descriptor,
                    "mapped_names": member.mapped_names,
                    "mapped_signatures": member.mapped_signatures,
                    "access_flags": member.access_flags,
                    "code": member.code.model_dump() if member.code else None,
                },
                tags=["java", member.kind, "mapping", "annotation"],
            )
        )
        kb.add_edge(
            Edge(src=class_node.id, dst=member_node.id, kind=f"declares_{member.kind}")
        )

    return JavaViewClassResult(
        archive_path=str(archive_path),
        class_found=True,
        matched_by=matched_by,
        entry_name=entry_name,
        class_name=class_name,
        dotted_class_name=_dotted(class_name),
        mapped_class_name=mapped_class_name,
        super_class=parsed["super_class"],
        major_version=parsed["major_version"],
        minor_version=parsed["minor_version"],
        access_flags=parsed["access_flags"],
        fields=fields,
        methods=methods,
        class_node_id=class_node.id,
    )


def _member_summary(
    kind: Literal["field", "method"],
    member: dict[str, Any],
    class_mapping: ProguardClassMapping | None,
    mappings: ProguardMappings | None,
) -> JavaClassMemberSummary:
    mapped_members = (
        mappings.matching_member_mappings(
            class_mapping,
            kind=kind,
            obfuscated_name=str(member["name"]),
            descriptor=str(member["descriptor"]),
        )
        if class_mapping is not None and mappings is not None
        else []
    )
    return JavaClassMemberSummary(
        kind=kind,
        name=str(member["name"]),
        descriptor=str(member["descriptor"]),
        access_flags=int(member["access_flags"]),
        mapped_names=[mapping.official_name for mapping in mapped_members],
        mapped_signatures=[mapping.official_signature for mapping in mapped_members],
        code=_code_summary(member.get("code")),
    )


def _code_summary(value: Any) -> JavaCodeSummary | None:
    if not isinstance(value, dict):
        return None
    return JavaCodeSummary(
        max_stack=int(value["max_stack"]),
        max_locals=int(value["max_locals"]),
        code_length=int(value["code_length"]),
        exception_table_len=int(value["exception_table_len"]),
        attributes_count=int(value["attributes_count"]),
    )


def _candidate_class_names(
    class_name: str,
    class_mapping: ProguardClassMapping | None,
) -> set[str]:
    candidates = {_internal(class_name)}
    if class_mapping is not None:
        candidates.add(_internal(class_mapping.obfuscated_name))
        candidates.add(_internal(class_mapping.official_name))
    return candidates


def _internal(class_name: str) -> str:
    return class_name.removesuffix(".class").replace(".", "/")


def _dotted(class_name: str) -> str:
    return class_name.replace("/", ".")


def build_tool() -> MemoryTool[JavaViewClassArgs, JavaViewClassResult]:
    return JavaViewClassTool()
