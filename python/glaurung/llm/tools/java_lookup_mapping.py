from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import ProguardMemberMapping, parse_proguard_mappings


class JavaLookupMappingArgs(BaseModel):
    mapping_path: str | None = Field(
        None,
        description="Path to a ProGuard/Mojang mapping file",
    )
    class_name: str | None = Field(
        None,
        description="Official or obfuscated class name",
    )
    member_name: str | None = Field(
        None,
        description="Optional official or obfuscated field/method name filter",
    )
    max_members: int = Field(64, ge=0, le=512)


class JavaMemberMappingSummary(BaseModel):
    kind: Literal["field", "method"]
    official_name: str
    obfuscated_name: str
    official_signature: str


class JavaLookupMappingResult(BaseModel):
    mapping_path: str
    mapping_format: str
    class_found: bool
    matched_by: Literal["official", "obfuscated", "none"]
    official_class_name: str | None = None
    obfuscated_class_name: str | None = None
    fields: list[JavaMemberMappingSummary]
    methods: list[JavaMemberMappingSummary]
    truncated: bool = False
    note_node_id: str | None = None


class JavaLookupMappingTool(MemoryTool[JavaLookupMappingArgs, JavaLookupMappingResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_lookup_mapping",
                description=(
                    "Look up a class or member in a ProGuard/Mojang mapping file "
                    "by either official or obfuscated name."
                ),
                tags=("java", "mapping", "deobfuscation", "lookup", "kb"),
            ),
            JavaLookupMappingArgs,
            JavaLookupMappingResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaLookupMappingArgs,
    ) -> JavaLookupMappingResult:
        if args.mapping_path is None or args.class_name is None:
            return JavaLookupMappingResult(
                mapping_path=args.mapping_path or "",
                mapping_format="proguard",
                class_found=False,
                matched_by="none",
                fields=[],
                methods=[],
                truncated=False,
                note_node_id=None,
            )

        mapping_path = Path(args.mapping_path)
        mappings = parse_proguard_mappings(mapping_path)
        class_mapping, matched_by = mappings.lookup_class(args.class_name)
        fields: list[JavaMemberMappingSummary] = []
        methods: list[JavaMemberMappingSummary] = []
        truncated = False

        if class_mapping is not None:
            field_members = _filter_members(class_mapping.fields, args.member_name)
            method_members = _filter_members(class_mapping.methods, args.member_name)
            combined_limit = args.max_members
            fields = [
                _member_summary(member) for member in field_members[:combined_limit]
            ]
            remaining = max(combined_limit - len(fields), 0)
            methods = [_member_summary(member) for member in method_members[:remaining]]
            truncated = len(field_members) + len(method_members) > args.max_members

        text = _note_text(
            class_name=args.class_name,
            member_name=args.member_name,
            class_found=class_mapping is not None,
            official_class_name=(
                class_mapping.official_name if class_mapping is not None else None
            ),
            obfuscated_class_name=(
                class_mapping.obfuscated_name if class_mapping is not None else None
            ),
            field_count=len(fields),
            method_count=len(methods),
            truncated=truncated,
        )
        note = kb.add_node(
            Node(
                kind=NodeKind.note,
                label="Java mapping lookup",
                text=text,
                props={
                    "tool": "java_lookup_mapping",
                    "mapping_path": str(mapping_path),
                    "class_name": args.class_name,
                    "member_name": args.member_name,
                    "matched_by": matched_by,
                    "class_found": class_mapping is not None,
                },
                tags=["java", "mapping", "deobfuscation", "lookup"],
            )
        )
        return JavaLookupMappingResult(
            mapping_path=str(mapping_path),
            mapping_format="proguard",
            class_found=class_mapping is not None,
            matched_by=matched_by,
            official_class_name=(
                class_mapping.official_name if class_mapping is not None else None
            ),
            obfuscated_class_name=(
                class_mapping.obfuscated_name if class_mapping is not None else None
            ),
            fields=fields,
            methods=methods,
            truncated=truncated,
            note_node_id=note.id,
        )


def _filter_members(
    members: list[ProguardMemberMapping],
    member_name: str | None,
) -> list[ProguardMemberMapping]:
    if member_name is None:
        return members
    return [
        member
        for member in members
        if member.official_name == member_name or member.obfuscated_name == member_name
    ]


def _member_summary(member: ProguardMemberMapping) -> JavaMemberMappingSummary:
    return JavaMemberMappingSummary(
        kind=member.kind,
        official_name=member.official_name,
        obfuscated_name=member.obfuscated_name,
        official_signature=member.official_signature,
    )


def _note_text(
    *,
    class_name: str,
    member_name: str | None,
    class_found: bool,
    official_class_name: str | None,
    obfuscated_class_name: str | None,
    field_count: int,
    method_count: int,
    truncated: bool,
) -> str:
    if not class_found:
        return f"No mapping entry found for class {class_name}."
    target = f"{official_class_name} -> {obfuscated_class_name}"
    if member_name:
        target += f" member={member_name}"
    suffix = " Results were truncated." if truncated else ""
    return (
        f"Mapping lookup found {target}: "
        f"{field_count} fields, {method_count} methods.{suffix}"
    )


def build_tool() -> MemoryTool[JavaLookupMappingArgs, JavaLookupMappingResult]:
    return JavaLookupMappingTool()
