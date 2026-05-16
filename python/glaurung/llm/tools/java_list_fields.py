from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g
from glaurung.java_classfile_policy import classfile_policy

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_access_flags import access_flag_names
from .java_descriptors import decode_field_descriptor
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)
from .java_signatures import decode_field_signature


class JavaListFieldsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_filter: str | None = Field(
        None,
        description=(
            "Optional substring filter over internal, dotted, or mapped class names."
        ),
    )
    name_filter: str | None = Field(
        None, description="Optional substring filter over raw or mapped field names"
    )
    descriptor_filter: str | None = Field(
        None, description="Optional substring filter over JVM field descriptors"
    )
    mapping_path: str | None = Field(
        None, description="Optional ProGuard/Mojang mapping file"
    )
    include_annotations: bool = False
    constants_only: bool = False
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


class JavaFieldConstantValue(BaseModel):
    kind: str
    value: str


class JavaListedField(BaseModel):
    class_name: str
    dotted_class_name: str
    mapped_class_name: str | None = None
    source_file: str | None = None
    class_major_version: int | None = None
    class_minor_version: int | None = None
    class_java_release: int | None = None
    class_java_release_label: str | None = None
    classfile_version_label: str | None = None
    is_preview_classfile: bool = False
    classfile_size: int | None = None
    classfile_size_category: str = "unknown"
    classfile_warnings: list[str] = Field(default_factory=list)
    name: str
    descriptor: str
    field_type: str | None = None
    descriptor_error: str | None = None
    generic_signature: str | None = None
    generic_field_type: str | None = None
    generic_signature_error: str | None = None
    constant_value: JavaFieldConstantValue | None = None
    has_constant_value: bool = False
    access_flags: int
    access_flag_names: list[str] = Field(default_factory=list)
    attribute_count: int = 0
    attribute_names: list[str] = Field(default_factory=list)
    is_deprecated: bool = False
    is_synthetic: bool = False
    mapped_names: list[str] = Field(default_factory=list)
    mapped_signatures: list[str] = Field(default_factory=list)
    annotation_descriptors: list[str] = Field(default_factory=list)


class JavaListFieldsResult(BaseModel):
    archive_path: str
    class_count_scanned: int = 0
    field_count_seen: int = 0
    matched_field_count: int = 0
    fields: list[JavaListedField] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaListFieldsTool(MemoryTool[JavaListFieldsArgs, JavaListFieldsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_fields",
                description=(
                    "List fields from a Java archive with class/name/descriptor/"
                    "access filters, descriptor and generic type decoding, constant "
                    "values, optional annotation descriptors, optional ProGuard/"
                    "Mojang mapped names, and KB evidence."
                ),
                tags=("java", "field", "jar", "mapping", "kb"),
            ),
            JavaListFieldsArgs,
            JavaListFieldsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListFieldsArgs,
    ) -> JavaListFieldsResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListFieldsResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )
        mappings = (
            parse_proguard_mappings(Path(args.mapping_path))
            if args.mapping_path is not None
            else None
        )
        result = JavaListFieldsResult(archive_path=str(archive_path))
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
                class_mapping = _lookup_class_mapping(mappings, class_name)
                if not _matches_class_filter(
                    class_name, class_mapping, args.class_filter
                ):
                    continue
                _list_fields_from_class(
                    kb=kb,
                    archive_path=archive_path,
                    parsed=parsed,
                    classfile_size=info.file_size,
                    class_mapping=class_mapping,
                    mappings=mappings,
                    args=args,
                    result=result,
                )
                if result.truncated:
                    break
        result.stop_reasons = _dedupe(result.stop_reasons)
        return result


def _list_fields_from_class(
    *,
    kb: KnowledgeBase,
    archive_path: Path,
    parsed: dict[str, Any],
    classfile_size: int | None,
    class_mapping: ProguardClassMapping | None,
    mappings: ProguardMappings | None,
    args: JavaListFieldsArgs,
    result: JavaListFieldsResult,
) -> None:
    class_name = str(parsed["class_name"])
    source_file = _optional_string(parsed.get("source_file"))
    for field in parsed.get("fields", []):
        if not isinstance(field, dict):
            continue
        result.field_count_seen += 1
        field_name = str(field.get("name"))
        descriptor = str(field.get("descriptor"))
        mapped_members = _mapped_fields(class_mapping, mappings, field_name, descriptor)
        if not _matches_field_filters(
            field, field_name, descriptor, mapped_members, args
        ):
            continue
        if len(result.fields) >= args.limit:
            result.truncated = True
            result.stop_reasons.append("limit")
            return
        summary = _field_summary(
            class_name=class_name,
            source_file=source_file,
            class_major_version=int(parsed.get("major_version", 0)),
            class_minor_version=int(parsed.get("minor_version", 0)),
            classfile_size=classfile_size,
            class_mapping=class_mapping,
            field=field,
            mapped_members=mapped_members,
            include_annotations=args.include_annotations,
        )
        result.fields.append(summary)
        result.matched_field_count += 1
        _add_field_node(kb, archive_path, summary)


def _field_summary(
    *,
    class_name: str,
    source_file: str | None,
    class_major_version: int,
    class_minor_version: int,
    classfile_size: int | None,
    class_mapping: ProguardClassMapping | None,
    field: dict[str, Any],
    mapped_members: list[Any],
    include_annotations: bool,
) -> JavaListedField:
    descriptor = str(field.get("descriptor"))
    decoded_descriptor = decode_field_descriptor(descriptor)
    generic_signature = _optional_string(field.get("signature"))
    decoded_signature = decode_field_signature(generic_signature)
    constant_value = _constant_value(field.get("constant_value"))
    policy = classfile_policy(
        class_major_version,
        class_minor_version,
        size_bytes=classfile_size,
    )
    return JavaListedField(
        class_name=class_name,
        dotted_class_name=_dotted(class_name),
        mapped_class_name=class_mapping.official_name if class_mapping else None,
        source_file=source_file,
        class_major_version=policy.major_version,
        class_minor_version=policy.minor_version,
        class_java_release=policy.java_release,
        class_java_release_label=policy.java_release_label,
        classfile_version_label=policy.classfile_version_label,
        is_preview_classfile=policy.is_preview_classfile,
        classfile_size=policy.classfile_size,
        classfile_size_category=policy.classfile_size_category,
        classfile_warnings=policy.classfile_warnings,
        name=str(field.get("name")),
        descriptor=descriptor,
        field_type=decoded_descriptor.field_type,
        descriptor_error=decoded_descriptor.error,
        generic_signature=generic_signature,
        generic_field_type=decoded_signature.field_type,
        generic_signature_error=decoded_signature.error,
        constant_value=constant_value,
        has_constant_value=constant_value is not None,
        access_flags=int(field.get("access_flags", 0)),
        access_flag_names=access_flag_names(int(field.get("access_flags", 0)), "field"),
        attribute_count=int(field.get("attribute_count", 0)),
        attribute_names=_string_list(field.get("attribute_names")),
        is_deprecated=bool(field.get("is_deprecated", False)),
        is_synthetic=bool(field.get("is_synthetic", False)),
        mapped_names=[member.official_name for member in mapped_members],
        mapped_signatures=[member.official_signature for member in mapped_members],
        annotation_descriptors=_annotation_descriptors(field)
        if include_annotations
        else [],
    )


def _matches_field_filters(
    field: dict[str, Any],
    field_name: str,
    descriptor: str,
    mapped_members: list[Any],
    args: JavaListFieldsArgs,
) -> bool:
    access_flags = int(field.get("access_flags", 0))
    if (
        args.access_flags_all
        and (access_flags & args.access_flags_all) != args.access_flags_all
    ):
        return False
    if args.access_flags_any and access_flags & args.access_flags_any == 0:
        return False
    if args.access_flags_none and access_flags & args.access_flags_none != 0:
        return False
    if args.constants_only and not isinstance(field.get("constant_value"), dict):
        return False
    if not _matches_field_name_filter(field_name, mapped_members, args.name_filter):
        return False
    return not (args.descriptor_filter and args.descriptor_filter not in descriptor)


def _lookup_class_mapping(
    mappings: ProguardMappings | None, class_name: str
) -> ProguardClassMapping | None:
    if mappings is None:
        return None
    class_mapping, _ = mappings.lookup_class(class_name)
    return class_mapping


def _mapped_fields(
    class_mapping: ProguardClassMapping | None,
    mappings: ProguardMappings | None,
    field_name: str,
    descriptor: str,
) -> list[Any]:
    if class_mapping is None or mappings is None:
        return []
    return mappings.matching_member_mappings(
        class_mapping,
        kind="field",
        obfuscated_name=field_name,
        descriptor=descriptor,
    )


def _matches_class_filter(
    class_name: str,
    class_mapping: ProguardClassMapping | None,
    class_filter: str | None,
) -> bool:
    if not class_filter:
        return True
    haystacks = {
        class_name,
        _dotted(class_name),
    }
    if class_mapping is not None:
        haystacks.add(class_mapping.official_name)
        haystacks.add(class_mapping.obfuscated_name)
    needle = class_filter.replace("/", ".")
    return any(needle in value.replace("/", ".") for value in haystacks)


def _matches_field_name_filter(
    field_name: str,
    mapped_members: list[Any],
    name_filter: str | None,
) -> bool:
    if not name_filter:
        return True
    haystacks = {field_name}
    haystacks.update(str(member.official_name) for member in mapped_members)
    haystacks.update(str(member.obfuscated_name) for member in mapped_members)
    return any(name_filter in value for value in haystacks)


def _annotation_descriptors(field: dict[str, Any]) -> list[str]:
    annotations = field.get("annotations")
    if not isinstance(annotations, list):
        return []
    return [
        str(annotation.get("descriptor"))
        for annotation in annotations
        if isinstance(annotation, dict) and annotation.get("descriptor")
    ]


def _constant_value(value: Any) -> JavaFieldConstantValue | None:
    if not isinstance(value, dict):
        return None
    return JavaFieldConstantValue.model_validate(value)


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _add_field_node(
    kb: KnowledgeBase,
    archive_path: Path,
    field: JavaListedField,
) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                str(archive_path),
                field.class_name,
                field.name,
                field.descriptor,
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    kb.add_node(
        Node(
            kind=NodeKind.java_field,
            label=(
                f"{field.mapped_class_name or field.dotted_class_name}#"
                f"{field.mapped_names[0] if field.mapped_names else field.name}"
                f":{field.descriptor}"
            ),
            props={
                "tool": "java_list_fields",
                "java_field_id": digest,
                "archive_path": str(archive_path),
                **field.model_dump(),
            },
            tags=["java", "field", "mapping" if field.mapped_names else "raw"],
        )
    )


def _dotted(class_name: str) -> str:
    return class_name.replace("/", ".")


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_tool() -> MemoryTool[JavaListFieldsArgs, JavaListFieldsResult]:
    return JavaListFieldsTool()
