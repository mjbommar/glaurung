from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g
from glaurung.java_classfile_policy import classfile_policy

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_access_flags import access_flag_names
from .java_class_kind import JavaClassKind, class_kind
from .java_descriptors import decode_field_descriptor, decode_method_descriptor
from .java_hierarchy_edges import add_java_hierarchy_edges
from .java_module_info import JavaModuleSummary, module_summary
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)
from .java_signatures import (
    decode_class_signature,
    decode_field_signature,
    decode_method_signature,
)
from .java_xref_summary import code_xref_counts


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
    stack_map_frame_count: int = 0
    xref_count: int = 0
    method_xref_count: int = 0
    field_xref_count: int = 0
    class_xref_count: int = 0
    string_xref_count: int = 0
    dynamic_xref_count: int = 0
    line_number_count: int = 0
    first_line: int | None = None
    last_line: int | None = None


class JavaAnnotationValueSummary(BaseModel):
    tag: str
    kind: str
    value: str | None = None
    type_name: str | None = None
    const_name: str | None = None
    values: list[JavaAnnotationValueSummary] = Field(default_factory=list)


class JavaAnnotationElementSummary(BaseModel):
    name: str
    value: JavaAnnotationValueSummary


class JavaAnnotationSummary(BaseModel):
    visibility: str
    descriptor: str
    elements: list[JavaAnnotationElementSummary] = Field(default_factory=list)


class JavaMethodParameterSummary(BaseModel):
    name: str | None = None
    access_flags: int
    access_flag_names: list[str] = Field(default_factory=list)


class JavaParameterAnnotationsSummary(BaseModel):
    parameter_index: int
    annotations: list[JavaAnnotationSummary] = Field(default_factory=list)


class JavaInnerClassSummary(BaseModel):
    inner_class: str
    outer_class: str | None = None
    inner_name: str | None = None
    access_flags: int
    access_flag_names: list[str] = Field(default_factory=list)


class JavaEnclosingMethodSummary(BaseModel):
    class_name: str
    method_name: str | None = None
    method_descriptor: str | None = None


class JavaRecordComponentSummary(BaseModel):
    name: str
    descriptor: str
    signature: str | None = None
    annotations: list[JavaAnnotationSummary] = Field(default_factory=list)


class JavaClassMemberSummary(BaseModel):
    kind: Literal["field", "method"]
    name: str
    descriptor: str
    generic_signature: str | None = None
    generic_type_parameters: list[str] = Field(default_factory=list)
    generic_field_type: str | None = None
    generic_parameter_types: list[str] = Field(default_factory=list)
    generic_return_type: str | None = None
    generic_throws: list[str] = Field(default_factory=list)
    generic_signature_error: str | None = None
    field_type: str | None = None
    parameter_types: list[str] = Field(default_factory=list)
    parameter_count: int = 0
    return_type: str | None = None
    descriptor_error: str | None = None
    method_parameters: list[JavaMethodParameterSummary] = Field(default_factory=list)
    parameter_annotations: list[JavaParameterAnnotationsSummary] = Field(
        default_factory=list
    )
    annotation_default: JavaAnnotationValueSummary | None = None
    access_flags: int
    access_flag_names: list[str] = Field(default_factory=list)
    mapped_names: list[str] = Field(default_factory=list)
    mapped_signatures: list[str] = Field(default_factory=list)
    annotations: list[JavaAnnotationSummary] = Field(default_factory=list)
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
    source_file: str | None = None
    generic_signature: str | None = None
    generic_type_parameters: list[str] = Field(default_factory=list)
    generic_super_class: str | None = None
    generic_interfaces: list[str] = Field(default_factory=list)
    generic_signature_error: str | None = None
    major_version: int | None = None
    minor_version: int | None = None
    java_release: int | None = None
    java_release_label: str | None = None
    classfile_version_label: str | None = None
    is_preview_classfile: bool = False
    classfile_size: int | None = None
    classfile_size_category: str = "unknown"
    classfile_warnings: list[str] = Field(default_factory=list)
    access_flags: int | None = None
    access_flag_names: list[str] = Field(default_factory=list)
    class_kind: JavaClassKind = "class"
    is_interface: bool = False
    is_annotation: bool = False
    is_enum: bool = False
    is_record: bool = False
    is_sealed: bool = False
    permitted_subclasses: list[str] = Field(default_factory=list)
    inner_classes: list[JavaInnerClassSummary] = Field(default_factory=list)
    enclosing_method: JavaEnclosingMethodSummary | None = None
    nest_host: str | None = None
    nest_members: list[str] = Field(default_factory=list)
    record_components: list[JavaRecordComponentSummary] = Field(default_factory=list)
    module_info: JavaModuleSummary | None = None
    annotations: list[JavaAnnotationSummary] = Field(default_factory=list)
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
                    classfile_size=info.file_size,
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
    classfile_size: int | None,
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
    source_file = _optional_string(parsed.get("source_file"))
    generic_signature = _optional_string(parsed.get("signature"))
    decoded_class_signature = decode_class_signature(generic_signature)
    policy = classfile_policy(
        int(parsed["major_version"]),
        int(parsed["minor_version"]),
        size_bytes=classfile_size,
    )
    annotations = _annotation_summaries(parsed.get("annotations"))
    inner_classes = _inner_class_summaries(parsed.get("inner_classes"))
    enclosing_method = _enclosing_method_summary(parsed.get("enclosing_method"))
    nest_host = _optional_string(parsed.get("nest_host"))
    nest_members = _string_list(parsed.get("nest_members"))
    record_components = _record_component_summaries(parsed.get("record_components"))
    parsed_module_info = module_summary(parsed.get("module"))
    kind = class_kind(
        class_name=class_name,
        access_flags=int(parsed["access_flags"]),
        super_class=_optional_string(parsed.get("super_class")),
        record_components=parsed.get("record_components"),
        module_info=parsed.get("module"),
    )
    is_record = parsed.get("super_class") == "java/lang/Record" or bool(
        record_components
    )
    permitted_subclasses = _string_list(parsed.get("permitted_subclasses"))
    is_sealed = bool(permitted_subclasses)
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
                "source_file": source_file,
                "generic_signature": generic_signature,
                "generic_type_parameters": decoded_class_signature.type_parameters,
                "generic_super_class": decoded_class_signature.super_class,
                "generic_interfaces": decoded_class_signature.interfaces,
                "generic_signature_error": decoded_class_signature.error,
                "major_version": parsed["major_version"],
                "minor_version": parsed["minor_version"],
                "java_release": policy.java_release,
                "java_release_label": policy.java_release_label,
                "classfile_version_label": policy.classfile_version_label,
                "is_preview_classfile": policy.is_preview_classfile,
                "classfile_size": policy.classfile_size,
                "classfile_size_category": policy.classfile_size_category,
                "classfile_warnings": policy.classfile_warnings,
                "access_flags": parsed["access_flags"],
                "access_flag_names": access_flag_names(
                    int(parsed["access_flags"]), "class"
                ),
                "class_kind": kind,
                "is_interface": kind in {"interface", "annotation"},
                "is_annotation": kind == "annotation",
                "is_enum": kind == "enum",
                "is_record": is_record,
                "is_sealed": is_sealed,
                "permitted_subclasses": permitted_subclasses,
                "permitted_subclass_count": len(permitted_subclasses),
                "inner_classes": [item.model_dump() for item in inner_classes],
                "inner_class_count": len(inner_classes),
                "enclosing_method": (
                    enclosing_method.model_dump() if enclosing_method else None
                ),
                "nest_host": nest_host,
                "nest_members": nest_members,
                "nest_member_count": len(nest_members),
                "record_components": [
                    component.model_dump() for component in record_components
                ],
                "record_component_count": len(record_components),
                "module_info": (
                    parsed_module_info.model_dump() if parsed_module_info else None
                ),
                "annotations": [annotation.model_dump() for annotation in annotations],
            },
            tags=["java", "class", "deobfuscated" if mapped_class_name else "raw"],
        )
    )
    interfaces = _string_list(parsed.get("interfaces"))
    add_java_hierarchy_edges(
        kb,
        archive_path=archive_path,
        class_node_id=class_node.id,
        super_class=str(parsed["super_class"]),
        interfaces=interfaces,
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
                    "source_file": source_file,
                    "name": member.name,
                    "descriptor": member.descriptor,
                    "generic_signature": member.generic_signature,
                    "generic_type_parameters": member.generic_type_parameters,
                    "generic_field_type": member.generic_field_type,
                    "generic_parameter_types": member.generic_parameter_types,
                    "generic_return_type": member.generic_return_type,
                    "generic_throws": member.generic_throws,
                    "generic_signature_error": member.generic_signature_error,
                    "field_type": member.field_type,
                    "parameter_types": member.parameter_types,
                    "parameter_count": member.parameter_count,
                    "return_type": member.return_type,
                    "descriptor_error": member.descriptor_error,
                    "method_parameters": [
                        parameter.model_dump() for parameter in member.method_parameters
                    ],
                    "parameter_annotations": [
                        parameter.model_dump()
                        for parameter in member.parameter_annotations
                    ],
                    "annotation_default": (
                        member.annotation_default.model_dump()
                        if member.annotation_default
                        else None
                    ),
                    "mapped_names": member.mapped_names,
                    "mapped_signatures": member.mapped_signatures,
                    "annotations": [
                        annotation.model_dump() for annotation in member.annotations
                    ],
                    "access_flags": member.access_flags,
                    "access_flag_names": member.access_flag_names,
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
        source_file=source_file,
        generic_signature=generic_signature,
        generic_type_parameters=decoded_class_signature.type_parameters,
        generic_super_class=decoded_class_signature.super_class,
        generic_interfaces=decoded_class_signature.interfaces,
        generic_signature_error=decoded_class_signature.error,
        major_version=policy.major_version,
        minor_version=policy.minor_version,
        java_release=policy.java_release,
        java_release_label=policy.java_release_label,
        classfile_version_label=policy.classfile_version_label,
        is_preview_classfile=policy.is_preview_classfile,
        classfile_size=policy.classfile_size,
        classfile_size_category=policy.classfile_size_category,
        classfile_warnings=policy.classfile_warnings,
        access_flags=parsed["access_flags"],
        access_flag_names=access_flag_names(int(parsed["access_flags"]), "class"),
        class_kind=kind,
        is_interface=kind in {"interface", "annotation"},
        is_annotation=kind == "annotation",
        is_enum=kind == "enum",
        is_record=is_record,
        is_sealed=is_sealed,
        permitted_subclasses=permitted_subclasses,
        inner_classes=inner_classes,
        enclosing_method=enclosing_method,
        nest_host=nest_host,
        nest_members=nest_members,
        record_components=record_components,
        module_info=parsed_module_info,
        annotations=annotations,
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
    descriptor = str(member["descriptor"])
    decoded_descriptor = (
        decode_method_descriptor(descriptor)
        if kind == "method"
        else decode_field_descriptor(descriptor)
    )
    generic_signature = _optional_string(member.get("signature"))
    decoded_signature = (
        decode_method_signature(generic_signature)
        if kind == "method"
        else decode_field_signature(generic_signature)
    )
    mapped_members = (
        mappings.matching_member_mappings(
            class_mapping,
            kind=kind,
            obfuscated_name=str(member["name"]),
            descriptor=descriptor,
        )
        if class_mapping is not None and mappings is not None
        else []
    )
    return JavaClassMemberSummary(
        kind=kind,
        name=str(member["name"]),
        descriptor=descriptor,
        generic_signature=generic_signature,
        generic_type_parameters=getattr(decoded_signature, "type_parameters", []),
        generic_field_type=getattr(decoded_signature, "field_type", None),
        generic_parameter_types=getattr(decoded_signature, "parameter_types", []),
        generic_return_type=getattr(decoded_signature, "return_type", None),
        generic_throws=getattr(decoded_signature, "throws", []),
        generic_signature_error=decoded_signature.error,
        field_type=decoded_descriptor.field_type,
        parameter_types=decoded_descriptor.parameter_types,
        parameter_count=decoded_descriptor.parameter_count,
        return_type=decoded_descriptor.return_type,
        descriptor_error=decoded_descriptor.error,
        method_parameters=_method_parameter_summaries(member.get("method_parameters")),
        parameter_annotations=_parameter_annotation_summaries(
            member.get("parameter_annotations")
        ),
        annotation_default=_annotation_value_summary(member.get("annotation_default")),
        access_flags=int(member["access_flags"]),
        access_flag_names=access_flag_names(
            int(member["access_flags"]), "method" if kind == "method" else "field"
        ),
        mapped_names=[mapping.official_name for mapping in mapped_members],
        mapped_signatures=[mapping.official_signature for mapping in mapped_members],
        annotations=_annotation_summaries(member.get("annotations")),
        code=_code_summary(member.get("code")),
    )


def _annotation_summaries(value: Any) -> list[JavaAnnotationSummary]:
    if not isinstance(value, list):
        return []
    return [
        JavaAnnotationSummary.model_validate(annotation)
        for annotation in value
        if isinstance(annotation, dict)
    ]


def _method_parameter_summaries(value: Any) -> list[JavaMethodParameterSummary]:
    if not isinstance(value, list):
        return []
    out: list[JavaMethodParameterSummary] = []
    for parameter in value:
        if not isinstance(parameter, dict):
            continue
        summary = JavaMethodParameterSummary.model_validate(parameter)
        summary.access_flag_names = access_flag_names(summary.access_flags, "parameter")
        out.append(summary)
    return out


def _parameter_annotation_summaries(
    value: Any,
) -> list[JavaParameterAnnotationsSummary]:
    if not isinstance(value, list):
        return []
    return [
        JavaParameterAnnotationsSummary.model_validate(parameter)
        for parameter in value
        if isinstance(parameter, dict)
    ]


def _annotation_value_summary(value: Any) -> JavaAnnotationValueSummary | None:
    if not isinstance(value, dict):
        return None
    return JavaAnnotationValueSummary.model_validate(value)


def _inner_class_summaries(value: Any) -> list[JavaInnerClassSummary]:
    if not isinstance(value, list):
        return []
    out: list[JavaInnerClassSummary] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        summary = JavaInnerClassSummary.model_validate(item)
        summary.access_flag_names = access_flag_names(
            summary.access_flags, "inner_class"
        )
        out.append(summary)
    return out


def _enclosing_method_summary(value: Any) -> JavaEnclosingMethodSummary | None:
    if not isinstance(value, dict):
        return None
    return JavaEnclosingMethodSummary.model_validate(value)


def _record_component_summaries(value: Any) -> list[JavaRecordComponentSummary]:
    if not isinstance(value, list):
        return []
    return [
        JavaRecordComponentSummary.model_validate(component)
        for component in value
        if isinstance(component, dict)
    ]


def _code_summary(value: Any) -> JavaCodeSummary | None:
    if not isinstance(value, dict):
        return None
    line_numbers = _line_numbers(value)
    xref_counts = code_xref_counts(value)
    return JavaCodeSummary(
        max_stack=int(value["max_stack"]),
        max_locals=int(value["max_locals"]),
        code_length=int(value["code_length"]),
        exception_table_len=int(value["exception_table_len"]),
        attributes_count=int(value["attributes_count"]),
        stack_map_frame_count=int(value.get("stack_map_frame_count", 0)),
        xref_count=xref_counts["xref_count"],
        method_xref_count=xref_counts["method_xref_count"],
        field_xref_count=xref_counts["field_xref_count"],
        class_xref_count=xref_counts["class_xref_count"],
        string_xref_count=xref_counts["string_xref_count"],
        dynamic_xref_count=xref_counts["dynamic_xref_count"],
        line_number_count=len(line_numbers),
        first_line=min(line_numbers) if line_numbers else None,
        last_line=max(line_numbers) if line_numbers else None,
    )


def _line_numbers(code: dict[str, Any]) -> list[int]:
    line_numbers = code.get("line_numbers")
    if not isinstance(line_numbers, list):
        return []
    out: list[int] = []
    for line in line_numbers:
        if not isinstance(line, dict):
            continue
        value = line.get("line_number")
        if isinstance(value, int):
            out.append(value)
    return out


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


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
