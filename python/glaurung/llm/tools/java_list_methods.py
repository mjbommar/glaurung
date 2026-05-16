from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_descriptors import decode_method_descriptor
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)


class JavaListMethodsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_filter: str | None = Field(
        None,
        description=(
            "Optional substring filter over internal, dotted, or mapped class names."
        ),
    )
    name_filter: str | None = Field(
        None, description="Optional substring filter over raw or mapped method names"
    )
    descriptor_filter: str | None = Field(
        None, description="Optional substring filter over JVM method descriptors"
    )
    mapping_path: str | None = Field(
        None, description="Optional ProGuard/Mojang mapping file"
    )
    include_constructors: bool = True
    include_annotations: bool = False
    max_classes_scan: int = Field(50_000, ge=1)
    limit: int = Field(256, ge=0)


class JavaListedMethod(BaseModel):
    class_name: str
    dotted_class_name: str
    mapped_class_name: str | None = None
    source_file: str | None = None
    name: str
    descriptor: str
    parameter_types: list[str] = Field(default_factory=list)
    parameter_count: int = 0
    return_type: str | None = None
    descriptor_error: str | None = None
    access_flags: int
    mapped_names: list[str] = Field(default_factory=list)
    mapped_signatures: list[str] = Field(default_factory=list)
    code_length: int | None = None
    max_stack: int | None = None
    max_locals: int | None = None
    line_number_count: int = 0
    first_line: int | None = None
    last_line: int | None = None
    annotation_descriptors: list[str] = Field(default_factory=list)


class JavaListMethodsResult(BaseModel):
    archive_path: str
    class_count_scanned: int = 0
    method_count_seen: int = 0
    matched_method_count: int = 0
    methods: list[JavaListedMethod] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaListMethodsTool(MemoryTool[JavaListMethodsArgs, JavaListMethodsResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_methods",
                description=(
                    "List methods from a Java archive with class/name/descriptor "
                    "filters, code-size summaries, optional annotation descriptors, "
                    "and optional ProGuard/Mojang mapping annotations."
                ),
                tags=("java", "method", "jar", "mapping", "kb"),
            ),
            JavaListMethodsArgs,
            JavaListMethodsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListMethodsArgs,
    ) -> JavaListMethodsResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListMethodsResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )
        mappings = (
            parse_proguard_mappings(Path(args.mapping_path))
            if args.mapping_path is not None
            else None
        )
        result = JavaListMethodsResult(archive_path=str(archive_path))
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
                _list_methods_from_class(
                    kb=kb,
                    archive_path=archive_path,
                    parsed=parsed,
                    class_mapping=class_mapping,
                    mappings=mappings,
                    args=args,
                    result=result,
                )
                if result.truncated:
                    break
        result.stop_reasons = _dedupe(result.stop_reasons)
        return result


def _list_methods_from_class(
    *,
    kb: KnowledgeBase,
    archive_path: Path,
    parsed: dict[str, Any],
    class_mapping: ProguardClassMapping | None,
    mappings: ProguardMappings | None,
    args: JavaListMethodsArgs,
    result: JavaListMethodsResult,
) -> None:
    class_name = str(parsed["class_name"])
    source_file = _optional_string(parsed.get("source_file"))
    for method in parsed.get("methods", []):
        if not isinstance(method, dict):
            continue
        result.method_count_seen += 1
        method_name = str(method.get("name"))
        descriptor = str(method.get("descriptor"))
        if not args.include_constructors and method_name in {"<init>", "<clinit>"}:
            continue
        mapped_members = _mapped_methods(
            class_mapping, mappings, method_name, descriptor
        )
        if not _matches_method_filter(method_name, mapped_members, args.name_filter):
            continue
        if args.descriptor_filter and args.descriptor_filter not in descriptor:
            continue
        if len(result.methods) >= args.limit:
            result.truncated = True
            result.stop_reasons.append("limit")
            return
        summary = _method_summary(
            class_name=class_name,
            source_file=source_file,
            class_mapping=class_mapping,
            method=method,
            mapped_members=mapped_members,
            include_annotations=args.include_annotations,
        )
        result.methods.append(summary)
        result.matched_method_count += 1
        _add_method_node(kb, archive_path, summary)


def _method_summary(
    *,
    class_name: str,
    source_file: str | None,
    class_mapping: ProguardClassMapping | None,
    method: dict[str, Any],
    mapped_members: list[Any],
    include_annotations: bool,
) -> JavaListedMethod:
    code = method.get("code")
    code_length: int | None = None
    max_stack: int | None = None
    max_locals: int | None = None
    line_numbers: list[int] = []
    if isinstance(code, dict):
        code_length = int(code.get("code_length", 0))
        max_stack = int(code.get("max_stack", 0))
        max_locals = int(code.get("max_locals", 0))
        line_numbers = _line_numbers(code)
    descriptor = str(method.get("descriptor"))
    decoded_descriptor = decode_method_descriptor(descriptor)
    return JavaListedMethod(
        class_name=class_name,
        dotted_class_name=_dotted(class_name),
        mapped_class_name=class_mapping.official_name if class_mapping else None,
        source_file=source_file,
        name=str(method.get("name")),
        descriptor=descriptor,
        parameter_types=decoded_descriptor.parameter_types,
        parameter_count=decoded_descriptor.parameter_count,
        return_type=decoded_descriptor.return_type,
        descriptor_error=decoded_descriptor.error,
        access_flags=int(method.get("access_flags", 0)),
        mapped_names=[member.official_name for member in mapped_members],
        mapped_signatures=[member.official_signature for member in mapped_members],
        code_length=code_length,
        max_stack=max_stack,
        max_locals=max_locals,
        line_number_count=len(line_numbers),
        first_line=min(line_numbers) if line_numbers else None,
        last_line=max(line_numbers) if line_numbers else None,
        annotation_descriptors=_annotation_descriptors(method)
        if include_annotations
        else [],
    )


def _lookup_class_mapping(
    mappings: ProguardMappings | None, class_name: str
) -> ProguardClassMapping | None:
    if mappings is None:
        return None
    class_mapping, _ = mappings.lookup_class(class_name)
    return class_mapping


def _mapped_methods(
    class_mapping: ProguardClassMapping | None,
    mappings: ProguardMappings | None,
    method_name: str,
    descriptor: str,
) -> list[Any]:
    if class_mapping is None or mappings is None:
        return []
    return mappings.matching_member_mappings(
        class_mapping,
        kind="method",
        obfuscated_name=method_name,
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


def _matches_method_filter(
    method_name: str,
    mapped_members: list[Any],
    name_filter: str | None,
) -> bool:
    if not name_filter:
        return True
    haystacks = {method_name}
    haystacks.update(str(member.official_name) for member in mapped_members)
    haystacks.update(str(member.obfuscated_name) for member in mapped_members)
    return any(name_filter in value for value in haystacks)


def _annotation_descriptors(method: dict[str, Any]) -> list[str]:
    annotations = method.get("annotations")
    if not isinstance(annotations, list):
        return []
    return [
        str(annotation.get("descriptor"))
        for annotation in annotations
        if isinstance(annotation, dict) and annotation.get("descriptor")
    ]


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


def _add_method_node(
    kb: KnowledgeBase,
    archive_path: Path,
    method: JavaListedMethod,
) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                str(archive_path),
                method.class_name,
                method.name,
                method.descriptor,
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    kb.add_node(
        Node(
            kind=NodeKind.java_method,
            label=(
                f"{method.mapped_class_name or method.dotted_class_name}#"
                f"{method.mapped_names[0] if method.mapped_names else method.name}"
                f"{method.descriptor}"
            ),
            props={
                "tool": "java_list_methods",
                "java_method_id": digest,
                "archive_path": str(archive_path),
                **method.model_dump(),
            },
            tags=["java", "method", "mapping" if method.mapped_names else "raw"],
        )
    )


def _dotted(class_name: str) -> str:
    return class_name.replace("/", ".")


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_tool() -> MemoryTool[JavaListMethodsArgs, JavaListMethodsResult]:
    return JavaListMethodsTool()
