from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaListStringConstantsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_filter: str | None = Field(None, description="Optional class substring")
    value_filter: str | None = Field(None, description="Optional string substring")
    min_length: int = Field(0, ge=0)
    include_values: bool = False
    preview_length: int = Field(80, ge=0, le=512)
    max_classes_scan: int = Field(100_000, ge=1)
    limit: int = Field(512, ge=0)


class JavaStringConstantSummary(BaseModel):
    class_name: str
    dotted_class_name: str
    entry_name: str
    source: Literal["ldc", "field_constant"]
    value_preview: str
    value: str | None = None
    value_length: int
    sha256: str
    method_name: str | None = None
    method_descriptor: str | None = None
    field_name: str | None = None
    field_descriptor: str | None = None
    bci: int | None = None


class JavaListStringConstantsResult(BaseModel):
    archive_path: str
    class_count_scanned: int = 0
    string_count_seen: int = 0
    matched_string_count: int = 0
    strings: list[JavaStringConstantSummary] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaListStringConstantsTool(
    MemoryTool[JavaListStringConstantsArgs, JavaListStringConstantsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_list_string_constants",
                description=(
                    "List bounded Java string constants from LDC bytecode xrefs and "
                    "static final ConstantValue fields, with hashes and optional values."
                ),
                tags=("java", "jar", "string", "constant", "kb"),
            ),
            JavaListStringConstantsArgs,
            JavaListStringConstantsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaListStringConstantsArgs,
    ) -> JavaListStringConstantsResult:
        archive_path = Path(args.path or ctx.file_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaListStringConstantsResult(
                archive_path=str(archive_path),
                stop_reasons=["input_not_zip"],
            )
        java_analysis = getattr(g, "analysis")
        result = JavaListStringConstantsResult(archive_path=str(archive_path))
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
                if not isinstance(parsed, dict):
                    continue
                class_name = str(parsed.get("class_name") or "")
                if args.class_filter and args.class_filter not in class_name.replace(
                    "/", "."
                ):
                    continue
                for item in _strings_from_class(info.filename, parsed, args):
                    result.string_count_seen += 1
                    if not _matches_value(item, args):
                        continue
                    if len(result.strings) >= args.limit:
                        result.truncated = True
                        result.stop_reasons.append("limit")
                        break
                    result.strings.append(item)
                    result.matched_string_count += 1
                    _add_string_node(kb, archive_path, item)
                if result.truncated:
                    break
        return result


def _strings_from_class(
    entry_name: str,
    parsed: dict[str, Any],
    args: JavaListStringConstantsArgs,
) -> list[JavaStringConstantSummary]:
    class_name = str(parsed.get("class_name") or "")
    out: list[JavaStringConstantSummary] = []
    for field in parsed.get("fields", []):
        if not isinstance(field, dict):
            continue
        constant = field.get("constant_value")
        if (
            isinstance(constant, dict)
            and constant.get("kind") == "string"
            and isinstance(constant.get("value"), str)
        ):
            out.append(
                _summary(
                    class_name=class_name,
                    entry_name=entry_name,
                    source="field_constant",
                    value=constant["value"],
                    args=args,
                    field_name=str(field.get("name") or ""),
                    field_descriptor=str(field.get("descriptor") or ""),
                )
            )
    for method in parsed.get("methods", []):
        if not isinstance(method, dict):
            continue
        code = method.get("code")
        if not isinstance(code, dict):
            continue
        for xref in code.get("xrefs", []):
            if not isinstance(xref, dict) or xref.get("kind") != "string":
                continue
            value = xref.get("string_value")
            if not isinstance(value, str):
                continue
            out.append(
                _summary(
                    class_name=class_name,
                    entry_name=entry_name,
                    source="ldc",
                    value=value,
                    args=args,
                    method_name=str(method.get("name") or ""),
                    method_descriptor=str(method.get("descriptor") or ""),
                    bci=int(xref.get("bci", 0)),
                )
            )
    return out


def _summary(
    *,
    class_name: str,
    entry_name: str,
    source: Literal["ldc", "field_constant"],
    value: str,
    args: JavaListStringConstantsArgs,
    method_name: str | None = None,
    method_descriptor: str | None = None,
    field_name: str | None = None,
    field_descriptor: str | None = None,
    bci: int | None = None,
) -> JavaStringConstantSummary:
    return JavaStringConstantSummary(
        class_name=class_name,
        dotted_class_name=class_name.replace("/", "."),
        entry_name=entry_name,
        source=source,
        value_preview=_preview(value, args.preview_length),
        value=value if args.include_values else None,
        value_length=len(value),
        sha256=hashlib.sha256(
            value.encode("utf-8", errors="surrogatepass")
        ).hexdigest(),
        method_name=method_name,
        method_descriptor=method_descriptor,
        field_name=field_name,
        field_descriptor=field_descriptor,
        bci=bci,
    )


def _matches_value(
    item: JavaStringConstantSummary,
    args: JavaListStringConstantsArgs,
) -> bool:
    if item.value_length < args.min_length:
        return False
    if args.value_filter is None:
        return True
    haystack = item.value if item.value is not None else item.value_preview
    return args.value_filter in haystack


def _preview(value: str, limit: int) -> str:
    if limit == 0:
        return ""
    if len(value) <= limit:
        return value
    return value[:limit]


def _add_string_node(
    kb: KnowledgeBase,
    archive_path: Path,
    item: JavaStringConstantSummary,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.string,
            label=item.value_preview,
            props={
                "tool": "java_list_string_constants",
                "archive_path": str(archive_path),
                **item.model_dump(),
            },
            tags=["java", "string", item.source],
        )
    )


def build_tool() -> MemoryTool[
    JavaListStringConstantsArgs, JavaListStringConstantsResult
]:
    return JavaListStringConstantsTool()
