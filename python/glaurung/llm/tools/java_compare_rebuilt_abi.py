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


AbiDifferenceKind = Literal[
    "missing_class",
    "extra_class",
    "missing_field",
    "extra_field",
    "missing_method",
    "extra_method",
    "changed_class_access",
    "changed_field_access",
    "changed_method_access",
]


class JavaCompareRebuiltAbiArgs(BaseModel):
    original_path: str | None = Field(
        None, description="Original JAR, class directory, or .class file"
    )
    rebuilt_path: str | None = Field(
        None, description="Rebuilt JAR, class directory, or .class file"
    )
    max_classes: int = Field(50_000, ge=0)
    max_differences: int = Field(512, ge=0)


class JavaAbiDifference(BaseModel):
    kind: AbiDifferenceKind
    class_name: str
    member_name: str | None = None
    descriptor: str | None = None
    original_access_flags: int | None = None
    rebuilt_access_flags: int | None = None
    message: str


class JavaCompareRebuiltAbiResult(BaseModel):
    original_path: str
    rebuilt_path: str | None = None
    abi_match: bool
    original_class_count: int = 0
    rebuilt_class_count: int = 0
    original_parse_error_count: int = 0
    rebuilt_parse_error_count: int = 0
    difference_count: int = 0
    differences: list[JavaAbiDifference] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class _ClassAbi(BaseModel):
    class_name: str
    access_flags: int
    fields: dict[str, int] = Field(default_factory=dict)
    methods: dict[str, int] = Field(default_factory=dict)


class _AbiLoadResult(BaseModel):
    classes: dict[str, _ClassAbi] = Field(default_factory=dict)
    parse_error_count: int = 0
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaCompareRebuiltAbiTool(
    MemoryTool[JavaCompareRebuiltAbiArgs, JavaCompareRebuiltAbiResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_compare_rebuilt_abi",
                description=(
                    "Compare original and rebuilt Java class ABI surfaces using "
                    "class, field, method descriptor, and access flag evidence."
                ),
                tags=("java", "abi", "source-recovery", "verification", "kb"),
            ),
            JavaCompareRebuiltAbiArgs,
            JavaCompareRebuiltAbiResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaCompareRebuiltAbiArgs,
    ) -> JavaCompareRebuiltAbiResult:
        original_path = Path(args.original_path or ctx.file_path)
        rebuilt_path = Path(args.rebuilt_path) if args.rebuilt_path else None
        if not original_path.exists():
            return JavaCompareRebuiltAbiResult(
                original_path=str(original_path),
                rebuilt_path=str(rebuilt_path) if rebuilt_path else None,
                abi_match=False,
                stop_reasons=["original_path_missing"],
            )
        if rebuilt_path is None:
            return JavaCompareRebuiltAbiResult(
                original_path=str(original_path),
                rebuilt_path=None,
                abi_match=False,
                stop_reasons=["rebuilt_path_missing"],
            )
        if not rebuilt_path.exists():
            return JavaCompareRebuiltAbiResult(
                original_path=str(original_path),
                rebuilt_path=str(rebuilt_path),
                abi_match=False,
                stop_reasons=["rebuilt_path_missing"],
            )

        original = _load_abi(original_path, args.max_classes)
        rebuilt = _load_abi(rebuilt_path, args.max_classes)
        stop_reasons = [*original.stop_reasons, *rebuilt.stop_reasons]
        differences = _compare_abi(
            original.classes, rebuilt.classes, args.max_differences
        )
        truncated = (
            original.truncated
            or rebuilt.truncated
            or len(differences) >= args.max_differences > 0
        )
        if len(differences) >= args.max_differences > 0:
            _append_once(stop_reasons, "max_differences")
        result = JavaCompareRebuiltAbiResult(
            original_path=str(original_path),
            rebuilt_path=str(rebuilt_path),
            abi_match=not differences
            and not original.stop_reasons
            and not rebuilt.stop_reasons,
            original_class_count=len(original.classes),
            rebuilt_class_count=len(rebuilt.classes),
            original_parse_error_count=original.parse_error_count,
            rebuilt_parse_error_count=rebuilt.parse_error_count,
            difference_count=len(differences),
            differences=differences,
            truncated=truncated,
            stop_reasons=stop_reasons,
        )
        _add_abi_node(kb, result)
        return result


def _load_abi(path: Path, max_classes: int) -> _AbiLoadResult:
    result = _AbiLoadResult()
    if path.is_dir():
        class_files = sorted(p for p in path.rglob("*.class") if p.is_file())
        for class_file in class_files:
            _add_class_bytes(result, class_file.read_bytes(), max_classes)
        return result
    if path.is_file() and path.suffix == ".class":
        _add_class_bytes(result, path.read_bytes(), max_classes)
        return result
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".class"):
                    continue
                if info.filename.startswith("META-INF/versions/"):
                    continue
                _add_class_bytes(result, zf.read(info), max_classes)
        return result
    result.stop_reasons.append("unsupported_class_container")
    return result


def _add_class_bytes(result: _AbiLoadResult, data: bytes, max_classes: int) -> None:
    if len(result.classes) >= max_classes:
        result.truncated = True
        _append_once(result.stop_reasons, "max_classes")
        return
    try:
        parsed = getattr(g, "analysis").parse_java_class_bytes(data)
    except RuntimeError:
        result.parse_error_count += 1
        return
    if parsed is None:
        result.parse_error_count += 1
        return
    abi = _class_abi(parsed)
    result.classes[abi.class_name] = abi


def _class_abi(parsed: dict[str, Any]) -> _ClassAbi:
    fields = {
        _member_key(member): int(member.get("access_flags", 0))
        for member in parsed.get("fields", [])
        if isinstance(member, dict)
    }
    methods = {
        _member_key(member): int(member.get("access_flags", 0))
        for member in parsed.get("methods", [])
        if isinstance(member, dict)
    }
    return _ClassAbi(
        class_name=str(parsed["class_name"]),
        access_flags=int(parsed["access_flags"]),
        fields=fields,
        methods=methods,
    )


def _member_key(member: dict[str, Any]) -> str:
    return f"{member.get('name')}:{member.get('descriptor')}"


def _split_member_key(key: str) -> tuple[str, str]:
    name, _, descriptor = key.partition(":")
    return name, descriptor


def _compare_abi(
    original: dict[str, _ClassAbi],
    rebuilt: dict[str, _ClassAbi],
    max_differences: int,
) -> list[JavaAbiDifference]:
    differences: list[JavaAbiDifference] = []

    for class_name in sorted(set(original) - set(rebuilt)):
        _add_difference(
            differences,
            max_differences,
            JavaAbiDifference(
                kind="missing_class",
                class_name=class_name,
                original_access_flags=original[class_name].access_flags,
                message=f"Rebuilt output is missing class {class_name}.",
            ),
        )
    for class_name in sorted(set(rebuilt) - set(original)):
        _add_difference(
            differences,
            max_differences,
            JavaAbiDifference(
                kind="extra_class",
                class_name=class_name,
                rebuilt_access_flags=rebuilt[class_name].access_flags,
                message=f"Rebuilt output contains extra class {class_name}.",
            ),
        )
    for class_name in sorted(set(original) & set(rebuilt)):
        _compare_class(
            original[class_name], rebuilt[class_name], differences, max_differences
        )
    return differences


def _compare_class(
    original: _ClassAbi,
    rebuilt: _ClassAbi,
    differences: list[JavaAbiDifference],
    max_differences: int,
) -> None:
    if original.access_flags != rebuilt.access_flags:
        _add_difference(
            differences,
            max_differences,
            JavaAbiDifference(
                kind="changed_class_access",
                class_name=original.class_name,
                original_access_flags=original.access_flags,
                rebuilt_access_flags=rebuilt.access_flags,
                message=f"Class access flags changed for {original.class_name}.",
            ),
        )
    _compare_members(
        class_name=original.class_name,
        original=original.fields,
        rebuilt=rebuilt.fields,
        missing_kind="missing_field",
        extra_kind="extra_field",
        changed_kind="changed_field_access",
        differences=differences,
        max_differences=max_differences,
    )
    _compare_members(
        class_name=original.class_name,
        original=original.methods,
        rebuilt=rebuilt.methods,
        missing_kind="missing_method",
        extra_kind="extra_method",
        changed_kind="changed_method_access",
        differences=differences,
        max_differences=max_differences,
    )


def _compare_members(
    *,
    class_name: str,
    original: dict[str, int],
    rebuilt: dict[str, int],
    missing_kind: AbiDifferenceKind,
    extra_kind: AbiDifferenceKind,
    changed_kind: AbiDifferenceKind,
    differences: list[JavaAbiDifference],
    max_differences: int,
) -> None:
    for key in sorted(set(original) - set(rebuilt)):
        name, descriptor = _split_member_key(key)
        _add_difference(
            differences,
            max_differences,
            JavaAbiDifference(
                kind=missing_kind,
                class_name=class_name,
                member_name=name,
                descriptor=descriptor,
                original_access_flags=original[key],
                message=f"Rebuilt output is missing {class_name}.{name}{descriptor}.",
            ),
        )
    for key in sorted(set(rebuilt) - set(original)):
        name, descriptor = _split_member_key(key)
        _add_difference(
            differences,
            max_differences,
            JavaAbiDifference(
                kind=extra_kind,
                class_name=class_name,
                member_name=name,
                descriptor=descriptor,
                rebuilt_access_flags=rebuilt[key],
                message=f"Rebuilt output adds {class_name}.{name}{descriptor}.",
            ),
        )
    for key in sorted(set(original) & set(rebuilt)):
        if original[key] == rebuilt[key]:
            continue
        name, descriptor = _split_member_key(key)
        _add_difference(
            differences,
            max_differences,
            JavaAbiDifference(
                kind=changed_kind,
                class_name=class_name,
                member_name=name,
                descriptor=descriptor,
                original_access_flags=original[key],
                rebuilt_access_flags=rebuilt[key],
                message=f"Access flags changed for {class_name}.{name}{descriptor}.",
            ),
        )


def _add_difference(
    differences: list[JavaAbiDifference],
    max_differences: int,
    difference: JavaAbiDifference,
) -> None:
    if max_differences == 0 or len(differences) < max_differences:
        differences.append(difference)


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _add_abi_node(kb: KnowledgeBase, result: JavaCompareRebuiltAbiResult) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                result.original_path,
                result.rebuilt_path or "",
                str(result.abi_match),
                str(result.difference_count),
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    kb.add_node(
        Node(
            kind=NodeKind.java_abi_comparison,
            label=f"abi {'match' if result.abi_match else 'diff'}: {digest}",
            text=(
                "Rebuilt ABI matches original."
                if result.abi_match
                else f"Rebuilt ABI differs with {result.difference_count} difference(s)."
            ),
            props={
                "tool": "java_compare_rebuilt_abi",
                "abi_comparison_id": digest,
                **result.model_dump(),
            },
            tags=["java", "abi", "verification"],
        )
    )


def build_tool() -> MemoryTool[JavaCompareRebuiltAbiArgs, JavaCompareRebuiltAbiResult]:
    return JavaCompareRebuiltAbiTool()
