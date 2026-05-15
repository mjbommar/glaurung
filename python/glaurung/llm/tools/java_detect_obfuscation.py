from __future__ import annotations

import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaDetectObfuscationArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    max_classes: int = Field(20_000, ge=1)
    short_name_max_len: int = Field(3, ge=1, le=8)
    max_examples: int = Field(12, ge=0, le=100)


class JavaDetectObfuscationResult(BaseModel):
    archive_path: str
    class_count: int
    parsed_class_count: int
    truncated: bool
    level: str
    confidence: float
    short_class_name_count: int
    default_package_class_count: int
    short_member_name_count: int
    member_count: int
    short_class_examples: list[str]
    default_package_examples: list[str]
    short_member_examples: list[str]
    mapping_recommended: bool
    rationale: str
    note_node_id: str | None = None


class JavaDetectObfuscationTool(
    MemoryTool[JavaDetectObfuscationArgs, JavaDetectObfuscationResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_detect_obfuscation",
                description=(
                    "Assess Java/JAR obfuscation indicators and add a KB "
                    "annotation note with mapping/de-obfuscation guidance."
                ),
                tags=("java", "jvm", "obfuscation", "annotation", "kb"),
            ),
            JavaDetectObfuscationArgs,
            JavaDetectObfuscationResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDetectObfuscationArgs,
    ) -> JavaDetectObfuscationResult:
        path = Path(args.path or ctx.file_path)
        java_analysis = getattr(g, "analysis")

        class_count = 0
        parsed_class_count = 0
        default_package_class_count = 0
        short_class_name_count = 0
        member_count = 0
        short_member_name_count = 0
        short_class_examples: list[str] = []
        default_package_examples: list[str] = []
        short_member_examples: list[str] = []
        truncated = False

        if not zipfile.is_zipfile(path):
            return JavaDetectObfuscationResult(
                archive_path=str(path),
                class_count=0,
                parsed_class_count=0,
                truncated=False,
                level="none",
                confidence=0.0,
                short_class_name_count=0,
                default_package_class_count=0,
                short_member_name_count=0,
                member_count=0,
                short_class_examples=[],
                default_package_examples=[],
                short_member_examples=[],
                mapping_recommended=False,
                rationale="Input is not a ZIP/JAR archive.",
                note_node_id=None,
            )

        with zipfile.ZipFile(path) as zf:
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
                simple_name = _simple_class_name(class_name)
                if "/" not in class_name:
                    default_package_class_count += 1
                    _append_example(
                        default_package_examples, class_name, args.max_examples
                    )
                if _is_short_obfuscated_name(simple_name, args.short_name_max_len):
                    short_class_name_count += 1
                    _append_example(short_class_examples, class_name, args.max_examples)

                for member in [*parsed["methods"], *parsed["fields"]]:
                    name = str(member["name"])
                    if name in {"<init>", "<clinit>"}:
                        continue
                    member_count += 1
                    if _is_short_obfuscated_name(name, args.short_name_max_len):
                        short_member_name_count += 1
                        _append_example(
                            short_member_examples,
                            f"{class_name}#{name}{member['descriptor']}",
                            args.max_examples,
                        )
            truncated = class_count > args.max_classes

        confidence = _confidence(
            parsed_class_count=parsed_class_count,
            short_class_name_count=short_class_name_count,
            default_package_class_count=default_package_class_count,
            member_count=member_count,
            short_member_name_count=short_member_name_count,
        )
        level = _level(confidence)
        mapping_recommended = level in {"medium", "high"}
        rationale = _rationale(
            level=level,
            confidence=confidence,
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            short_class_name_count=short_class_name_count,
            default_package_class_count=default_package_class_count,
            short_member_name_count=short_member_name_count,
            member_count=member_count,
            truncated=truncated,
        )

        note = kb.add_node(
            Node(
                kind=NodeKind.note,
                label=f"Java obfuscation: {level}",
                text=rationale,
                props={
                    "tool": "java_detect_obfuscation",
                    "archive_path": str(path),
                    "confidence": confidence,
                    "mapping_recommended": mapping_recommended,
                    "short_class_examples": short_class_examples,
                    "default_package_examples": default_package_examples,
                    "short_member_examples": short_member_examples,
                },
                tags=["java", "obfuscation", "annotation"],
            )
        )

        return JavaDetectObfuscationResult(
            archive_path=str(path),
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            truncated=truncated,
            level=level,
            confidence=confidence,
            short_class_name_count=short_class_name_count,
            default_package_class_count=default_package_class_count,
            short_member_name_count=short_member_name_count,
            member_count=member_count,
            short_class_examples=short_class_examples,
            default_package_examples=default_package_examples,
            short_member_examples=short_member_examples,
            mapping_recommended=mapping_recommended,
            rationale=rationale,
            note_node_id=note.id,
        )


def _simple_class_name(class_name: str) -> str:
    return class_name.rsplit("/", 1)[-1].split("$", 1)[0]


def _is_short_obfuscated_name(name: str, max_len: int) -> bool:
    if len(name) > max_len:
        return False
    if not name:
        return False
    return name[0].isalpha() and all(ch.isalnum() or ch == "_" for ch in name)


def _append_example(items: list[str], value: str, limit: int) -> None:
    if len(items) < limit and value not in items:
        items.append(value)


def _confidence(
    *,
    parsed_class_count: int,
    short_class_name_count: int,
    default_package_class_count: int,
    member_count: int,
    short_member_name_count: int,
) -> float:
    if parsed_class_count == 0:
        return 0.0
    short_class_ratio = short_class_name_count / parsed_class_count
    default_package_ratio = default_package_class_count / parsed_class_count
    short_member_ratio = short_member_name_count / member_count if member_count else 0.0
    score = (
        0.50 * short_class_ratio
        + 0.15 * default_package_ratio
        + 0.35 * short_member_ratio
    )
    return round(min(score, 1.0), 3)


def _level(confidence: float) -> str:
    if confidence >= 0.65:
        return "high"
    if confidence >= 0.35:
        return "medium"
    if confidence >= 0.10:
        return "low"
    return "none"


def _rationale(
    *,
    level: str,
    confidence: float,
    class_count: int,
    parsed_class_count: int,
    short_class_name_count: int,
    default_package_class_count: int,
    short_member_name_count: int,
    member_count: int,
    truncated: bool,
) -> str:
    parts = [
        f"Java obfuscation assessment: {level} (confidence {confidence:.3f}).",
        f"Parsed {parsed_class_count}/{class_count} classes.",
        f"Short class names: {short_class_name_count}.",
        f"Default-package classes: {default_package_class_count}.",
        f"Short member names: {short_member_name_count}/{member_count}.",
    ]
    if truncated:
        parts.append("Assessment was truncated by max_classes.")
    if level in {"medium", "high"}:
        parts.append(
            "Load mappings or run de-obfuscation before making semantic claims."
        )
    else:
        parts.append("No strong short-name obfuscation signal was detected.")
    return " ".join(parts)


def build_tool() -> MemoryTool[JavaDetectObfuscationArgs, JavaDetectObfuscationResult]:
    return JavaDetectObfuscationTool()
