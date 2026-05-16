from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from glaurung.java import JavaHelperError, run_jvm_tool

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


JavaDecompilerEngine = Literal["auto", "cfr", "vineflower"]


class JavaDecompileClassArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_name: str | None = Field(
        None,
        description="Class name in internal or dotted form, such as app/Main or app.Main",
    )
    engine: JavaDecompilerEngine = "auto"
    helper_jar: str | None = Field(
        None,
        description="Optional path to the glaurung-jvm-tools fat JAR",
    )
    timeout_seconds: int = Field(60, ge=1, le=600)
    max_source_chars: int = Field(200_000, ge=0)
    include_source: bool = True


class JavaDecompileClassResult(BaseModel):
    archive_path: str
    sha256: str = ""
    class_name: str | None = None
    engine: str | None = None
    success: bool = False
    source: str | None = None
    source_length: int = 0
    source_truncated: bool = False
    ast: dict[str, Any] = Field(default_factory=dict)
    diagnostics: list[str] = Field(default_factory=list)
    diagnostic_count: int = 0
    helper_jar: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None
    stop_reasons: list[str] = Field(default_factory=list)
    decompile_node_id: str | None = None


class JavaDecompileClassTool(
    MemoryTool[JavaDecompileClassArgs, JavaDecompileClassResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_decompile_class",
                description=(
                    "Decompile one JVM class from a JAR through the Glaurung JVM "
                    "helper using CFR or Vineflower, then summarize the resulting "
                    "Java source with JavaParser."
                ),
                tags=("java", "decompile", "source-recovery", "ast", "kb"),
            ),
            JavaDecompileClassArgs,
            JavaDecompileClassResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDecompileClassArgs,
    ) -> JavaDecompileClassResult:
        archive_path = Path(args.path or ctx.file_path)
        digest = _sha256(archive_path)
        if args.class_name is None:
            return JavaDecompileClassResult(
                archive_path=str(archive_path),
                sha256=digest,
                stop_reasons=["class_name_missing"],
            )
        if not zipfile.is_zipfile(archive_path):
            return JavaDecompileClassResult(
                archive_path=str(archive_path),
                sha256=digest,
                class_name=args.class_name,
                stop_reasons=["input_not_zip"],
            )

        try:
            raw = run_jvm_tool(
                [
                    "decompile",
                    "--jar",
                    str(archive_path),
                    "--class",
                    args.class_name,
                    "--engine",
                    args.engine,
                    "--max-source-chars",
                    str(args.max_source_chars),
                ],
                helper_jar=args.helper_jar,
                timeout_seconds=args.timeout_seconds,
            )
        except JavaHelperError as exc:
            return JavaDecompileClassResult(
                archive_path=str(archive_path),
                sha256=digest,
                class_name=args.class_name,
                engine=args.engine,
                stop_reasons=["helper_unavailable"],
                diagnostics=[str(exc)],
                diagnostic_count=1,
            )

        source = raw.get("source") if isinstance(raw.get("source"), str) else None
        raw_ast = raw.get("ast")
        ast: dict[str, Any] = raw_ast if isinstance(raw_ast, dict) else {}
        result = JavaDecompileClassResult(
            archive_path=str(archive_path),
            sha256=digest,
            class_name=_string_or_none(raw.get("class_name")) or args.class_name,
            engine=_string_or_none(raw.get("engine")) or args.engine,
            success=bool(raw.get("success")),
            source=source if args.include_source else None,
            source_length=_int_or_zero(raw.get("source_length")),
            source_truncated=bool(raw.get("source_truncated", False)),
            ast=ast,
            diagnostics=_string_list(raw.get("diagnostics")),
            diagnostic_count=_int_or_zero(raw.get("diagnostic_count")),
            helper_jar=_string_or_none(raw.get("helper_jar")),
            exit_code=raw.get("exit_code")
            if isinstance(raw.get("exit_code"), int)
            else None,
            timed_out=bool(raw.get("timed_out", False)),
            stdout_excerpt=_string_or_none(raw.get("stdout_excerpt")),
            stderr_excerpt=_string_or_none(raw.get("stderr_excerpt")),
            stop_reasons=_string_list(raw.get("stop_reasons")),
        )
        _add_decompile_node(kb, result, include_source=args.include_source)
        return result


def _add_decompile_node(
    kb: KnowledgeBase,
    result: JavaDecompileClassResult,
    *,
    include_source: bool,
) -> None:
    node = Node(
        kind=NodeKind.java_decompile_unit,
        label=result.class_name or "decompiled-class",
        text=(
            result.source
            if include_source and result.source is not None
            else (
                f"Decompiled {result.class_name or 'class'} with "
                f"{result.engine or 'unknown'}: "
                f"{'success' if result.success else 'failed'}."
            )
        ),
        props={
            "tool": "java_decompile_class",
            **result.model_dump(exclude={"decompile_node_id"}),
        },
        tags=["java", "decompile", result.engine or "unknown"],
    )
    kb.add_node(node)
    result.decompile_node_id = node.id


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    except FileNotFoundError:
        return ""
    return h.hexdigest()


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) else 0


def build_tool() -> MemoryTool[JavaDecompileClassArgs, JavaDecompileClassResult]:
    return JavaDecompileClassTool()
