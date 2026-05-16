from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from glaurung.java import JavaHelperError, run_jvm_tool

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaParseDecompiledSourceArgs(BaseModel):
    source_path: str | None = Field(None, description="Path to a Java source file")
    helper_jar: str | None = Field(
        None,
        description="Optional path to the glaurung-jvm-tools fat JAR",
    )
    timeout_seconds: int = Field(30, ge=1, le=600)


class JavaParseDecompiledSourceResult(BaseModel):
    source_path: str
    success: bool = False
    ast: dict[str, Any] = Field(default_factory=dict)
    helper_jar: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None
    diagnostics: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    parse_node_id: str | None = None


class JavaParseDecompiledSourceTool(
    MemoryTool[JavaParseDecompiledSourceArgs, JavaParseDecompiledSourceResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_parse_decompiled_source",
                description=(
                    "Parse a recovered or decompiled Java source file with "
                    "JavaParser through the Glaurung JVM helper and return a "
                    "compact AST summary."
                ),
                tags=("java", "source-recovery", "ast", "kb"),
            ),
            JavaParseDecompiledSourceArgs,
            JavaParseDecompiledSourceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaParseDecompiledSourceArgs,
    ) -> JavaParseDecompiledSourceResult:
        source_path = Path(args.source_path or ctx.file_path)
        if not source_path.is_file():
            return JavaParseDecompiledSourceResult(
                source_path=str(source_path),
                stop_reasons=["source_path_missing"],
            )

        try:
            raw = run_jvm_tool(
                ["parse-source", "--source", str(source_path)],
                helper_jar=args.helper_jar,
                timeout_seconds=args.timeout_seconds,
            )
        except JavaHelperError as exc:
            return JavaParseDecompiledSourceResult(
                source_path=str(source_path),
                diagnostics=[str(exc)],
                stop_reasons=["helper_unavailable"],
            )

        raw_ast = raw.get("ast")
        ast: dict[str, Any] = raw_ast if isinstance(raw_ast, dict) else {}
        ast_success = bool(ast.get("parse_success"))
        result = JavaParseDecompiledSourceResult(
            source_path=str(source_path),
            success=bool(raw.get("success")) and ast_success,
            ast=ast,
            helper_jar=_string_or_none(raw.get("helper_jar")),
            exit_code=raw.get("exit_code")
            if isinstance(raw.get("exit_code"), int)
            else None,
            timed_out=bool(raw.get("timed_out", False)),
            stdout_excerpt=_string_or_none(raw.get("stdout_excerpt")),
            stderr_excerpt=_string_or_none(raw.get("stderr_excerpt")),
            diagnostics=_problem_messages(ast),
            stop_reasons=_stop_reasons(raw, ast_success),
        )
        _add_parse_node(kb, result)
        return result


def _add_parse_node(kb: KnowledgeBase, result: JavaParseDecompiledSourceResult) -> None:
    node = Node(
        kind=NodeKind.java_decompile_unit,
        label=Path(result.source_path).name,
        text=(
            f"Parsed Java source {result.source_path}: "
            f"{'success' if result.success else 'failed'}."
        ),
        props={
            "tool": "java_parse_decompiled_source",
            **result.model_dump(exclude={"parse_node_id"}),
        },
        tags=["java", "source", "ast"],
    )
    kb.add_node(node)
    result.parse_node_id = node.id


def _stop_reasons(raw: dict[str, Any], ast_success: bool) -> list[str]:
    stop_reasons = _string_list(raw.get("stop_reasons"))
    if bool(raw.get("success")) and not ast_success:
        stop_reasons.append("source_parse_failed")
    return _dedupe(stop_reasons)


def _problem_messages(ast: dict[str, Any]) -> list[str]:
    problems = ast.get("problems")
    if not isinstance(problems, list):
        return []
    return [item for item in problems if isinstance(item, str)]


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def build_tool() -> MemoryTool[
    JavaParseDecompiledSourceArgs, JavaParseDecompiledSourceResult
]:
    return JavaParseDecompiledSourceTool()
