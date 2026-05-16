from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_parse_decompiled_source import build_tool as build_java_parse_source


class JavaIndexSourceProjectArgs(BaseModel):
    source_project_root: str | None = Field(None, description="Recovered project root")
    source_root: str = "src/main/java"
    helper_jar: str | None = None
    max_sources: int = Field(2_000, ge=0)
    max_types: int = Field(4_000, ge=0)
    max_problems: int = Field(256, ge=0)
    timeout_seconds_per_file: int = Field(30, ge=1, le=600)


class JavaIndexedField(BaseModel):
    source_path: str
    package_name: str | None = None
    type_name: str
    name: str
    field_type: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)


class JavaIndexedMethod(BaseModel):
    source_path: str
    package_name: str | None = None
    type_name: str
    name: str
    return_type: str | None = None
    parameter_count: int = 0
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    modifiers: list[str] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)
    thrown_exceptions: list[str] = Field(default_factory=list)


class JavaIndexedType(BaseModel):
    source_path: str
    package_name: str | None = None
    name: str
    kind: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)
    fields: list[JavaIndexedField] = Field(default_factory=list)
    methods: list[JavaIndexedMethod] = Field(default_factory=list)


class JavaSourceSyntaxProblem(BaseModel):
    source_path: str
    message: str


class JavaIndexSourceProjectResult(BaseModel):
    source_project_root: str
    source_root: str
    source_count: int = 0
    parsed_source_count: int = 0
    parse_success_count: int = 0
    parse_error_count: int = 0
    package_count: int = 0
    packages: list[str] = Field(default_factory=list)
    import_count: int = 0
    imports: list[str] = Field(default_factory=list)
    type_count: int = 0
    types: list[JavaIndexedType] = Field(default_factory=list)
    method_count: int = 0
    field_count: int = 0
    syntax_problem_count: int = 0
    syntax_problems: list[JavaSourceSyntaxProblem] = Field(default_factory=list)
    source_ast_node_ids: list[str] = Field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    index_node_id: str | None = None


class JavaIndexSourceProjectTool(
    MemoryTool[JavaIndexSourceProjectArgs, JavaIndexSourceProjectResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_index_source_project",
                description=(
                    "Parse and aggregate a recovered Java source tree into a "
                    "project-level AST index of packages, imports, types, fields, "
                    "methods, annotations, thrown exceptions, and syntax problems."
                ),
                tags=("java", "source-recovery", "ast", "index", "kb"),
            ),
            JavaIndexSourceProjectArgs,
            JavaIndexSourceProjectResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaIndexSourceProjectArgs,
    ) -> JavaIndexSourceProjectResult:
        root = Path(args.source_project_root or ctx.file_path)
        source_root = root / args.source_root
        if not root.is_dir():
            return JavaIndexSourceProjectResult(
                source_project_root=str(root),
                source_root=str(source_root),
                stop_reasons=["source_project_root_missing"],
            )
        if not source_root.is_dir():
            return JavaIndexSourceProjectResult(
                source_project_root=str(root),
                source_root=str(source_root),
                stop_reasons=["source_root_missing"],
            )

        parse_tool = build_java_parse_source()
        result = JavaIndexSourceProjectResult(
            source_project_root=str(root),
            source_root=str(source_root),
        )
        packages: set[str] = set()
        imports: set[str] = set()
        for source in sorted(source_root.rglob("*.java")):
            if result.source_count >= args.max_sources:
                result.truncated = True
                _append_once(result.stop_reasons, "max_sources")
                break
            result.source_count += 1
            parsed = parse_tool.run(
                ctx,
                kb,
                parse_tool.input_model(
                    source_path=str(source),
                    helper_jar=args.helper_jar,
                    timeout_seconds=args.timeout_seconds_per_file,
                ),
            )
            if parsed.ast_node_id:
                result.source_ast_node_ids.append(parsed.ast_node_id)
            result.parsed_source_count += 1
            if parsed.success:
                result.parse_success_count += 1
            else:
                result.parse_error_count += 1
            _append_problems(result, root, source, parsed.diagnostics, args)
            ast = parsed.ast
            package_name = _string_or_none(ast.get("package_name"))
            if package_name:
                packages.add(package_name)
            for import_name in _string_list(ast.get("imports")):
                imports.add(import_name)
            _append_types(result, root, source, package_name, ast, args)

        result.packages = sorted(packages)
        result.package_count = len(result.packages)
        result.imports = sorted(imports)
        result.import_count = len(result.imports)
        result.type_count = len(result.types)
        result.method_count = sum(len(item.methods) for item in result.types)
        result.field_count = sum(len(item.fields) for item in result.types)
        result.syntax_problem_count = len(result.syntax_problems)
        _add_index_node(kb, result)
        return result


def _append_types(
    result: JavaIndexSourceProjectResult,
    root: Path,
    source: Path,
    package_name: str | None,
    ast: dict[str, Any],
    args: JavaIndexSourceProjectArgs,
) -> None:
    for raw_type in _dict_list(ast.get("types")):
        if len(result.types) >= args.max_types:
            result.truncated = True
            _append_once(result.stop_reasons, "max_types")
            return
        type_name = _string_or_none(raw_type.get("name")) or "<anonymous>"
        indexed = JavaIndexedType(
            source_path=_relative(root, source),
            package_name=package_name,
            name=type_name,
            kind=_string_or_none(raw_type.get("kind")),
            modifiers=_string_list(raw_type.get("modifiers")),
            annotations=_string_list(raw_type.get("annotations")),
        )
        for raw_field in _dict_list(raw_type.get("fields")):
            indexed.fields.append(
                JavaIndexedField(
                    source_path=indexed.source_path,
                    package_name=package_name,
                    type_name=type_name,
                    name=_string_or_none(raw_field.get("name")) or "<unknown>",
                    field_type=_string_or_none(raw_field.get("type")),
                    modifiers=_string_list(raw_field.get("modifiers")),
                    annotations=_string_list(raw_field.get("annotations")),
                )
            )
        for raw_method in _dict_list(raw_type.get("method_details")):
            indexed.methods.append(
                JavaIndexedMethod(
                    source_path=indexed.source_path,
                    package_name=package_name,
                    type_name=type_name,
                    name=_string_or_none(raw_method.get("name")) or "<unknown>",
                    return_type=_string_or_none(raw_method.get("return_type")),
                    parameter_count=_int_or_zero(raw_method.get("parameter_count")),
                    parameters=_dict_list(raw_method.get("parameters")),
                    modifiers=_string_list(raw_method.get("modifiers")),
                    annotations=_string_list(raw_method.get("annotations")),
                    thrown_exceptions=_string_list(raw_method.get("thrown_exceptions")),
                )
            )
        result.types.append(indexed)


def _append_problems(
    result: JavaIndexSourceProjectResult,
    root: Path,
    source: Path,
    diagnostics: list[str],
    args: JavaIndexSourceProjectArgs,
) -> None:
    for diagnostic in diagnostics:
        if len(result.syntax_problems) >= args.max_problems:
            result.truncated = True
            _append_once(result.stop_reasons, "max_problems")
            return
        result.syntax_problems.append(
            JavaSourceSyntaxProblem(
                source_path=_relative(root, source),
                message=diagnostic,
            )
        )


def _add_index_node(
    kb: KnowledgeBase,
    result: JavaIndexSourceProjectResult,
) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                result.source_project_root,
                str(result.source_count),
                str(result.parse_success_count),
                str(result.parse_error_count),
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    node = Node(
        kind=NodeKind.java_source_project_index,
        label=f"source index {digest}",
        text=(
            f"Indexed {result.source_count} Java source file(s), "
            f"{result.type_count} type(s), {result.method_count} method(s), and "
            f"{result.syntax_problem_count} syntax problem(s)."
        ),
        props={
            "tool": "java_index_source_project",
            "java_source_project_index_id": digest,
            **result.model_dump(exclude={"index_node_id"}),
        },
        tags=["java", "source", "ast", "index"],
    )
    kb.add_node(node)
    result.index_node_id = node.id


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) else 0


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def build_tool() -> MemoryTool[
    JavaIndexSourceProjectArgs, JavaIndexSourceProjectResult
]:
    return JavaIndexSourceProjectTool()
