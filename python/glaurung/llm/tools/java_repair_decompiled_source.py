from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_compile_recovered_project import (
    JavaCompileRecoveredProjectResult,
    JavaCompileTool,
    build_tool as build_java_compile_recovered_project,
)


JavaRepairKind = Literal["rename_public_type_file"]


class JavaRepairDecompiledSourceArgs(BaseModel):
    source_project_root: str | None = Field(None, description="Recovered project root")
    build_tool: JavaCompileTool = "javac"
    java_home: str | None = None
    java_release: int | None = Field(None, ge=1)
    javac_args_file: str = "javac.args"
    sources_file: str = "sources.txt"
    classpath: list[str] = Field(default_factory=list)
    max_iterations: int = Field(3, ge=1, le=10)
    max_repairs_per_iteration: int = Field(8, ge=0)
    max_diagnostics: int = Field(64, ge=0)
    timeout_seconds: int = Field(30, ge=1, le=600)
    dry_run: bool = False


class JavaSourceRepair(BaseModel):
    iteration: int
    kind: JavaRepairKind
    file: str
    new_file: str
    applied: bool
    message: str


class JavaRepairDecompiledSourceResult(BaseModel):
    source_project_root: str
    success: bool = False
    dry_run: bool = False
    iteration_count: int = 0
    repair_count: int = 0
    repairs: list[JavaSourceRepair] = Field(default_factory=list)
    compile_results: list[JavaCompileRecoveredProjectResult] = Field(
        default_factory=list
    )
    final_compile_result: JavaCompileRecoveredProjectResult | None = None
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    repair_node_id: str | None = None


class JavaRepairDecompiledSourceTool(
    MemoryTool[JavaRepairDecompiledSourceArgs, JavaRepairDecompiledSourceResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_repair_decompiled_source",
                description=(
                    "Run a bounded compile-repair loop for recovered Java source. "
                    "The initial implementation applies safe mechanical repairs "
                    "from javac diagnostics, then recompiles and records every "
                    "attempt."
                ),
                tags=("java", "source-recovery", "compile", "repair", "kb"),
            ),
            JavaRepairDecompiledSourceArgs,
            JavaRepairDecompiledSourceResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaRepairDecompiledSourceArgs,
    ) -> JavaRepairDecompiledSourceResult:
        root = Path(args.source_project_root or ctx.file_path)
        if not root.is_dir():
            return JavaRepairDecompiledSourceResult(
                source_project_root=str(root),
                dry_run=args.dry_run,
                stop_reasons=["source_project_root_missing"],
            )

        result = JavaRepairDecompiledSourceResult(
            source_project_root=str(root),
            dry_run=args.dry_run,
        )
        compile_tool = build_java_compile_recovered_project()

        for iteration in range(args.max_iterations):
            compile_result = compile_tool.run(
                ctx,
                kb,
                compile_tool.input_model(
                    source_project_root=str(root),
                    build_tool=args.build_tool,
                    java_home=args.java_home,
                    java_release=args.java_release,
                    javac_args_file=args.javac_args_file,
                    sources_file=args.sources_file,
                    classpath=args.classpath,
                    max_diagnostics=args.max_diagnostics,
                    timeout_seconds=args.timeout_seconds,
                ),
            )
            result.compile_results.append(compile_result)
            result.final_compile_result = compile_result
            result.iteration_count = iteration + 1
            if compile_result.success:
                result.success = True
                result.repair_count = sum(
                    1 for repair in result.repairs if repair.applied
                )
                _add_repair_node(kb, result)
                return result

            repairs = _repairs_for_compile_result(
                root,
                compile_result,
                iteration=iteration,
                dry_run=args.dry_run,
                max_repairs=args.max_repairs_per_iteration,
            )
            result.repairs.extend(repairs)
            if not repairs:
                _append_once(result.stop_reasons, "no_applicable_repairs")
                break
            if args.dry_run:
                _append_once(result.stop_reasons, "dry_run")
                break
            _rewrite_sources_file(root, args.sources_file)
            if len(repairs) >= args.max_repairs_per_iteration > 0:
                _append_once(result.stop_reasons, "max_repairs_per_iteration")

        if not result.success and result.iteration_count >= args.max_iterations:
            _append_once(result.stop_reasons, "max_iterations")
        result.repair_count = sum(1 for repair in result.repairs if repair.applied)
        _add_repair_node(kb, result)
        return result


_PUBLIC_TYPE_FILENAME_RE = re.compile(
    r"(?:class|interface|enum|record)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+is public, "
    r"should be declared in a file named ([A-Za-z_$][A-Za-z0-9_$]*\.java)"
)


def _repairs_for_compile_result(
    root: Path,
    compile_result: JavaCompileRecoveredProjectResult,
    *,
    iteration: int,
    dry_run: bool,
    max_repairs: int,
) -> list[JavaSourceRepair]:
    repairs: list[JavaSourceRepair] = []
    if max_repairs == 0:
        return repairs
    for diagnostic in compile_result.diagnostics:
        if len(repairs) >= max_repairs:
            break
        match = _PUBLIC_TYPE_FILENAME_RE.search(diagnostic.message)
        if match is None or diagnostic.file is None:
            continue
        source_file = _resolve_under_root(root, diagnostic.file)
        if source_file is None or not source_file.is_file():
            continue
        demanded_file = match.group(2)
        target_file = source_file.with_name(demanded_file)
        if target_file == source_file:
            continue
        if target_file.exists():
            repairs.append(
                JavaSourceRepair(
                    iteration=iteration,
                    kind="rename_public_type_file",
                    file=_relative(root, source_file),
                    new_file=_relative(root, target_file),
                    applied=False,
                    message="Target file already exists; manual merge is required.",
                )
            )
            continue
        if not dry_run:
            source_file.rename(target_file)
        repairs.append(
            JavaSourceRepair(
                iteration=iteration,
                kind="rename_public_type_file",
                file=_relative(root, source_file),
                new_file=_relative(root, target_file),
                applied=not dry_run,
                message=f"Renamed source file to match public type {match.group(1)}.",
            )
        )
    return repairs


def _resolve_under_root(root: Path, value: str) -> Path | None:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def _rewrite_sources_file(root: Path, sources_file: str) -> None:
    source_root = root / "src" / "main" / "java"
    if not source_root.is_dir():
        return
    sources = sorted(path for path in source_root.rglob("*.java") if path.is_file())
    (root / sources_file).write_text(
        "\n".join(_relative(root, source) for source in sources) + "\n",
        encoding="utf-8",
    )


def _add_repair_node(
    kb: KnowledgeBase,
    result: JavaRepairDecompiledSourceResult,
) -> None:
    node = Node(
        kind=NodeKind.java_repair_result,
        label=f"repair: {'pass' if result.success else 'fail'}",
        text=(
            f"Compile-repair loop {'succeeded' if result.success else 'stopped'} "
            f"after {result.iteration_count} iteration(s) with "
            f"{result.repair_count} applied repair(s)."
        ),
        props={
            "tool": "java_repair_decompiled_source",
            **result.model_dump(exclude={"repair_node_id"}),
        },
        tags=["java", "repair", "compile"],
    )
    kb.add_node(node)
    result.repair_node_id = node.id


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def build_tool() -> MemoryTool[
    JavaRepairDecompiledSourceArgs, JavaRepairDecompiledSourceResult
]:
    return JavaRepairDecompiledSourceTool()
