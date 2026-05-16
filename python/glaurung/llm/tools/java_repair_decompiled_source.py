from __future__ import annotations

import json
import re
import zipfile
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


JavaRepairKind = Literal[
    "rename_public_type_file",
    "rewrite_inner_companion_declaration",
    "add_missing_import",
    "ambiguous_missing_import",
    "add_local_classpath_jar",
    "write_build_repair_plan",
    "report_signature_mismatch",
    "report_enum_record_sealed_reconstruction",
    "report_malformed_anonymous_class",
    "report_bad_cast",
    "report_synthetic_bridge_noise",
]


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
            if len(repairs) < args.max_repairs_per_iteration:
                repairs.extend(
                    _repair_missing_local_dependencies(
                        root,
                        compile_result,
                        iteration=iteration,
                        dry_run=args.dry_run,
                        max_repairs=args.max_repairs_per_iteration - len(repairs),
                        java_release=args.java_release,
                        sources_file=args.sources_file,
                        javac_args_file=args.javac_args_file,
                    )
                )
            if len(repairs) < args.max_repairs_per_iteration:
                if not any(
                    repair.kind == "add_local_classpath_jar" and repair.applied
                    for repair in repairs
                ):
                    repairs.extend(
                        _write_build_repair_plan(
                            root,
                            compile_result,
                            iteration=iteration,
                            dry_run=args.dry_run,
                            max_repairs=args.max_repairs_per_iteration - len(repairs),
                        )
                    )
            if len(repairs) < args.max_repairs_per_iteration:
                repairs.extend(
                    _repair_missing_imports(
                        root,
                        compile_result,
                        iteration=iteration,
                        dry_run=args.dry_run,
                        max_repairs=args.max_repairs_per_iteration - len(repairs),
                    )
                )
            if len(repairs) < args.max_repairs_per_iteration:
                repairs.extend(
                    _repair_inner_companion_declarations(
                        root,
                        iteration=iteration,
                        dry_run=args.dry_run,
                        max_repairs=args.max_repairs_per_iteration - len(repairs),
                    )
                )
            if len(repairs) < args.max_repairs_per_iteration:
                repairs.extend(
                    _report_deeper_repair_candidates(
                        root,
                        compile_result,
                        iteration=iteration,
                        max_repairs=args.max_repairs_per_iteration - len(repairs),
                    )
                )
            result.repairs.extend(repairs)
            if not repairs:
                _append_once(result.stop_reasons, "no_applicable_repairs")
                break
            if args.dry_run:
                _append_once(result.stop_reasons, "dry_run")
                break
            if not any(repair.applied for repair in repairs):
                _append_once(result.stop_reasons, "no_applicable_repairs")
                break
            if any(
                repair.kind == "write_build_repair_plan" and repair.applied
                for repair in repairs
            ) and not any(
                repair.applied and repair.kind != "write_build_repair_plan"
                for repair in repairs
            ):
                _append_once(result.stop_reasons, "build_repair_plan_written")
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
_INNER_COMPANION_DECL_RE = re.compile(
    r"\b(?P<access>public|protected|private)?\s*"
    r"(?:static\s+)?"
    r"(?P<kind>class|interface|enum)\s+"
    r"(?P<outer>[A-Za-z_$][A-Za-z0-9_$]*)\."
    r"(?P<inner>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?P<suffix>\s*(?:<[^>{;]+>)?)"
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


def _repair_missing_local_dependencies(
    root: Path,
    compile_result: JavaCompileRecoveredProjectResult,
    *,
    iteration: int,
    dry_run: bool,
    max_repairs: int,
    java_release: int | None,
    sources_file: str,
    javac_args_file: str,
) -> list[JavaSourceRepair]:
    if max_repairs == 0 or compile_result.selected_build_tool != "javac":
        return []
    missing_targets = _missing_import_targets(compile_result)
    if not missing_targets:
        return []
    jars = _matching_local_jars(root, missing_targets)
    if not jars:
        return []
    _rewrite_sources_file(root, sources_file)
    argfile = root / javac_args_file
    classpath = ":".join(_relative(root, jar) for jar in jars)
    content = "\n".join(
        [
            "--release",
            str(java_release or 17),
            "-classpath",
            classpath,
            "-d",
            "build/classes",
            f"@{sources_file}",
            "",
        ]
    )
    if not dry_run:
        argfile.write_text(content, encoding="utf-8")
    return [
        JavaSourceRepair(
            iteration=iteration,
            kind="add_local_classpath_jar",
            file=javac_args_file,
            new_file=javac_args_file,
            applied=not dry_run,
            message=(
                "Added local classpath jar(s) for missing dependency target(s): "
                + ", ".join(_relative(root, jar) for jar in jars[:max_repairs])
            ),
        )
    ]


def _write_build_repair_plan(
    root: Path,
    compile_result: JavaCompileRecoveredProjectResult,
    *,
    iteration: int,
    dry_run: bool,
    max_repairs: int,
) -> list[JavaSourceRepair]:
    if max_repairs == 0:
        return []
    targets = _missing_external_dependency_targets(compile_result)
    if not targets:
        return []
    candidate_jars = _matching_local_jars(root, targets)
    plan_path = root / ".glaurung" / "build-repair-plan.json"
    plan = {
        "tool": "java_repair_decompiled_source",
        "reason": "missing_external_dependencies",
        "selected_build_tool": compile_result.selected_build_tool,
        "missing_targets": targets,
        "local_candidate_jars": [_relative(root, jar) for jar in candidate_jars],
        "suggested_actions": [
            "Add the matching local jar to javac.args, Maven, or Gradle before editing source.",
            "If no local jar matches, resolve the dependency explicitly through the project dependency policy.",
        ],
    }
    if not dry_run:
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(
            json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return [
        JavaSourceRepair(
            iteration=iteration,
            kind="write_build_repair_plan",
            file=_relative(root, plan_path),
            new_file=_relative(root, plan_path),
            applied=not dry_run,
            message=(
                "Wrote dependency/build repair plan for missing external target(s): "
                + ", ".join(targets)
            ),
        )
    ]


def _repair_missing_imports(
    root: Path,
    compile_result: JavaCompileRecoveredProjectResult,
    *,
    iteration: int,
    dry_run: bool,
    max_repairs: int,
) -> list[JavaSourceRepair]:
    if max_repairs == 0 or compile_result.selected_build_tool != "javac":
        return []
    index = _source_type_index(root)
    if not index:
        return []
    repairs: list[JavaSourceRepair] = []
    repaired_files: set[Path] = set()
    for diagnostic in compile_result.diagnostics:
        if len(repairs) >= max_repairs:
            break
        if diagnostic.file is None:
            continue
        if diagnostic.category not in {
            "missing_import",
            "missing_classpath_dependency",
        }:
            continue
        simple_name = _missing_simple_type_name(diagnostic.package_or_class)
        if simple_name is None:
            continue
        candidates = index.get(simple_name, [])
        source_file = _resolve_under_root(root, diagnostic.file)
        if source_file in repaired_files:
            continue
        if source_file is None or not source_file.is_file():
            continue
        if len(candidates) > 1:
            repairs.append(
                JavaSourceRepair(
                    iteration=iteration,
                    kind="ambiguous_missing_import",
                    file=_relative(root, source_file),
                    new_file=_relative(root, source_file),
                    applied=False,
                    message=(
                        f"Unresolved type {simple_name} matches multiple local "
                        "source types: "
                        + ", ".join(candidate[1] for candidate in candidates)
                    ),
                )
            )
            continue
        if len(candidates) != 1:
            continue
        package_name, fqcn, candidate_file = candidates[0]
        if candidate_file == source_file:
            continue
        text = source_file.read_text(encoding="utf-8", errors="replace")
        source_package = _source_package(text)
        if source_package == package_name or f"import {fqcn};" in text:
            continue
        rewritten = _insert_import(text, fqcn)
        if rewritten == text:
            continue
        if not dry_run:
            source_file.write_text(rewritten, encoding="utf-8")
        repaired_files.add(source_file)
        repairs.append(
            JavaSourceRepair(
                iteration=iteration,
                kind="add_missing_import",
                file=_relative(root, source_file),
                new_file=_relative(root, source_file),
                applied=not dry_run,
                message=f"Added import {fqcn} for unresolved type {simple_name}.",
            )
        )
    return repairs


def _report_deeper_repair_candidates(
    root: Path,
    compile_result: JavaCompileRecoveredProjectResult,
    *,
    iteration: int,
    max_repairs: int,
) -> list[JavaSourceRepair]:
    if max_repairs == 0:
        return []
    repairs: list[JavaSourceRepair] = []
    for diagnostic in compile_result.diagnostics:
        if len(repairs) >= max_repairs:
            break
        source_file = (
            _resolve_under_root(root, diagnostic.file) if diagnostic.file else None
        )
        file_label = (
            _relative(root, source_file)
            if source_file is not None and source_file.is_file()
            else diagnostic.file or ""
        )
        kind: JavaRepairKind | None = None
        message = diagnostic.message
        raw = diagnostic.raw_excerpt.lower()
        if diagnostic.category == "generic_signature_mismatch":
            kind = "report_signature_mismatch"
        elif diagnostic.category == "enum_record_sealed_reconstruction":
            kind = "report_enum_record_sealed_reconstruction"
        elif diagnostic.category == "lambda_or_anonymous_reconstruction":
            kind = "report_malformed_anonymous_class"
        elif "unavailable anonymous inner class" in raw:
            kind = "report_malformed_anonymous_class"
        elif "cannot cast" in raw or "inconvertible types" in raw:
            kind = "report_bad_cast"
        elif "bridge" in raw and "synthetic" in raw:
            kind = "report_synthetic_bridge_noise"
        if kind is None:
            continue
        repairs.append(
            JavaSourceRepair(
                iteration=iteration,
                kind=kind,
                file=file_label,
                new_file=file_label,
                applied=False,
                message=(
                    "Deferred non-mechanical repair; use bytecode descriptors and "
                    f"AST evidence before editing source: {message}"
                ),
            )
        )
    return repairs


_PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;")
_IMPORT_RE = re.compile(r"(?m)^\s*import\s+(?:static\s+)?[A-Za-z0-9_.*]+\s*;")
_TYPE_DECL_RE = re.compile(
    r"(?m)^\s*(?:public\s+)?(?:abstract\s+|final\s+|sealed\s+|non-sealed\s+)*"
    r"(class|interface|enum|record)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b"
)


def _source_type_index(root: Path) -> dict[str, list[tuple[str, str, Path]]]:
    source_root = root / "src" / "main" / "java"
    if not source_root.is_dir():
        return {}
    index: dict[str, list[tuple[str, str, Path]]] = {}
    for source_file in sorted(source_root.rglob("*.java")):
        text = source_file.read_text(encoding="utf-8", errors="replace")
        package_name = _source_package(text)
        for match in _TYPE_DECL_RE.finditer(text):
            simple = match.group(2)
            fqcn = f"{package_name}.{simple}" if package_name else simple
            index.setdefault(simple, []).append((package_name, fqcn, source_file))
    return index


def _missing_simple_type_name(value: str | None) -> str | None:
    if not value:
        return None
    simple = value.rsplit(".", 1)[-1].strip()
    if re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*$", simple):
        return simple
    return None


def _source_package(text: str) -> str:
    match = _PACKAGE_RE.search(text)
    return match.group(1) if match else ""


def _insert_import(text: str, fqcn: str) -> str:
    lines = text.splitlines()
    insert_at = 0
    for idx, line in enumerate(lines):
        if line.strip().startswith("package "):
            insert_at = idx + 1
            break
    for idx, line in enumerate(lines):
        if _IMPORT_RE.match(line):
            insert_at = idx + 1
    while insert_at < len(lines) and lines[insert_at].strip() == "":
        insert_at += 1
    lines.insert(insert_at, f"import {fqcn};")
    lines.insert(insert_at + 1, "")
    return "\n".join(lines).rstrip() + "\n"


def _missing_import_targets(
    compile_result: JavaCompileRecoveredProjectResult,
) -> list[str]:
    out: list[str] = []
    for diagnostic in compile_result.diagnostics:
        if diagnostic.category != "missing_classpath_dependency":
            continue
        import_match = re.search(
            r"\(from import ([A-Za-z0-9_.*]+)\)", diagnostic.message
        )
        if import_match is not None:
            _append_once(out, import_match.group(1).removesuffix(".*"))
            continue
        if diagnostic.package_or_class:
            _append_once(out, diagnostic.package_or_class)
    return out


def _missing_external_dependency_targets(
    compile_result: JavaCompileRecoveredProjectResult,
) -> list[str]:
    return [
        target
        for target in _missing_import_targets(compile_result)
        if "." in target or target.endswith(".*")
    ]


def _matching_local_jars(root: Path, targets: list[str]) -> list[Path]:
    candidates = [
        jar
        for lib_dir_name in ("libs", "lib")
        for jar in (root / lib_dir_name).glob("*.jar")
        if jar.is_file()
    ]
    matches: list[Path] = []
    for jar in sorted(candidates):
        if _jar_matches_any_target(jar, targets):
            matches.append(jar)
    return matches


def _jar_matches_any_target(jar: Path, targets: list[str]) -> bool:
    try:
        with zipfile.ZipFile(jar) as zf:
            entries = {
                info.filename
                for info in zf.infolist()
                if not info.is_dir() and info.filename.endswith(".class")
            }
    except zipfile.BadZipFile:
        return False
    for target in targets:
        internal = target.replace(".", "/")
        if f"{internal}.class" in entries:
            return True
        if any(entry.startswith(internal.rstrip("/") + "/") for entry in entries):
            return True
    return False


def _repair_inner_companion_declarations(
    root: Path,
    *,
    iteration: int,
    dry_run: bool,
    max_repairs: int,
) -> list[JavaSourceRepair]:
    if max_repairs == 0:
        return []
    source_root = root / "src" / "main" / "java"
    if not source_root.is_dir():
        return []
    repairs: list[JavaSourceRepair] = []
    for source_file in sorted(source_root.rglob("*$*.java")):
        if len(repairs) >= max_repairs:
            break
        text = source_file.read_text(encoding="utf-8", errors="replace")
        rewritten = _rewrite_inner_companion_text(text, source_file.stem)
        if rewritten == text:
            continue
        if not dry_run:
            source_file.write_text(rewritten, encoding="utf-8")
        repairs.append(
            JavaSourceRepair(
                iteration=iteration,
                kind="rewrite_inner_companion_declaration",
                file=_relative(root, source_file),
                new_file=_relative(root, source_file),
                applied=not dry_run,
                message=(
                    "Rewrote dotted nested type declaration into a legal "
                    "top-level companion declaration."
                ),
            )
        )
    return repairs


def _rewrite_inner_companion_text(text: str, expected_stem: str) -> str:
    if "$" not in expected_stem:
        return text

    def replacement(match: re.Match[str]) -> str:
        declared_stem = f"{match.group('outer')}${match.group('inner')}"
        if declared_stem != expected_stem:
            return match.group(0)
        access = "public " if match.group("access") == "public" else ""
        return f"{access}{match.group('kind')} {declared_stem}{match.group('suffix')}"

    return _INNER_COMPANION_DECL_RE.sub(replacement, text, count=1)


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
