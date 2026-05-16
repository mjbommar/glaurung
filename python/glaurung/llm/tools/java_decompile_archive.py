from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from pydantic import BaseModel, Field

from glaurung.java import JavaHelperError, run_jvm_tool

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_proguard_mappings import (
    ProguardClassMapping,
    ProguardMappings,
    parse_proguard_mappings,
)


JavaDecompilerEngine = Literal["auto", "cfr", "vineflower"]
JavaConcreteDecompilerEngine = Literal["cfr", "vineflower"]
JavaInnerClassPolicy = Literal["skip", "companion", "merge"]
JavaInnerClassKind = Literal[
    "top_level",
    "named_inner",
    "anonymous",
    "lambda",
    "synthetic",
]
JavaInnerClassAction = Literal[
    "emitted_top_level",
    "emitted_companion",
    "merged_into_outer",
    "suppressed",
    "skipped",
    "not_written",
]
JavaDecompileQuality = Literal[
    "parseable",
    "decompiled_with_parse_errors",
    "decompiled_truncated",
    "failed",
    "skipped",
]


def _default_fallback_engines() -> list[JavaConcreteDecompilerEngine]:
    return ["cfr", "vineflower"]


class JavaDecompileArchiveArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    output_root: str | None = Field(
        None,
        description=(
            "Optional recovered project root. When set, decompiled sources are "
            "written under src/main/java."
        ),
    )
    engine: JavaDecompilerEngine = "auto"
    fallback: bool = True
    fallback_engines: list[JavaConcreteDecompilerEngine] = Field(
        default_factory=_default_fallback_engines
    )
    helper_jar: str | None = Field(
        None,
        description="Optional path to the glaurung-jvm-tools fat JAR",
    )
    mapping_path: str | None = Field(
        None,
        description=(
            "Optional ProGuard/Mojang mapping file. Used for mapped class names, "
            "mapped filters, and deobfuscation metadata; source rewriting is a "
            "separate repair/remap step."
        ),
    )
    include_packages: list[str] = Field(
        default_factory=list,
        description=(
            "Optional internal or dotted package prefixes to include, such as "
            "app or net.minecraft.server."
        ),
    )
    exclude_packages: list[str] = Field(default_factory=list)
    include_class_globs: list[str] = Field(default_factory=list)
    exclude_class_globs: list[str] = Field(default_factory=list)
    inner_class_policy: JavaInnerClassPolicy = Field(
        "skip",
        description=(
            "How to handle $ inner/anonymous/lambda class files: skip them, or "
            "decompile them as separate companion source files."
        ),
    )
    max_classes: int = Field(256, ge=0)
    max_source_chars_per_class: int = Field(200_000, ge=0)
    timeout_seconds_per_class: int = Field(60, ge=1, le=600)
    write_sources: bool = False
    include_bytecode_correlation: bool = False
    max_correlation_methods: int = Field(32, ge=0)
    rewrite_mapped_sources: bool = Field(
        False,
        description=(
            "When mapping_path is supplied, rewrite emitted source package, class, "
            "field, and method names using the parsed ProGuard/Mojang mapping."
        ),
    )
    compile_candidates: bool = Field(
        False,
        description=(
            "Compile each decompiler candidate in isolation and include the result "
            "in fallback quality scoring."
        ),
    )
    candidate_project_root: str | None = Field(
        None,
        description=(
            "Optional recovered project root whose existing src/main/java sources "
            "are included when compiling decompiler candidates."
        ),
    )
    candidate_classpath: list[str] = Field(
        default_factory=list,
        description="Optional classpath used for decompiler candidate compilation.",
    )
    max_candidate_project_sources: int = Field(256, ge=0)
    java_release: int = Field(17, ge=1)


class JavaDecompileAttempt(BaseModel):
    engine: str
    success: bool = False
    parse_success: bool = False
    source_length: int = 0
    source_truncated: bool = False
    type_count: int = 0
    method_count: int = 0
    quality_score: int = 0
    compile_success: bool | None = None
    compile_diagnostic_count: int = 0
    helper_jar: str | None = None
    diagnostics: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)


class JavaInnerClassGroup(BaseModel):
    outer_class_name: str
    named_inner_classes: list[str] = Field(default_factory=list)
    anonymous_classes: list[str] = Field(default_factory=list)
    lambda_classes: list[str] = Field(default_factory=list)
    synthetic_classes: list[str] = Field(default_factory=list)


class JavaDecompiledClassSummary(BaseModel):
    entry_name: str
    class_name: str
    outer_class_name: str | None = None
    inner_class_kind: JavaInnerClassKind = "top_level"
    inner_class_action: JavaInnerClassAction = "not_written"
    mapped_class_name: str | None = None
    mapping_match: Literal["obfuscated", "official", "none"] = "none"
    mapped_source_rewritten: bool = False
    selected_engine: str | None = None
    success: bool = False
    quality: JavaDecompileQuality = "failed"
    parse_success: bool = False
    source_length: int = 0
    source_truncated: bool = False
    type_count: int = 0
    method_count: int = 0
    quality_score: int = 0
    compile_success: bool | None = None
    compile_diagnostic_count: int = 0
    attempted_engines: list[JavaDecompileAttempt] = Field(default_factory=list)
    source_file: str | None = None
    bytecode_method_count: int | None = None
    bytecode_field_count: int | None = None
    bytecode_methods: list[str] = Field(default_factory=list)
    bytecode_method_line_anchors: list[str] = Field(default_factory=list)
    decompiled_methods: list[str] = Field(default_factory=list)
    method_count_delta: int | None = None
    correlation_stop_reasons: list[str] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)


class JavaDecompileArchiveResult(BaseModel):
    archive_path: str
    sha256: str = ""
    output_root: str | None = None
    source_root: str | None = None
    wrote_sources: bool = False
    class_count: int = 0
    attempted_class_count: int = 0
    success_count: int = 0
    parseable_count: int = 0
    failed_count: int = 0
    skipped_class_count: int = 0
    skipped_inner_class_count: int = 0
    suppressed_inner_class_count: int = 0
    written_source_count: int = 0
    mapped_class_count: int = 0
    inner_class_group_count: int = 0
    inner_class_groups: list[JavaInnerClassGroup] = Field(default_factory=list)
    classes: list[JavaDecompiledClassSummary] = Field(default_factory=list)
    failed_classes: list[str] = Field(default_factory=list)
    skipped_classes: list[str] = Field(default_factory=list)
    helper_jar: str | None = None
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    truncated: bool = False
    decompile_archive_node_id: str | None = None


class _Correlation(BaseModel):
    bytecode_method_count: int | None = None
    bytecode_field_count: int | None = None
    bytecode_methods: list[str] = Field(default_factory=list)
    bytecode_method_line_anchors: list[str] = Field(default_factory=list)
    decompiled_methods: list[str] = Field(default_factory=list)
    method_count_delta: int | None = None
    stop_reasons: list[str] = Field(default_factory=list)


class JavaDecompileArchiveTool(
    MemoryTool[JavaDecompileArchiveArgs, JavaDecompileArchiveResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_decompile_archive",
                description=(
                    "Decompile a bounded set of classes from a JAR with package "
                    "and glob filters, CFR/Vineflower fallback, per-class quality "
                    "metadata, and optional source-tree emission."
                ),
                tags=("java", "jar", "decompile", "source-recovery", "kb"),
            ),
            JavaDecompileArchiveArgs,
            JavaDecompileArchiveResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDecompileArchiveArgs,
    ) -> JavaDecompileArchiveResult:
        archive_path = Path(args.path or ctx.file_path)
        digest = _sha256(archive_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaDecompileArchiveResult(
                archive_path=str(archive_path),
                sha256=digest,
                stop_reasons=["input_not_zip"],
            )
        if args.write_sources and args.output_root is None:
            return JavaDecompileArchiveResult(
                archive_path=str(archive_path),
                sha256=digest,
                stop_reasons=["output_root_missing"],
            )

        output_root = Path(args.output_root) if args.output_root else None
        source_root = output_root / "src" / "main" / "java" if output_root else None
        if args.write_sources and source_root is not None:
            source_root.mkdir(parents=True, exist_ok=True)

        result = JavaDecompileArchiveResult(
            archive_path=str(archive_path),
            sha256=digest,
            output_root=str(output_root) if output_root else None,
            source_root=str(source_root) if source_root else None,
            wrote_sources=args.write_sources,
        )
        mappings = (
            parse_proguard_mappings(Path(args.mapping_path))
            if args.mapping_path
            else None
        )
        engines = _engine_order(args)
        entries = _class_entries(archive_path)
        result.class_count = len(entries)
        result.inner_class_groups = _inner_class_groups(entries)
        result.inner_class_group_count = len(result.inner_class_groups)

        for entry_name in entries:
            class_name = entry_name.removesuffix(".class")
            class_mapping, mapped_class_name, mapping_match = _mapped_class_mapping(
                mappings, class_name
            )
            if not _safe_archive_path(entry_name):
                _record_skip(result, entry_name, "unsafe_archive_path")
                continue
            inner_kind = _inner_class_kind(class_name)
            if "$" in class_name and args.inner_class_policy == "skip":
                result.skipped_inner_class_count += 1
                _record_skip(result, entry_name, "inner_class_skipped")
                continue
            if (
                "$" in class_name
                and args.inner_class_policy == "merge"
                and inner_kind != "named_inner"
            ):
                result.skipped_inner_class_count += 1
                result.suppressed_inner_class_count += 1
                _record_skip(result, entry_name, "inner_class_suppressed")
                continue
            if not _matches_filters(class_name, mapped_class_name, args):
                _record_skip(result, entry_name, "filtered")
                continue
            if result.attempted_class_count >= args.max_classes:
                result.truncated = True
                _append_once(result.stop_reasons, "max_classes")
                break

            summary = _decompile_one_class(
                archive_path=archive_path,
                class_name=class_name,
                mapped_class_name=mapped_class_name,
                mapping_match=mapping_match,
                class_mapping=class_mapping,
                entry_name=entry_name,
                engines=engines,
                args=args,
                source_root=source_root,
                project_root=output_root,
            )
            result.attempted_class_count += 1
            result.classes.append(summary)
            if summary.success:
                result.success_count += 1
            else:
                result.failed_count += 1
                result.failed_classes.append(class_name)
            if summary.parse_success:
                result.parseable_count += 1
            if summary.source_file is not None:
                result.written_source_count += 1
            if summary.mapped_class_name is not None:
                result.mapped_class_count += 1
            if result.helper_jar is None:
                helper_jar = _helper_jar_from_attempt(summary)
                if helper_jar is not None:
                    result.helper_jar = helper_jar

        if (
            args.write_sources
            and output_root is not None
            and result.written_source_count
        ):
            _write_sources_file(output_root, result.classes)
        _add_archive_node(kb, result)
        return result


def _decompile_one_class(
    *,
    archive_path: Path,
    class_name: str,
    mapped_class_name: str | None,
    mapping_match: Literal["obfuscated", "official", "none"],
    class_mapping: ProguardClassMapping | None,
    entry_name: str,
    engines: list[JavaConcreteDecompilerEngine],
    args: JavaDecompileArchiveArgs,
    source_root: Path | None,
    project_root: Path | None,
) -> JavaDecompiledClassSummary:
    attempts: list[JavaDecompileAttempt] = []
    raw_by_engine: dict[str, dict[str, Any]] = {}
    for engine in engines:
        try:
            raw = run_jvm_tool(
                [
                    "decompile",
                    "--jar",
                    str(archive_path),
                    "--class",
                    class_name,
                    "--engine",
                    engine,
                    "--max-source-chars",
                    str(args.max_source_chars_per_class),
                ],
                helper_jar=args.helper_jar,
                timeout_seconds=args.timeout_seconds_per_class,
            )
        except JavaHelperError as exc:
            raw = {
                "success": False,
                "engine": engine,
                "diagnostics": [str(exc)],
                "stop_reasons": ["helper_unavailable"],
            }
        raw_by_engine[engine] = raw
        attempt = _attempt_from_raw(engine, raw)
        if args.compile_candidates:
            _score_candidate_compilation(class_name, raw, attempt, args)
        attempts.append(attempt)
        if _attempt_good_enough(attempt) or not args.fallback:
            break

    selected = _select_best_attempt(attempts)
    selected_raw = raw_by_engine.get(selected.engine, {}) if selected else {}
    raw_selected_ast = selected_raw.get("ast")
    selected_ast: dict[str, Any] = (
        raw_selected_ast if isinstance(raw_selected_ast, dict) else {}
    )
    source_file: str | None = None
    inner_action: JavaInnerClassAction = "not_written"
    write_stop_reasons: list[str] = []
    if selected is not None and selected.success and args.write_sources:
        source = selected_raw.get("source")
        if isinstance(source, str) and source.strip() and source_root is not None:
            mapped_source_rewritten = False
            dest_class_name = class_name
            source_to_write = source
            if (
                args.rewrite_mapped_sources
                and class_mapping is not None
                and mapped_class_name is not None
            ):
                source_to_write = _rewrite_mapped_source(source, class_mapping)
                dest_class_name = mapped_class_name.replace(".", "/")
                mapped_source_rewritten = source_to_write != source
            if (
                args.inner_class_policy == "merge"
                and _inner_class_kind(class_name) == "named_inner"
            ):
                outer = _outer_class_name(class_name)
                if outer is None:
                    write_stop_reasons.append("outer_class_missing_for_merge")
                else:
                    outer_dest = source_root.joinpath(*outer.split("/")).with_suffix(
                        ".java"
                    )
                    if _merge_inner_source_into_outer(
                        outer_dest=outer_dest,
                        inner_source=source_to_write,
                        outer_class_name=outer,
                        inner_class_name=class_name,
                    ):
                        source_file = _relative(project_root or source_root, outer_dest)
                        inner_action = "merged_into_outer"
                    else:
                        write_stop_reasons.append("inner_merge_failed")
            else:
                dest = source_root.joinpath(*dest_class_name.split("/")).with_suffix(
                    ".java"
                )
                if dest.exists() and dest_class_name != class_name:
                    write_stop_reasons.append("mapped_source_collision")
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(source_to_write.rstrip() + "\n", encoding="utf-8")
                    source_file = _relative(project_root or source_root, dest)
                    inner_action = (
                        "emitted_companion"
                        if "$" in class_name
                        else "emitted_top_level"
                    )
        else:
            mapped_source_rewritten = False
    else:
        mapped_source_rewritten = False
    correlation = (
        _bytecode_correlation(
            archive_path=archive_path,
            class_name=class_name,
            ast=selected_ast,
            args=args,
        )
        if args.include_bytecode_correlation
        else _Correlation()
    )

    return JavaDecompiledClassSummary(
        entry_name=entry_name,
        class_name=class_name,
        outer_class_name=_outer_class_name(class_name),
        inner_class_kind=_inner_class_kind(class_name),
        inner_class_action=inner_action,
        mapped_class_name=mapped_class_name,
        mapping_match=mapping_match,
        mapped_source_rewritten=mapped_source_rewritten,
        selected_engine=selected.engine if selected else None,
        success=bool(selected and selected.success),
        quality=_quality(selected),
        parse_success=bool(selected and selected.parse_success),
        source_length=selected.source_length if selected else 0,
        source_truncated=bool(selected and selected.source_truncated),
        type_count=selected.type_count if selected else 0,
        method_count=selected.method_count if selected else 0,
        quality_score=selected.quality_score if selected else 0,
        compile_success=selected.compile_success if selected else None,
        compile_diagnostic_count=selected.compile_diagnostic_count if selected else 0,
        attempted_engines=attempts,
        source_file=source_file,
        bytecode_method_count=correlation.bytecode_method_count,
        bytecode_field_count=correlation.bytecode_field_count,
        bytecode_methods=correlation.bytecode_methods,
        bytecode_method_line_anchors=correlation.bytecode_method_line_anchors,
        decompiled_methods=correlation.decompiled_methods,
        method_count_delta=correlation.method_count_delta,
        correlation_stop_reasons=correlation.stop_reasons,
        diagnostics=selected.diagnostics if selected else [],
        stop_reasons=[
            *(selected.stop_reasons if selected else ["no_decompiler_attempts"]),
            *write_stop_reasons,
        ],
    )


def _bytecode_correlation(
    *,
    archive_path: Path,
    class_name: str,
    ast: dict[str, Any],
    args: JavaDecompileArchiveArgs,
) -> _Correlation:
    decompiled_methods = _decompiled_method_names(ast, args.max_correlation_methods)
    try:
        raw = run_jvm_tool(
            ["bytecode", "--jar", str(archive_path), "--class", class_name],
            helper_jar=args.helper_jar,
            timeout_seconds=args.timeout_seconds_per_class,
        )
    except JavaHelperError:
        return _Correlation(
            decompiled_methods=decompiled_methods,
            stop_reasons=["helper_unavailable"],
        )
    if not raw.get("success"):
        return _Correlation(
            decompiled_methods=decompiled_methods,
            stop_reasons=_string_list(raw.get("stop_reasons")) or ["bytecode_failed"],
        )
    bytecode_methods = _bytecode_method_signatures(
        raw.get("methods"),
        args.max_correlation_methods,
    )
    bytecode_method_line_anchors = _bytecode_method_line_anchors(
        raw.get("methods"),
        args.max_correlation_methods,
    )
    bytecode_method_count = _int_or_zero(raw.get("method_count"))
    return _Correlation(
        bytecode_method_count=bytecode_method_count,
        bytecode_field_count=_int_or_zero(raw.get("field_count")),
        bytecode_methods=bytecode_methods,
        bytecode_method_line_anchors=bytecode_method_line_anchors,
        decompiled_methods=decompiled_methods,
        method_count_delta=bytecode_method_count - len(decompiled_methods),
    )


def _decompiled_method_names(ast: dict[str, Any], max_methods: int) -> list[str]:
    if max_methods == 0:
        return []
    out: list[str] = []
    types = ast.get("types")
    if not isinstance(types, list):
        return out
    for type_info in types:
        if not isinstance(type_info, dict):
            continue
        methods = type_info.get("methods")
        if not isinstance(methods, list):
            continue
        for method in methods:
            if isinstance(method, str) and method not in out:
                out.append(method)
                if len(out) >= max_methods:
                    return out
    return out


def _bytecode_method_signatures(value: object, max_methods: int) -> list[str]:
    if max_methods == 0 or not isinstance(value, list):
        return []
    out: list[str] = []
    for method in value:
        if not isinstance(method, dict):
            continue
        method_info = cast(dict[str, Any], method)
        name = method_info.get("name")
        descriptor = method_info.get("descriptor")
        if isinstance(name, str) and isinstance(descriptor, str):
            out.append(f"{name}{descriptor}")
            if len(out) >= max_methods:
                break
    return out


def _bytecode_method_line_anchors(value: object, max_methods: int) -> list[str]:
    if max_methods == 0 or not isinstance(value, list):
        return []
    out: list[str] = []
    for method in value:
        if not isinstance(method, dict):
            continue
        method_info = cast(dict[str, Any], method)
        name = method_info.get("name")
        descriptor = method_info.get("descriptor")
        line_min = method_info.get("line_min")
        line_max = method_info.get("line_max")
        if (
            isinstance(name, str)
            and isinstance(descriptor, str)
            and isinstance(line_min, int)
            and isinstance(line_max, int)
        ):
            if line_min == line_max:
                out.append(f"{name}{descriptor} line={line_min}")
            else:
                out.append(f"{name}{descriptor} lines={line_min}-{line_max}")
            if len(out) >= max_methods:
                break
    return out


def _attempt_from_raw(engine: str, raw: dict[str, Any]) -> JavaDecompileAttempt:
    raw_ast = raw.get("ast")
    ast: dict[str, Any] = raw_ast if isinstance(raw_ast, dict) else {}
    source_length = _int_or_zero(raw.get("source_length"))
    parse_success = bool(ast.get("parse_success"))
    source_truncated = bool(raw.get("source_truncated", False))
    success = bool(raw.get("success"))
    type_count = _int_or_zero(ast.get("type_count"))
    method_count = _int_or_zero(ast.get("method_count"))
    return JavaDecompileAttempt(
        engine=engine,
        success=success,
        parse_success=parse_success,
        source_length=source_length,
        source_truncated=source_truncated,
        type_count=type_count,
        method_count=method_count,
        quality_score=_quality_score(
            success=success,
            parse_success=parse_success,
            source_length=source_length,
            source_truncated=source_truncated,
            type_count=type_count,
            method_count=method_count,
        ),
        helper_jar=_string_or_none(raw.get("helper_jar")),
        diagnostics=_string_list(raw.get("diagnostics")),
        stop_reasons=_string_list(raw.get("stop_reasons")),
    )


def _score_candidate_compilation(
    class_name: str,
    raw: dict[str, Any],
    attempt: JavaDecompileAttempt,
    args: JavaDecompileArchiveArgs,
) -> None:
    source = raw.get("source")
    if not isinstance(source, str) or not source.strip():
        return
    compiled = _compile_candidate_source(class_name, source, args)
    if compiled is None:
        attempt.stop_reasons = _dedupe([*attempt.stop_reasons, "javac_missing"])
        return
    success, diagnostic_count = compiled
    attempt.compile_success = success
    attempt.compile_diagnostic_count = diagnostic_count
    if success:
        attempt.quality_score += 35
    else:
        attempt.quality_score -= 35 + min(diagnostic_count, 20)


def _compile_candidate_source(
    class_name: str,
    source: str,
    args: JavaDecompileArchiveArgs,
) -> tuple[bool, int] | None:
    javac = shutil.which("javac")
    if javac is None:
        return None
    with tempfile.TemporaryDirectory(prefix="glaurung-java-candidate-") as tmp:
        tmp_path = Path(tmp)
        source_path = (
            tmp_path / "src" / Path(*class_name.split("/")).with_suffix(".java")
        )
        classes_dir = tmp_path / "classes"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        classes_dir.mkdir()
        source_path.write_text(source.rstrip() + "\n", encoding="utf-8")
        project_sources = _candidate_project_sources(
            args.candidate_project_root,
            class_name,
            args.max_candidate_project_sources,
        )
        source_args = [str(source_path), *[str(path) for path in project_sources]]
        classpath = _candidate_classpath(args.candidate_classpath)
        try:
            command = [
                javac,
                "--release",
                str(args.java_release),
                "-d",
                str(classes_dir),
            ]
            if classpath:
                command.extend(["-classpath", classpath])
            command.extend(source_args)
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, 1
        output = "\n".join(part for part in (proc.stderr, proc.stdout) if part)
        diagnostic_count = output.count(": error:") + output.count(": warning:")
        return proc.returncode == 0, diagnostic_count


def _candidate_project_sources(
    project_root: str | None,
    class_name: str,
    max_sources: int,
) -> list[Path]:
    if project_root is None or max_sources == 0:
        return []
    root = Path(project_root)
    source_root = root / "src" / "main" / "java"
    if not source_root.is_dir():
        return []
    candidate_rel = Path(*class_name.split("/")).with_suffix(".java")
    sources: list[Path] = []
    for source in sorted(
        path for path in source_root.rglob("*.java") if path.is_file()
    ):
        try:
            if source.relative_to(source_root) == candidate_rel:
                continue
        except ValueError:
            pass
        sources.append(source)
        if len(sources) >= max_sources:
            break
    return sources


def _candidate_classpath(classpath: list[str]) -> str:
    existing = [str(Path(item)) for item in classpath if item and Path(item).exists()]
    return os.pathsep.join(dict.fromkeys(existing))


def _merge_inner_source_into_outer(
    *,
    outer_dest: Path,
    inner_source: str,
    outer_class_name: str,
    inner_class_name: str,
) -> bool:
    if not outer_dest.is_file():
        return False
    outer_text = outer_dest.read_text(encoding="utf-8", errors="replace")
    inner_simple = inner_class_name.rsplit("$", 1)[-1]
    if re.search(
        rf"\b(class|interface|enum|record)\s+{re.escape(inner_simple)}\b", outer_text
    ):
        return True
    inner_body = _inner_source_body(inner_source, outer_class_name, inner_simple)
    if not inner_body.strip():
        return False
    insert_at = outer_text.rfind("}")
    if insert_at < 0:
        return False
    merged = (
        outer_text[:insert_at].rstrip()
        + "\n\n"
        + _indent_inner_source(inner_body.rstrip())
        + "\n"
        + outer_text[insert_at:]
    )
    outer_dest.write_text(merged.rstrip() + "\n", encoding="utf-8")
    return True


def _inner_source_body(
    source: str,
    outer_class_name: str,
    inner_simple: str,
) -> str:
    text = _strip_package_and_imports(source)
    outer_simple = outer_class_name.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
    text = re.sub(
        rf"\b(class|interface|enum|record)\s+{re.escape(outer_simple)}[.$]{re.escape(inner_simple)}\b",
        rf"\1 {inner_simple}",
        text,
        count=1,
    )
    text = re.sub(
        rf"\b(class|interface|enum|record)\s+{re.escape(outer_simple)}\$?{re.escape(inner_simple)}\b",
        rf"\1 {inner_simple}",
        text,
        count=1,
    )
    text = re.sub(
        rf"\b{re.escape(outer_simple)}\${re.escape(inner_simple)}\b", inner_simple, text
    )
    text = re.sub(
        rf"\b{re.escape(outer_simple)}\.{re.escape(inner_simple)}\b", inner_simple, text
    )
    text = re.sub(
        rf"\b(public|protected|private)\s+(?=(?:final\s+|abstract\s+)?(?:class|interface|enum|record)\s+{re.escape(inner_simple)}\b)",
        "",
        text,
        count=1,
    )
    if not re.search(
        rf"\bstatic\s+(?:final\s+|abstract\s+)?(?:class|interface|enum|record)\s+{re.escape(inner_simple)}\b",
        text,
    ):
        text = re.sub(
            rf"\b((?:final\s+|abstract\s+)?(?:class|interface|enum|record)\s+{re.escape(inner_simple)}\b)",
            r"static \1",
            text,
            count=1,
        )
    return text.strip()


def _strip_package_and_imports(source: str) -> str:
    lines = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("package ") or stripped.startswith("import "):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _indent_inner_source(source: str) -> str:
    return "\n".join(
        ("    " + line if line.strip() else line) for line in source.splitlines()
    )


def _quality_score(
    *,
    success: bool,
    parse_success: bool,
    source_length: int,
    source_truncated: bool,
    type_count: int,
    method_count: int,
) -> int:
    score = 0
    if success:
        score += 100
    if source_length > 0:
        score += 25
    if parse_success:
        score += 100
    if type_count > 0:
        score += 15
    score += min(method_count, 20)
    if source_truncated:
        score -= 50
    return score


def _attempt_good_enough(attempt: JavaDecompileAttempt) -> bool:
    good = (
        attempt.success
        and attempt.parse_success
        and not attempt.source_truncated
        and attempt.source_length > 0
    )
    if good and attempt.compile_success is False:
        return False
    return good


def _select_best_attempt(
    attempts: list[JavaDecompileAttempt],
) -> JavaDecompileAttempt | None:
    if not attempts:
        return None
    return max(attempts, key=lambda attempt: attempt.quality_score)


def _quality(
    attempt: JavaDecompileAttempt | None,
) -> JavaDecompileQuality:
    if attempt is None or not attempt.success:
        return "failed"
    if attempt.source_truncated:
        return "decompiled_truncated"
    if attempt.parse_success:
        return "parseable"
    return "decompiled_with_parse_errors"


def _engine_order(args: JavaDecompileArchiveArgs) -> list[JavaConcreteDecompilerEngine]:
    if args.engine == "auto":
        engines = list(args.fallback_engines)
    else:
        engines = [args.engine]
        if args.fallback:
            engines.extend(args.fallback_engines)
    out: list[JavaConcreteDecompilerEngine] = []
    for engine in engines:
        if engine not in out:
            out.append(engine)
    return out


def _class_entries(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as zf:
        return sorted(
            (
                info.filename
                for info in zf.infolist()
                if not info.is_dir() and info.filename.endswith(".class")
            ),
            key=_class_entry_sort_key,
        )


def _class_entry_sort_key(entry_name: str) -> tuple[str, int, str]:
    class_name = entry_name.removesuffix(".class")
    outer = _outer_class_name(class_name) or class_name
    return outer, 1 if "$" in class_name else 0, class_name


def _mapped_class_mapping(
    mappings: ProguardMappings | None,
    class_name: str,
) -> tuple[
    ProguardClassMapping | None,
    str | None,
    Literal["obfuscated", "official", "none"],
]:
    if mappings is None:
        return None, None, "none"
    class_mapping, match = mappings.lookup_class(class_name)
    if class_mapping is None:
        return None, None, "none"
    return class_mapping, class_mapping.official_name, match


def _rewrite_mapped_source(source: str, class_mapping: ProguardClassMapping) -> str:
    official = class_mapping.official_name
    official_parts = official.split(".")
    official_simple = official_parts[-1]
    official_package = ".".join(official_parts[:-1])
    obfuscated_simple = class_mapping.obfuscated_name.split(".")[-1]

    rewritten = _rewrite_package(source, official_package)
    rewritten = re.sub(
        rf"\b(class|interface|enum|record)\s+{re.escape(obfuscated_simple)}\b",
        rf"\1 {official_simple}",
        rewritten,
        count=1,
    )
    rewritten = re.sub(
        rf"\b{re.escape(obfuscated_simple)}\s*\(",
        f"{official_simple}(",
        rewritten,
    )
    for field in class_mapping.fields:
        rewritten = re.sub(
            rf"\b{re.escape(field.obfuscated_name)}\b",
            field.official_name,
            rewritten,
        )
    for method in class_mapping.methods:
        rewritten = re.sub(
            rf"\b{re.escape(method.obfuscated_name)}\b",
            method.official_name,
            rewritten,
        )
    return rewritten


def _rewrite_package(source: str, package_name: str) -> str:
    package_re = re.compile(r"(?m)^\s*package\s+[A-Za-z0-9_.]+;\s*\n+")
    if package_name:
        replacement = f"package {package_name};\n\n"
        if package_re.search(source):
            return package_re.sub(replacement, source, count=1)
        return replacement + source.lstrip()
    return package_re.sub("", source, count=1)


def _inner_class_groups(entries: list[str]) -> list[JavaInnerClassGroup]:
    groups: dict[str, JavaInnerClassGroup] = {}
    for entry in entries:
        class_name = entry.removesuffix(".class")
        outer = _outer_class_name(class_name)
        if outer is None:
            continue
        group = groups.setdefault(outer, JavaInnerClassGroup(outer_class_name=outer))
        kind = _inner_class_kind(class_name)
        if kind == "named_inner":
            group.named_inner_classes.append(class_name)
        elif kind == "anonymous":
            group.anonymous_classes.append(class_name)
        elif kind == "lambda":
            group.lambda_classes.append(class_name)
        elif kind == "synthetic":
            group.synthetic_classes.append(class_name)
    return list(groups.values())


def _outer_class_name(class_name: str) -> str | None:
    if "$" not in class_name:
        return None
    return class_name.split("$", 1)[0]


def _inner_class_kind(class_name: str) -> JavaInnerClassKind:
    if "$" not in class_name:
        return "top_level"
    suffix = class_name.rsplit("$", 1)[-1]
    if "Lambda" in suffix or "$$Lambda$" in class_name:
        return "lambda"
    if suffix.isdigit() or (suffix and suffix[0].isdigit()):
        return "anonymous"
    if suffix.startswith(("access$", "switch$", "$SwitchMap")):
        return "synthetic"
    return "named_inner"


def _matches_filters(
    class_name: str,
    mapped_class_name: str | None,
    args: JavaDecompileArchiveArgs,
) -> bool:
    candidates = [class_name.replace(".", "/")]
    if mapped_class_name is not None:
        candidates.append(mapped_class_name.replace(".", "/"))
    if args.include_packages and not any(
        candidate.startswith(_normalize_package_prefix(prefix))
        for candidate in candidates
        for prefix in args.include_packages
    ):
        return False
    if any(
        candidate.startswith(_normalize_package_prefix(prefix))
        for candidate in candidates
        for prefix in args.exclude_packages
    ):
        return False
    if args.include_class_globs and not any(
        fnmatch.fnmatch(candidate, glob.replace(".", "/"))
        for candidate in candidates
        for glob in args.include_class_globs
    ):
        return False
    if any(
        fnmatch.fnmatch(candidate, glob.replace(".", "/"))
        for candidate in candidates
        for glob in args.exclude_class_globs
    ):
        return False
    return True


def _normalize_package_prefix(value: str) -> str:
    normalized = value.strip().replace(".", "/").strip("/")
    return normalized + "/" if normalized else ""


def _record_skip(
    result: JavaDecompileArchiveResult,
    entry_name: str,
    stop_reason: str,
) -> None:
    result.skipped_class_count += 1
    result.skipped_classes.append(entry_name.removesuffix(".class"))
    if stop_reason == "unsafe_archive_path":
        _append_once(result.stop_reasons, stop_reason)


def _write_sources_file(
    output_root: Path,
    classes: list[JavaDecompiledClassSummary],
) -> None:
    sources = sorted(
        summary.source_file for summary in classes if summary.source_file is not None
    )
    (output_root / "decompiled-sources.txt").write_text(
        "\n".join(sources) + "\n",
        encoding="utf-8",
    )


def _helper_jar_from_attempt(summary: JavaDecompiledClassSummary) -> str | None:
    for attempt in summary.attempted_engines:
        if attempt.helper_jar is not None:
            return attempt.helper_jar
    return None


def _safe_archive_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not (
        path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)
    )


def _add_archive_node(kb: KnowledgeBase, result: JavaDecompileArchiveResult) -> None:
    node = Node(
        kind=NodeKind.java_decompile_archive,
        label=Path(result.archive_path).name,
        text=(
            f"Decompiled {result.success_count}/{result.attempted_class_count} "
            f"attempted class(es); {result.parseable_count} parsed cleanly."
        ),
        props={
            "tool": "java_decompile_archive",
            **result.model_dump(exclude={"decompile_archive_node_id"}),
        },
        tags=["java", "decompile", "archive"],
    )
    kb.add_node(node)
    result.decompile_archive_node_id = node.id


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    except FileNotFoundError:
        return ""
    return h.hexdigest()


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) else 0


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def build_tool() -> MemoryTool[JavaDecompileArchiveArgs, JavaDecompileArchiveResult]:
    return JavaDecompileArchiveTool()
