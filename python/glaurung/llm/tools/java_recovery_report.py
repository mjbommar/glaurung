from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_compile_recovered_project import JavaCompilerDiagnostic
from .java_decompile_archive import JavaInnerClassPolicy
from .java_recover_project import (
    JavaDecompilerEngine,
    JavaRecoverProjectArgs,
    JavaRecoverProjectResult,
    build_tool as build_java_recover_project,
)
from .java_reconstruct_source_tree import ResourcePolicy
from .java_validate_recovered_application import ValidationProfile


JavaRecoveryReportStatus = Literal["clean", "partial", "blocked", "failed"]
JavaRecoveryReportBlockerKind = Literal[
    "compile_error",
    "parse_error",
    "repair_deferred",
    "validation_issue",
    "decompile_failure",
    "missing_input",
]
JavaRecoveryRepairAutomation = Literal["automatic", "manual"]


class JavaRecoveryReportArgs(BaseModel):
    path: str | None = Field(None, description="Original JAR/ZIP archive")
    output_root: str | None = Field(
        None,
        description="Destination recovered Java project root.",
    )
    resource_policy: ResourcePolicy = "copy_runtime"
    decompiler_engine: JavaDecompilerEngine = "auto"
    helper_jar: str | None = None
    mapping_path: str | None = None
    rewrite_mapped_sources: bool = False
    include_packages: list[str] = Field(default_factory=list)
    include_class_globs: list[str] = Field(default_factory=list)
    inner_class_policy: JavaInnerClassPolicy = "skip"
    max_classes: int = Field(64, ge=0)
    max_resources: int = Field(2_000, ge=0)
    max_source_chars_per_class: int = Field(200_000, ge=0)
    timeout_seconds_per_class: int = Field(60, ge=1, le=600)
    java_release: int = Field(17, ge=1)
    compile_candidates: bool = True
    classpath: list[str] = Field(default_factory=list)
    include_dependency_inference: bool = True
    collect_local_libraries: bool = True
    extract_nested_archives: bool = False
    max_nested_archives: int = Field(64, ge=0)
    max_nested_archive_bytes: int = Field(50_000_000, ge=0)
    allow_dependency_network: bool = False
    include_local_maven_cache: bool = True
    local_maven_repository: str | None = None
    max_local_maven_cache_jars: int = Field(2_048, ge=0)
    resume: bool = True
    force_redecompile: bool = False
    run_repair: bool = True
    max_repair_iterations: int = Field(2, ge=1, le=10)
    run_validate: bool = True
    validate_profile: ValidationProfile = "full_static"
    allow_generated_stubs: bool = False
    max_blockers: int = Field(8, ge=0)
    snippet_context_lines: int = Field(2, ge=0, le=8)
    max_snippet_line_chars: int = Field(180, ge=40, le=500)
    max_class_summaries: int = Field(12, ge=0)
    max_repair_summaries: int = Field(12, ge=0)
    write_report_files: bool = True
    report_markdown_file: str = ".glaurung/recovery-report.md"
    report_json_file: str = ".glaurung/recovery-report.json"


class JavaRecoveryReportLocation(BaseModel):
    file: str
    absolute_file: str | None = None
    line: int | None = None
    column: int | None = None


class JavaRecoveryReportSnippetLine(BaseModel):
    line: int
    text: str
    focus: bool = False


class JavaRecoveryReportBlocker(BaseModel):
    kind: JavaRecoveryReportBlockerKind
    severity: str
    category: str
    title: str
    message: str
    location: JavaRecoveryReportLocation | None = None
    likely_cause: str
    next_action: str
    snippet: list[JavaRecoveryReportSnippetLine] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class JavaRecoveryReportProgress(BaseModel):
    cache_hit: bool = False
    resumed_steps: list[str] = Field(default_factory=list)
    decompile_success_count: int = 0
    generated_source_count: int = 0
    generated_resource_count: int = 0
    parsed_source_count: int = 0
    parse_error_count: int = 0
    type_count: int = 0
    method_count: int = 0
    field_count: int = 0
    effective_classpath_count: int = 0
    compile_success: bool | None = None
    compile_diagnostic_count: int = 0
    repair_success: bool | None = None
    repair_count: int = 0
    validation_passed: bool | None = None
    compatibility_score: float | None = None


class JavaRecoveryReportClassSummary(BaseModel):
    class_name: str
    selected_engine: str | None = None
    quality: str
    parse_success: bool
    compile_success: bool | None = None
    source_file: str | None = None
    inner_class_action: str
    method_count_delta: int | None = None
    attempted_engines: list[str] = Field(default_factory=list)
    bytecode_method_count: int | None = None
    bytecode_field_count: int | None = None
    bytecode_methods: list[str] = Field(default_factory=list)
    bytecode_line_anchors: list[str] = Field(default_factory=list)
    decompiled_methods: list[str] = Field(default_factory=list)
    correlation_notes: list[str] = Field(default_factory=list)
    candidate_notes: list[str] = Field(default_factory=list)


class JavaRecoveryReportRepairSummary(BaseModel):
    kind: str
    applied: bool
    automation: JavaRecoveryRepairAutomation = "manual"
    file: str
    new_file: str
    message: str
    recommended_action: str = ""


class JavaRecoveryReportRollups(BaseModel):
    total_class_summary_count: int = 0
    displayed_class_summary_count: int = 0
    omitted_class_summary_count: int = 0
    by_package: dict[str, int] = Field(default_factory=dict)
    by_engine: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    by_compile_status: dict[str, int] = Field(default_factory=dict)
    by_inner_action: dict[str, int] = Field(default_factory=dict)
    blocker_summary_by_category: dict[str, int] = Field(default_factory=dict)
    blocker_summary_by_file: dict[str, int] = Field(default_factory=dict)
    repair_summary_by_kind: dict[str, int] = Field(default_factory=dict)


class JavaRecoveryReportResult(BaseModel):
    archive_path: str
    source_project_root: str | None = None
    status: JavaRecoveryReportStatus
    headline: str
    summary: str
    progress: JavaRecoveryReportProgress
    blocker_count: int
    blockers: list[JavaRecoveryReportBlocker] = Field(default_factory=list)
    class_summary_count: int = 0
    class_summaries: list[JavaRecoveryReportClassSummary] = Field(default_factory=list)
    repair_summary_count: int = 0
    repair_summaries: list[JavaRecoveryReportRepairSummary] = Field(
        default_factory=list
    )
    rollups: JavaRecoveryReportRollups = Field(
        default_factory=JavaRecoveryReportRollups
    )
    next_actions: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    markdown: str
    recovery_result: JavaRecoverProjectResult
    report_markdown_path: str | None = None
    report_json_path: str | None = None
    report_node_id: str | None = None


class JavaRecoveryReportTool(
    MemoryTool[JavaRecoveryReportArgs, JavaRecoveryReportResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_recovery_report",
                description=(
                    "Run Java project recovery and render a daily-use report with "
                    "status, progress, ranked blockers, source snippets, and next "
                    "actions."
                ),
                tags=("java", "source-recovery", "report", "dx", "kb"),
            ),
            JavaRecoveryReportArgs,
            JavaRecoveryReportResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaRecoveryReportArgs,
    ) -> JavaRecoveryReportResult:
        recover_tool = build_java_recover_project()
        recovery = recover_tool.run(
            ctx,
            kb,
            _recovery_args(args),
        )
        root = (
            Path(recovery.source_project_root) if recovery.source_project_root else None
        )
        report_markdown_path = _report_path(root, args.report_markdown_file)
        report_json_path = _report_path(root, args.report_json_file)
        progress = _progress(recovery)
        blockers = _rank_blockers(recovery, args)
        class_summaries = _class_summaries(recovery, args)
        if not class_summaries and recovery.cache_hit:
            class_summaries = _cached_class_summaries(
                report_json_path,
                args.max_class_summaries,
            )
        repair_summaries = _repair_summaries(recovery, args)
        rollups = _rollups(recovery, class_summaries, blockers, repair_summaries, args)
        if recovery.cache_hit and rollups.total_class_summary_count == len(
            class_summaries
        ):
            cached_rollups = _cached_rollups(report_json_path)
            if cached_rollups is not None:
                rollups = _adapt_cached_rollups(cached_rollups, class_summaries)
        next_actions = _next_actions(recovery, blockers)
        status = _status(recovery, blockers)
        headline = _headline(status, recovery, blockers)
        summary = _summary(status, progress, blockers)
        commands = _commands(recovery, blockers, report_markdown_path)
        result = JavaRecoveryReportResult(
            archive_path=recovery.archive_path,
            source_project_root=recovery.source_project_root,
            status=status,
            headline=headline,
            summary=summary,
            progress=progress,
            blocker_count=len(blockers),
            blockers=blockers,
            class_summary_count=len(class_summaries),
            class_summaries=class_summaries,
            repair_summary_count=len(repair_summaries),
            repair_summaries=repair_summaries,
            rollups=rollups,
            next_actions=next_actions,
            commands=commands,
            markdown=_markdown(
                status=status,
                headline=headline,
                progress=progress,
                blockers=blockers,
                class_summaries=class_summaries,
                repair_summaries=repair_summaries,
                rollups=rollups,
                next_actions=next_actions,
                commands=commands,
                recovery=recovery,
            ),
            recovery_result=recovery,
            report_markdown_path=str(report_markdown_path)
            if report_markdown_path is not None
            else None,
            report_json_path=str(report_json_path)
            if report_json_path is not None
            else None,
        )
        if args.write_report_files:
            _write_report_files(result, report_markdown_path, report_json_path)
        _add_report_node(kb, result)
        return result


def _recovery_args(args: JavaRecoveryReportArgs) -> JavaRecoverProjectArgs:
    return JavaRecoverProjectArgs(
        path=args.path,
        output_root=args.output_root,
        resource_policy=args.resource_policy,
        decompiler_engine=args.decompiler_engine,
        helper_jar=args.helper_jar,
        mapping_path=args.mapping_path,
        rewrite_mapped_sources=args.rewrite_mapped_sources,
        include_packages=args.include_packages,
        include_class_globs=args.include_class_globs,
        inner_class_policy=args.inner_class_policy,
        max_classes=args.max_classes,
        max_resources=args.max_resources,
        max_source_chars_per_class=args.max_source_chars_per_class,
        timeout_seconds_per_class=args.timeout_seconds_per_class,
        java_release=args.java_release,
        compile_candidates=args.compile_candidates,
        classpath=args.classpath,
        include_dependency_inference=args.include_dependency_inference,
        collect_local_libraries=args.collect_local_libraries,
        extract_nested_archives=args.extract_nested_archives,
        max_nested_archives=args.max_nested_archives,
        max_nested_archive_bytes=args.max_nested_archive_bytes,
        allow_dependency_network=args.allow_dependency_network,
        include_local_maven_cache=args.include_local_maven_cache,
        local_maven_repository=args.local_maven_repository,
        max_local_maven_cache_jars=args.max_local_maven_cache_jars,
        resume=args.resume,
        force_redecompile=args.force_redecompile,
        run_repair=args.run_repair,
        max_repair_iterations=args.max_repair_iterations,
        run_validate=args.run_validate,
        validate_profile=args.validate_profile,
        allow_generated_stubs=args.allow_generated_stubs,
    )


def _progress(recovery: JavaRecoverProjectResult) -> JavaRecoveryReportProgress:
    source_index = recovery.source_index_result
    compile_result = recovery.compile_result
    repair_result = recovery.repair_result
    validation = recovery.validation_result
    return JavaRecoveryReportProgress(
        cache_hit=recovery.cache_hit,
        resumed_steps=recovery.resumed_steps,
        decompile_success_count=recovery.decompile_success_count,
        generated_source_count=recovery.generated_source_count,
        generated_resource_count=recovery.generated_resource_count,
        parsed_source_count=recovery.parsed_source_count,
        parse_error_count=source_index.parse_error_count if source_index else 0,
        type_count=source_index.type_count if source_index else 0,
        method_count=source_index.method_count if source_index else 0,
        field_count=source_index.field_count if source_index else 0,
        effective_classpath_count=len(recovery.effective_classpath),
        compile_success=recovery.compile_success,
        compile_diagnostic_count=(
            compile_result.diagnostic_count if compile_result else 0
        ),
        repair_success=recovery.repair_success,
        repair_count=repair_result.repair_count if repair_result else 0,
        validation_passed=recovery.validation_passed,
        compatibility_score=(
            validation.compatibility_score if validation is not None else None
        ),
    )


def _class_summaries(
    recovery: JavaRecoverProjectResult,
    args: JavaRecoveryReportArgs,
) -> list[JavaRecoveryReportClassSummary]:
    decompile = recovery.decompile_result
    if decompile is None:
        return []
    out: list[JavaRecoveryReportClassSummary] = []
    for item in decompile.classes[: args.max_class_summaries]:
        out.append(
            JavaRecoveryReportClassSummary(
                class_name=item.class_name,
                selected_engine=item.selected_engine,
                quality=item.quality,
                parse_success=item.parse_success,
                compile_success=item.compile_success,
                source_file=item.source_file,
                inner_class_action=item.inner_class_action,
                method_count_delta=item.method_count_delta,
                attempted_engines=[
                    attempt.engine for attempt in item.attempted_engines
                ],
                bytecode_method_count=item.bytecode_method_count,
                bytecode_field_count=item.bytecode_field_count,
                bytecode_methods=item.bytecode_methods[:8],
                bytecode_line_anchors=item.bytecode_method_line_anchors[:8],
                decompiled_methods=item.decompiled_methods[:8],
                correlation_notes=item.correlation_stop_reasons[:8],
                candidate_notes=_candidate_notes(item),
            )
        )
    return out


def _cached_class_summaries(
    report_json_path: Path | None,
    max_class_summaries: int,
) -> list[JavaRecoveryReportClassSummary]:
    if report_json_path is None or not report_json_path.is_file():
        return []
    try:
        data = json.loads(report_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw = data.get("class_summaries") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[JavaRecoveryReportClassSummary] = []
    for item in raw[:max_class_summaries]:
        if not isinstance(item, dict):
            continue
        try:
            out.append(JavaRecoveryReportClassSummary(**item))
        except ValueError:
            continue
    return out


def _cached_rollups(report_json_path: Path | None) -> JavaRecoveryReportRollups | None:
    if report_json_path is None or not report_json_path.is_file():
        return None
    try:
        data = json.loads(report_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    raw = data.get("rollups") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        return None
    try:
        return JavaRecoveryReportRollups(**raw)
    except ValueError:
        return None


def _adapt_cached_rollups(
    rollups: JavaRecoveryReportRollups,
    class_summaries: list[JavaRecoveryReportClassSummary],
) -> JavaRecoveryReportRollups:
    rollups.displayed_class_summary_count = len(class_summaries)
    rollups.omitted_class_summary_count = max(
        0,
        rollups.total_class_summary_count - len(class_summaries),
    )
    return rollups


def _repair_summaries(
    recovery: JavaRecoverProjectResult,
    args: JavaRecoveryReportArgs,
) -> list[JavaRecoveryReportRepairSummary]:
    repair_result = recovery.repair_result
    if repair_result is None:
        return []
    summaries = [
        JavaRecoveryReportRepairSummary(
            kind=repair.kind,
            applied=repair.applied,
            automation=_repair_automation(repair.kind),
            file=repair.file,
            new_file=repair.new_file,
            message=repair.message,
            recommended_action=_repair_next_action(repair.kind)
            if not repair.applied
            else _applied_repair_action(repair.kind),
        )
        for repair in repair_result.repairs
    ]
    return _dedupe_repair_summaries(summaries)[: args.max_repair_summaries]


def _candidate_notes(item: object) -> list[str]:
    attempts = getattr(item, "attempted_engines", [])
    notes: list[str] = []
    for attempt in attempts:
        engine = getattr(attempt, "engine", "unknown")
        parse = _bool_label(getattr(attempt, "parse_success", None))
        compile_status = _bool_label(getattr(attempt, "compile_success", None))
        diagnostics = getattr(attempt, "compile_diagnostic_count", 0)
        context = getattr(attempt, "compile_context", "none")
        score = getattr(attempt, "quality_score", 0)
        notes.append(
            f"{engine}: parse={parse}, compile={compile_status}, context={context}, diagnostics={diagnostics}, score={score}"
        )
    return notes[:8]


def _rollups(
    recovery: JavaRecoverProjectResult,
    class_summaries: list[JavaRecoveryReportClassSummary],
    blockers: list[JavaRecoveryReportBlocker],
    repair_summaries: list[JavaRecoveryReportRepairSummary],
    args: JavaRecoveryReportArgs,
) -> JavaRecoveryReportRollups:
    rollups = JavaRecoveryReportRollups(
        displayed_class_summary_count=len(class_summaries)
    )
    decompile = recovery.decompile_result
    if decompile is not None:
        rollups.total_class_summary_count = len(decompile.classes)
        for item in decompile.classes:
            _increment(rollups.by_package, _package_name(item.class_name))
            _increment(rollups.by_engine, item.selected_engine or "n/a")
            _increment(rollups.by_quality, item.quality)
            _increment(rollups.by_compile_status, _bool_label(item.compile_success))
            _increment(rollups.by_inner_action, item.inner_class_action)
    else:
        rollups.total_class_summary_count = len(class_summaries)
        for item in class_summaries:
            _increment(rollups.by_package, _package_name(item.class_name))
            _increment(rollups.by_engine, item.selected_engine or "n/a")
            _increment(rollups.by_quality, item.quality)
            _increment(rollups.by_compile_status, _bool_label(item.compile_success))
            _increment(rollups.by_inner_action, item.inner_class_action)

    rollups.omitted_class_summary_count = max(
        0,
        rollups.total_class_summary_count
        - min(args.max_class_summaries, len(class_summaries)),
    )
    for blocker in blockers:
        _increment(rollups.blocker_summary_by_category, blocker.category)
        if blocker.location is not None:
            _increment(rollups.blocker_summary_by_file, blocker.location.file)
    for repair in repair_summaries:
        _increment(rollups.repair_summary_by_kind, repair.kind)
    return rollups


def _dedupe_repair_summaries(
    repairs: list[JavaRecoveryReportRepairSummary],
) -> list[JavaRecoveryReportRepairSummary]:
    seen: set[tuple[str, bool, str, str]] = set()
    out: list[JavaRecoveryReportRepairSummary] = []
    for repair in repairs:
        key = (repair.kind, repair.applied, repair.file, repair.new_file)
        if key in seen:
            continue
        seen.add(key)
        out.append(repair)
    return out


def _rank_blockers(
    recovery: JavaRecoverProjectResult,
    args: JavaRecoveryReportArgs,
) -> list[JavaRecoveryReportBlocker]:
    blockers: list[JavaRecoveryReportBlocker] = []
    root = Path(recovery.source_project_root) if recovery.source_project_root else None

    if recovery.compile_result is not None:
        for diagnostic in recovery.compile_result.diagnostics:
            blockers.append(_blocker_from_diagnostic(diagnostic, root, args))

    if recovery.source_index_result is not None:
        for problem in recovery.source_index_result.syntax_problems:
            location = _location(
                file=problem.source_path,
                root=root,
            )
            blockers.append(
                JavaRecoveryReportBlocker(
                    kind="parse_error",
                    severity="high",
                    category="source_parse_error",
                    title=f"JavaParser could not parse {problem.source_path}",
                    message=problem.message,
                    location=location,
                    likely_cause=(
                        "The decompiler emitted Java syntax that JavaParser cannot "
                        "model reliably."
                    ),
                    next_action=(
                        "Inspect the source around the parser problem and compare "
                        "against bytecode/decompiler alternatives before editing."
                    ),
                    snippet=_snippet(root, location, args) if root else [],
                )
            )

    if recovery.repair_result is not None:
        for repair in recovery.repair_result.repairs:
            if repair.applied:
                continue
            location = _location(file=repair.file, root=root)
            blockers.append(
                JavaRecoveryReportBlocker(
                    kind="repair_deferred",
                    severity="medium",
                    category=repair.kind,
                    title=f"Deferred repair: {repair.kind}",
                    message=repair.message,
                    location=location,
                    likely_cause=_repair_likely_cause(repair.kind),
                    next_action=_repair_next_action(repair.kind),
                    snippet=_snippet(root, location, args) if root else [],
                    evidence=[repair.kind],
                )
            )

    validation = recovery.validation_result
    if validation is not None:
        for check in validation.checks:
            if check.status != "fail":
                continue
            blockers.append(
                JavaRecoveryReportBlocker(
                    kind="validation_issue",
                    severity="high",
                    category=check.name,
                    title=f"Validation failed: {check.name}",
                    message=check.message,
                    likely_cause=(
                        "The rebuilt project does not yet match the selected "
                        "validation profile."
                    ),
                    next_action=(
                        "Use the validation details to decide whether to repair "
                        "source, restore resources, or adjust build metadata."
                    ),
                    evidence=[check.name],
                )
            )

    if not blockers and recovery.stop_reasons:
        blockers.append(
            JavaRecoveryReportBlocker(
                kind="missing_input",
                severity="medium",
                category="stop_reason",
                title="Recovery stopped before a clean result",
                message=", ".join(recovery.stop_reasons[:4]),
                likely_cause="The recovery pipeline reported stop reasons.",
                next_action="Inspect stop reasons and rerun with a narrower class filter if needed.",
                evidence=recovery.stop_reasons[:4],
            )
        )

    return _dedupe_blockers(_sort_blockers(blockers))[: args.max_blockers]


def _blocker_from_diagnostic(
    diagnostic: JavaCompilerDiagnostic,
    root: Path | None,
    args: JavaRecoveryReportArgs,
) -> JavaRecoveryReportBlocker:
    location = (
        _location(
            file=diagnostic.file,
            root=root,
            line=diagnostic.line,
            column=diagnostic.column,
        )
        if diagnostic.file
        else None
    )
    category = diagnostic.category
    return JavaRecoveryReportBlocker(
        kind="compile_error",
        severity="high" if diagnostic.severity == "error" else "medium",
        category=category,
        title=_diagnostic_title(diagnostic),
        message=diagnostic.message,
        location=location,
        likely_cause=_diagnostic_likely_cause(diagnostic),
        next_action=_diagnostic_next_action(diagnostic),
        snippet=_snippet(root, location, args) if root and location else [],
        evidence=[diagnostic.raw_excerpt] if diagnostic.raw_excerpt else [],
    )


def _location(
    *,
    file: str,
    root: Path | None,
    line: int | None = None,
    column: int | None = None,
) -> JavaRecoveryReportLocation:
    absolute_file = None
    if root is not None:
        candidate = root / file
        if candidate.exists():
            absolute_file = str(candidate)
    return JavaRecoveryReportLocation(
        file=file,
        absolute_file=absolute_file,
        line=line,
        column=column,
    )


def _diagnostic_title(diagnostic: JavaCompilerDiagnostic) -> str:
    if diagnostic.file and diagnostic.line:
        return f"{diagnostic.category} at {diagnostic.file}:{diagnostic.line}"
    if diagnostic.file:
        return f"{diagnostic.category} in {diagnostic.file}"
    return str(diagnostic.category)


def _diagnostic_likely_cause(diagnostic: JavaCompilerDiagnostic) -> str:
    message = diagnostic.message.lower()
    if diagnostic.category == "missing_classpath_dependency":
        return "A required dependency is missing from the recovered compile classpath."
    if "package" in message and "does not exist" in message:
        return "The source likely needs a dependency/build metadata fix, not a source edit."
    if diagnostic.category == "bad_decompiler_syntax":
        return "The decompiler emitted Java syntax that javac cannot parse."
    if diagnostic.category == "generic_signature_mismatch":
        return "The decompiler likely lost generic, cast, or descriptor information."
    return "javac rejected the recovered source for this location."


def _diagnostic_next_action(diagnostic: JavaCompilerDiagnostic) -> str:
    message = diagnostic.message.lower()
    if diagnostic.category == "missing_classpath_dependency" or (
        "package" in message and "does not exist" in message
    ):
        return (
            "Fix classpath/build metadata first; if the archive contains nested "
            "libraries, rerun with extract_nested_archives=True."
        )
    if diagnostic.category == "bad_decompiler_syntax":
        return (
            "Compare CFR and Vineflower output for this class, then repair the "
            "smallest malformed source construct."
        )
    if diagnostic.category == "generic_signature_mismatch":
        return (
            "Use bytecode descriptors, call-site anchors, and local variable tables "
            "to restore the missing type information."
        )
    return "Inspect this source location and compare it with bytecode evidence."


def _repair_likely_cause(kind: str) -> str:
    if kind == "write_build_repair_plan":
        return "The compiler found missing external packages/classes."
    if kind == "ambiguous_missing_import":
        return "More than one local source type could satisfy the unresolved name."
    if kind == "report_signature_mismatch":
        return "Decompiler output disagrees with bytecode type/signature evidence."
    if kind == "parameterize_raw_iterable_for_each":
        return "The decompiler emitted a raw iterable even though the foreach target type is known."
    if kind == "cast_generic_sneaky_throw":
        return "The decompiler lost the generic cast used by a sneaky-throw helper."
    if kind == "report_malformed_anonymous_class":
        return "The decompiler could not reconstruct an anonymous class as legal Java."
    return "The repair loop found a non-mechanical repair that needs more evidence."


def _repair_automation(kind: str) -> JavaRecoveryRepairAutomation:
    if kind.startswith("report_") or kind == "ambiguous_missing_import":
        return "manual"
    return "automatic"


def _applied_repair_action(kind: str) -> str:
    if kind == "write_build_repair_plan":
        return "Review the generated build repair plan and update dependencies/classpath before rerunning."
    if kind == "parameterize_raw_iterable_for_each":
        return "Rerun compilation and validate the rewritten generic iterable against bytecode evidence."
    if kind == "cast_generic_sneaky_throw":
        return "Rerun compilation and validate the generic sneaky-throw cast against bytecode evidence."
    return "Rerun compilation and validation to confirm the applied repair."


def _repair_next_action(kind: str) -> str:
    if kind == "write_build_repair_plan":
        return "Update the classpath/build file before editing recovered source."
    if kind == "ambiguous_missing_import":
        return (
            "Choose the intended type using package, bytecode, and call-site evidence."
        )
    if kind == "report_signature_mismatch":
        return "Recover the source signature from bytecode descriptors and generic attributes."
    if kind == "parameterize_raw_iterable_for_each":
        return "Use the foreach target type and bytecode descriptors to parameterize the raw iterable."
    if kind == "cast_generic_sneaky_throw":
        return "Restore the generic cast on the thrown Throwable value."
    if kind == "report_malformed_anonymous_class":
        return "Reconstruct the anonymous class body or try the alternate decompiler output."
    return "Review the deferred repair evidence before making a source patch."


def _snippet(
    root: Path | None,
    location: JavaRecoveryReportLocation | None,
    args: JavaRecoveryReportArgs,
) -> list[JavaRecoveryReportSnippetLine]:
    if root is None or location is None or location.line is None:
        return []
    path = root / location.file
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    focus = max(1, location.line)
    start = max(1, focus - args.snippet_context_lines)
    end = min(len(lines), focus + args.snippet_context_lines)
    out: list[JavaRecoveryReportSnippetLine] = []
    for line_no in range(start, end + 1):
        text = lines[line_no - 1]
        if len(text) > args.max_snippet_line_chars:
            text = text[: args.max_snippet_line_chars - 3] + "..."
        out.append(
            JavaRecoveryReportSnippetLine(
                line=line_no,
                text=text,
                focus=line_no == focus,
            )
        )
    return out


def _sort_blockers(
    blockers: list[JavaRecoveryReportBlocker],
) -> list[JavaRecoveryReportBlocker]:
    return sorted(
        blockers,
        key=lambda item: (
            _SEVERITY_RANK.get(item.severity, 0),
            _KIND_RANK.get(item.kind, 0),
            item.location.file if item.location else "",
            item.location.line or 0 if item.location else 0,
        ),
        reverse=True,
    )


def _dedupe_blockers(
    blockers: list[JavaRecoveryReportBlocker],
) -> list[JavaRecoveryReportBlocker]:
    seen: set[tuple[str, str, str, int | None, int | None]] = set()
    out: list[JavaRecoveryReportBlocker] = []
    for blocker in blockers:
        key = (
            blocker.kind,
            blocker.category,
            blocker.location.file if blocker.location else "",
            blocker.location.line if blocker.location else None,
            blocker.location.column if blocker.location else None,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(blocker)
    return out


def _next_actions(
    recovery: JavaRecoverProjectResult,
    blockers: list[JavaRecoveryReportBlocker],
) -> list[str]:
    actions: list[str] = []
    for blocker in blockers:
        _append_once(actions, blocker.next_action)
    if recovery.validation_result is not None:
        for action in recovery.validation_result.next_actions:
            _append_once(actions, action)
    if not actions:
        actions.append(
            "No blocking recovery issues; inspect ABI/resource validation before trusting behavior."
        )
    return actions[:8]


def _commands(
    recovery: JavaRecoverProjectResult,
    blockers: list[JavaRecoveryReportBlocker],
    report_markdown_path: Path | None,
) -> list[str]:
    commands: list[str] = []
    root = recovery.source_project_root
    if report_markdown_path is not None:
        commands.append(f"sed -n '1,220p' {report_markdown_path}")
    if root is not None:
        commands.append(f"cd {root} && javac @javac.args")
    first_location = next(
        (blocker.location for blocker in blockers if blocker.location is not None),
        None,
    )
    if first_location is not None and first_location.absolute_file is not None:
        line = first_location.line or 1
        commands.append(
            f"nl -ba {first_location.absolute_file} | sed -n '{max(1, line - 5)},{line + 5}p'"
        )
    if any(
        blocker.category in {"missing_classpath_dependency", "write_build_repair_plan"}
        or "classpath" in blocker.next_action.lower()
        for blocker in blockers
    ):
        commands.append("rerun java_recovery_report with extract_nested_archives=True")
    return commands[:8]


def _status(
    recovery: JavaRecoverProjectResult,
    blockers: list[JavaRecoveryReportBlocker],
) -> JavaRecoveryReportStatus:
    if recovery.success and not blockers:
        return "clean"
    if recovery.compile_success is False:
        return "blocked"
    if recovery.validation_passed is False or blockers:
        return "partial"
    return "failed"


def _headline(
    status: JavaRecoveryReportStatus,
    recovery: JavaRecoverProjectResult,
    blockers: list[JavaRecoveryReportBlocker],
) -> str:
    if status == "clean":
        return "Recovered Java project compiles and passes the selected validation profile."
    if blockers:
        first = blockers[0]
        if first.location:
            return f"Recovery is blocked by {first.category} at {first.location.file}."
        return f"Recovery is blocked by {first.category}."
    if recovery.quality_summary:
        return recovery.quality_summary
    return "Recovery did not produce a clean project."


def _summary(
    status: JavaRecoveryReportStatus,
    progress: JavaRecoveryReportProgress,
    blockers: list[JavaRecoveryReportBlocker],
) -> str:
    return (
        f"{status}: {progress.generated_source_count} source file(s), "
        f"{progress.parsed_source_count} parsed, "
        f"{progress.compile_diagnostic_count} compile diagnostic(s), "
        f"{len(blockers)} blocker(s)."
    )


def _markdown(
    *,
    status: JavaRecoveryReportStatus,
    headline: str,
    progress: JavaRecoveryReportProgress,
    blockers: list[JavaRecoveryReportBlocker],
    class_summaries: list[JavaRecoveryReportClassSummary],
    repair_summaries: list[JavaRecoveryReportRepairSummary],
    rollups: JavaRecoveryReportRollups,
    next_actions: list[str],
    commands: list[str],
    recovery: JavaRecoverProjectResult,
) -> str:
    lines = [
        "# Java Recovery Report",
        "",
        f"Status: {status}",
        f"Headline: {headline}",
        f"Archive: `{recovery.archive_path}`",
    ]
    if recovery.source_project_root:
        lines.append(f"Project: `{recovery.source_project_root}`")
    lines.extend(
        [
            "",
            "## Progress",
            f"- Cache: {'hit' if progress.cache_hit else 'miss'}",
            (
                "- Sources: "
                f"{progress.generated_source_count} generated, "
                f"{progress.parsed_source_count} parsed, "
                f"{progress.parse_error_count} parse errors"
            ),
            (
                "- AST: "
                f"{progress.type_count} types, "
                f"{progress.method_count} methods, "
                f"{progress.field_count} fields"
            ),
            (
                "- Compile: "
                f"{_bool_label(progress.compile_success)} "
                f"({progress.compile_diagnostic_count} diagnostics)"
            ),
            f"- Repair: {_bool_label(progress.repair_success)} ({progress.repair_count} applied)",
            f"- Validation: {_bool_label(progress.validation_passed)}",
        ]
    )
    if progress.compatibility_score is not None:
        lines.append(f"- Compatibility: {progress.compatibility_score:.2f}")
    lines.extend(
        [
            "",
            "## Rollups",
            (
                "- Classes: "
                f"{rollups.total_class_summary_count} total, "
                f"{rollups.displayed_class_summary_count} shown, "
                f"{rollups.omitted_class_summary_count} omitted"
            ),
            f"- Packages: {_format_counts(rollups.by_package)}",
            f"- Engines: {_format_counts(rollups.by_engine)}",
            f"- Quality: {_format_counts(rollups.by_quality)}",
            f"- Candidate compile: {_format_counts(rollups.by_compile_status)}",
            f"- Inner class actions: {_format_counts(rollups.by_inner_action)}",
        ]
    )
    if rollups.blocker_summary_by_category:
        lines.append(
            f"- Blockers: {_format_counts(rollups.blocker_summary_by_category)}"
        )
    if rollups.repair_summary_by_kind:
        lines.append(f"- Repairs: {_format_counts(rollups.repair_summary_by_kind)}")
    lines.extend(["", "## Source/Bytecode Links"])
    if class_summaries:
        for item in class_summaries:
            source = item.source_file or "n/a"
            bytecode_count = (
                str(item.bytecode_method_count)
                if item.bytecode_method_count is not None
                else "n/a"
            )
            decompiled_count = len(item.decompiled_methods)
            methods = "; ".join(item.bytecode_methods[:4]) or "none"
            anchors = "; ".join(item.bytecode_line_anchors[:4])
            candidates = "; ".join(item.candidate_notes[:3]) or "none"
            notes = (
                f"; notes={','.join(item.correlation_notes)}"
                if item.correlation_notes
                else ""
            )
            lines.append(
                "- "
                f"`{item.class_name}` -> `{source}`: "
                f"bytecode_methods={bytecode_count}, "
                f"decompiled_methods={decompiled_count}{notes}"
            )
            lines.append(f"  - Bytecode: {methods}")
            if anchors:
                lines.append(f"  - Lines: {anchors}")
            lines.append(f"  - Candidates: {candidates}")
    else:
        lines.append("- No source/bytecode links available for this run.")
    lines.extend(["", "## Class Summary"])
    if class_summaries:
        for item in class_summaries:
            source = f" -> `{item.source_file}`" if item.source_file else ""
            compile_status = _bool_label(item.compile_success)
            delta = (
                f", method_delta={item.method_count_delta}"
                if item.method_count_delta is not None
                else ""
            )
            engines = (
                f", attempted={','.join(item.attempted_engines)}"
                if item.attempted_engines
                else ""
            )
            lines.append(
                "- "
                f"`{item.class_name}`: engine={item.selected_engine or 'n/a'}, "
                f"quality={item.quality}, parse={_bool_label(item.parse_success)}, "
                f"candidate_compile={compile_status}, action={item.inner_class_action}"
                f"{delta}{engines}{source}"
            )
    else:
        lines.append("- No per-class decompile summaries available for this run.")
    if rollups.omitted_class_summary_count:
        lines.append(
            "- Omitted "
            f"{rollups.omitted_class_summary_count} additional class summaries; "
            "see recovery-report.json."
        )
    lines.extend(["", "## Repair Summary"])
    if repair_summaries:
        for repair in repair_summaries:
            repair_status = "applied" if repair.applied else "deferred"
            target = (
                repair.new_file if repair.applied and repair.new_file else repair.file
            )
            lines.append(
                f"- {repair_status}/{repair.automation}: {repair.kind} on `{target}` - "
                f"{repair.message}"
            )
            if repair.recommended_action:
                lines.append(f"  - Next: {repair.recommended_action}")
    else:
        lines.append("- No repair attempts were needed or recorded.")
    lines.extend(["", "## Top Blockers"])
    if blockers:
        for index, blocker in enumerate(blockers, start=1):
            loc = _format_location(blocker.location)
            lines.append(f"{index}. {blocker.title}{loc}")
            lines.append(f"   - Error: {blocker.message}")
            lines.append(f"   - Cause: {blocker.likely_cause}")
            lines.append(f"   - Next: {blocker.next_action}")
            if blocker.snippet:
                lines.append("")
                lines.append("   ```java")
                for line in blocker.snippet:
                    marker = ">" if line.focus else " "
                    lines.append(f"   {marker} {line.line}: {line.text}")
                lines.append("   ```")
                lines.append("")
    else:
        lines.append("- No blocking recovery issues.")
    lines.extend(["", "## Next Actions"])
    for action in next_actions:
        lines.append(f"- {action}")
    lines.extend(["", "## Commands"])
    for command in commands:
        lines.append(f"- `{command}`")
    return "\n".join(lines).strip() + "\n"


def _format_location(location: JavaRecoveryReportLocation | None) -> str:
    if location is None:
        return ""
    if location.line is not None:
        return f" (`{location.file}:{location.line}`)"
    return f" (`{location.file}`)"


def _bool_label(value: bool | None) -> str:
    if value is True:
        return "pass"
    if value is False:
        return "fail"
    return "skip"


def _package_name(class_name: str) -> str:
    normalized = class_name.replace(".", "/")
    if "/" not in normalized:
        return "(default)"
    package = normalized.rsplit("/", 1)[0]
    if not package:
        return "(default)"
    return package.replace("/", ".")


def _increment(values: dict[str, int], key: str) -> None:
    values[key] = values.get(key, 0) + 1


def _format_counts(values: dict[str, int], limit: int = 8) -> str:
    if not values:
        return "none"
    items = sorted(values.items(), key=lambda item: (-item[1], item[0]))
    rendered = [f"{key}={count}" for key, count in items[:limit]]
    omitted = len(items) - len(rendered)
    if omitted:
        rendered.append(f"+{omitted} more")
    return ", ".join(rendered)


def _report_path(root: Path | None, value: str) -> Path | None:
    if root is None or not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    return root / path


def _write_report_files(
    result: JavaRecoveryReportResult,
    markdown_path: Path | None,
    json_path: Path | None,
) -> None:
    if markdown_path is not None:
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(result.markdown, encoding="utf-8")
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(
                result.model_dump(exclude={"recovery_result", "report_node_id"}),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


def _add_report_node(kb: KnowledgeBase, result: JavaRecoveryReportResult) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                result.archive_path,
                result.source_project_root or "",
                result.status,
                result.headline,
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    node = Node(
        kind=NodeKind.java_recovery_report,
        label=f"java recovery report {digest}",
        text=result.markdown,
        props={
            "tool": "java_recovery_report",
            "java_recovery_report_id": digest,
            **result.model_dump(exclude={"report_node_id", "recovery_result"}),
        },
        tags=["java", "source-recovery", "report"],
    )
    kb.add_node(node)
    result.report_node_id = node.id


def _append_once(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_KIND_RANK = {
    "compile_error": 5,
    "parse_error": 4,
    "repair_deferred": 3,
    "validation_issue": 2,
    "decompile_failure": 1,
    "missing_input": 0,
}


def build_tool() -> MemoryTool[JavaRecoveryReportArgs, JavaRecoveryReportResult]:
    return JavaRecoveryReportTool()
