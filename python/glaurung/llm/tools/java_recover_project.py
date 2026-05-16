from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_compile_recovered_project import (
    JavaCompileRecoveredProjectResult,
    build_tool as build_java_compile_recovered_project,
)
from .java_decompile_archive import (
    JavaDecompileArchiveResult,
    JavaInnerClassPolicy,
    build_tool as build_java_decompile_archive,
)
from .java_infer_dependencies import (
    JavaInferDependenciesResult,
    build_tool as build_java_infer_dependencies,
)
from .java_index_source_project import (
    JavaIndexSourceProjectResult,
    build_tool as build_java_index_source_project,
)
from .java_reconstruct_source_tree import (
    JavaReconstructSourceTreeResult,
    ResourcePolicy,
    build_tool as build_java_reconstruct_source_tree,
)
from .java_repair_decompiled_source import (
    JavaRepairDecompiledSourceResult,
    build_tool as build_java_repair_decompiled_source,
)
from .java_validate_recovered_application import (
    JavaValidateRecoveredApplicationResult,
    ValidationProfile,
    build_tool as build_java_validate_recovered_application,
)


JavaDecompilerEngine = Literal["auto", "cfr", "vineflower"]


class JavaRecoverProjectArgs(BaseModel):
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
    max_classes: int = Field(256, ge=0)
    max_resources: int = Field(20_000, ge=0)
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
    run_repair: bool = True
    max_repair_iterations: int = Field(3, ge=1, le=10)
    run_validate: bool = True
    validate_profile: ValidationProfile = "full_static"
    allow_generated_stubs: bool = False


class JavaRecoverProjectResult(BaseModel):
    archive_path: str
    source_project_root: str | None = None
    success: bool = False
    quality_summary: str = ""
    reconstruct_result: JavaReconstructSourceTreeResult | None = None
    dependency_result: JavaInferDependenciesResult | None = None
    decompile_result: JavaDecompileArchiveResult | None = None
    source_index_result: JavaIndexSourceProjectResult | None = None
    compile_result: JavaCompileRecoveredProjectResult | None = None
    repair_result: JavaRepairDecompiledSourceResult | None = None
    validation_result: JavaValidateRecoveredApplicationResult | None = None
    decompile_success_count: int = 0
    compile_success: bool | None = None
    repair_success: bool | None = None
    validation_passed: bool | None = None
    parsed_source_count: int = 0
    generated_source_count: int = 0
    generated_resource_count: int = 0
    generated_build_files: list[str] = Field(default_factory=list)
    effective_classpath: list[str] = Field(default_factory=list)
    extracted_nested_archives: list[str] = Field(default_factory=list)
    extracted_nested_archive_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    recovery_node_id: str | None = None


class JavaRecoverProjectTool(
    MemoryTool[JavaRecoverProjectArgs, JavaRecoverProjectResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_recover_project",
                description=(
                    "Run an end-to-end bounded Java recovery flow: preserve "
                    "resources/build metadata, decompile archive classes, refresh "
                    "source/build files, compile, repair, and validate."
                ),
                tags=("java", "jar", "source-recovery", "decompile", "compile", "kb"),
            ),
            JavaRecoverProjectArgs,
            JavaRecoverProjectResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaRecoverProjectArgs,
    ) -> JavaRecoverProjectResult:
        archive_path = Path(args.path or ctx.file_path)
        if not args.output_root:
            return JavaRecoverProjectResult(
                archive_path=str(archive_path),
                stop_reasons=["output_root_missing"],
            )

        output_root = Path(args.output_root)
        result = JavaRecoverProjectResult(
            archive_path=str(archive_path),
            source_project_root=str(output_root),
        )

        reconstruct_tool = build_java_reconstruct_source_tree()
        reconstruct = reconstruct_tool.run(
            ctx,
            kb,
            reconstruct_tool.input_model(
                path=str(archive_path),
                output_root=str(output_root),
                resource_policy=args.resource_policy,
                decompile_sources=False,
                helper_jar=args.helper_jar,
                max_classes=args.max_classes,
                max_resources=args.max_resources,
                java_release=args.java_release,
                generate_build_files=True,
            ),
        )
        result.reconstruct_result = reconstruct
        result.generated_resource_count = len(reconstruct.resource_files)
        result.generated_build_files = reconstruct.build_files
        result.warnings.extend(reconstruct.warnings)
        result.stop_reasons.extend(reconstruct.stop_reasons)
        if reconstruct.stop_reasons and not reconstruct.wrote_files:
            _finish(result, kb)
            return result

        if args.include_dependency_inference:
            dependency_tool = build_java_infer_dependencies()
            dependency_result = dependency_tool.run(
                ctx,
                kb,
                dependency_tool.input_model(path=str(archive_path)),
            )
            result.dependency_result = dependency_result
            result.stop_reasons.extend(dependency_result.stop_reasons)

        if args.extract_nested_archives:
            extracted, extraction_warnings, extraction_reasons = (
                _extract_nested_archives(archive_path, output_root, args)
            )
            result.extracted_nested_archives = [
                _relative(output_root, path) for path in extracted
            ]
            result.extracted_nested_archive_count = len(extracted)
            result.warnings.extend(extraction_warnings)
            result.stop_reasons.extend(extraction_reasons)

        effective_classpath = _effective_classpath(output_root, args)
        result.effective_classpath = [
            _relative_or_str(output_root, path) for path in effective_classpath
        ]

        decompile_tool = build_java_decompile_archive()
        decompile = decompile_tool.run(
            ctx,
            kb,
            decompile_tool.input_model(
                path=str(archive_path),
                output_root=str(output_root),
                engine=args.decompiler_engine,
                helper_jar=args.helper_jar,
                mapping_path=args.mapping_path,
                include_packages=args.include_packages,
                include_class_globs=args.include_class_globs,
                inner_class_policy=args.inner_class_policy,
                max_classes=args.max_classes,
                max_source_chars_per_class=args.max_source_chars_per_class,
                timeout_seconds_per_class=args.timeout_seconds_per_class,
                write_sources=True,
                include_bytecode_correlation=True,
                rewrite_mapped_sources=args.rewrite_mapped_sources,
                compile_candidates=args.compile_candidates,
                candidate_project_root=str(output_root),
                candidate_classpath=[str(path) for path in effective_classpath],
                java_release=args.java_release,
            ),
        )
        result.decompile_result = decompile
        result.decompile_success_count = decompile.success_count
        result.generated_source_count = decompile.written_source_count
        result.warnings.extend(decompile.warnings)
        result.stop_reasons.extend(decompile.stop_reasons)

        _refresh_sources_and_javac_args(
            output_root,
            args.java_release,
            effective_classpath,
        )
        index_tool = build_java_index_source_project()
        source_index = index_tool.run(
            ctx,
            kb,
            index_tool.input_model(
                source_project_root=str(output_root),
                helper_jar=args.helper_jar,
                timeout_seconds_per_file=args.timeout_seconds_per_class,
            ),
        )
        result.source_index_result = source_index
        result.parsed_source_count = source_index.parse_success_count
        result.stop_reasons.extend(source_index.stop_reasons)

        compile_tool = build_java_compile_recovered_project()
        compile_result = compile_tool.run(
            ctx,
            kb,
            compile_tool.input_model(
                source_project_root=str(output_root),
                build_tool="javac",
                java_release=args.java_release,
                classpath=[str(path) for path in effective_classpath],
                timeout_seconds=args.timeout_seconds_per_class,
            ),
        )
        result.compile_result = compile_result
        result.compile_success = compile_result.success
        result.warnings.extend(compile_result.warnings)
        result.stop_reasons.extend(compile_result.stop_reasons)

        if compile_result.success:
            result.repair_success = True
        elif args.run_repair:
            repair_tool = build_java_repair_decompiled_source()
            repair = repair_tool.run(
                ctx,
                kb,
                repair_tool.input_model(
                    source_project_root=str(output_root),
                    build_tool="javac",
                    java_release=args.java_release,
                    classpath=[str(path) for path in effective_classpath],
                    max_iterations=args.max_repair_iterations,
                    timeout_seconds=args.timeout_seconds_per_class,
                ),
            )
            result.repair_result = repair
            result.repair_success = repair.success
            result.compile_result = repair.final_compile_result or compile_result
            result.compile_success = result.compile_result.success
            result.warnings.extend(repair.warnings)
            result.stop_reasons.extend(repair.stop_reasons)

        if args.run_validate:
            validate_tool = build_java_validate_recovered_application()
            validation = validate_tool.run(
                ctx,
                kb,
                validate_tool.input_model(
                    original_path=str(archive_path),
                    source_project_root=str(output_root),
                    profile=args.validate_profile,
                    java_release=args.java_release,
                    classpath=[str(path) for path in effective_classpath],
                    run_compile=True,
                    allow_generated_stubs=args.allow_generated_stubs,
                    compile_timeout_seconds=args.timeout_seconds_per_class,
                ),
            )
            result.validation_result = validation
            result.validation_passed = validation.validation_passed
            result.quality_summary = validation.quality_summary
            result.warnings.extend(validation.warnings)
            result.stop_reasons.extend(validation.stop_reasons)
            result.success = validation.validation_passed
        else:
            result.success = bool(result.compile_success)
            result.quality_summary = (
                "clean_enough: recovered source compiles for the selected profile."
                if result.success
                else "not_clean_enough: recovered source does not compile."
            )

        _finish(result, kb)
        return result


def _refresh_sources_and_javac_args(
    output_root: Path,
    java_release: int,
    classpath: list[Path],
) -> None:
    source_root = output_root / "src" / "main" / "java"
    sources = sorted(path for path in source_root.rglob("*.java") if path.is_file())
    (output_root / "sources.txt").write_text(
        "\n".join(_relative(output_root, source) for source in sources) + "\n",
        encoding="utf-8",
    )
    lines = ["--release", str(java_release)]
    if classpath:
        lines.extend(
            [
                "-classpath",
                ":".join(_relative_or_str(output_root, path) for path in classpath),
            ]
        )
    lines.extend(["-d", "build/classes", "@sources.txt", ""])
    (output_root / "javac.args").write_text("\n".join(lines), encoding="utf-8")


def _effective_classpath(
    output_root: Path,
    args: JavaRecoverProjectArgs,
) -> list[Path]:
    candidates = [Path(item) for item in args.classpath]
    if args.collect_local_libraries:
        for lib_dir in (output_root / "libs", output_root / "lib"):
            if lib_dir.is_dir():
                candidates.extend(
                    sorted(path for path in lib_dir.rglob("*.jar") if path.is_file())
                )
    return _dedupe_paths(candidates)


def _extract_nested_archives(
    archive_path: Path,
    output_root: Path,
    args: JavaRecoverProjectArgs,
) -> tuple[list[Path], list[str], list[str]]:
    extracted: list[Path] = []
    warnings: list[str] = []
    stop_reasons: list[str] = []
    if not zipfile.is_zipfile(archive_path):
        return extracted, warnings, ["input_not_zip_for_nested_archives"]
    dest_root = output_root / "libs" / "nested"
    dest_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith((".jar", ".zip")):
                continue
            safe_name = _safe_archive_path(info.filename)
            if safe_name is None:
                warnings.append(f"Skipped unsafe nested archive path {info.filename}.")
                continue
            if len(extracted) >= args.max_nested_archives:
                stop_reasons.append("max_nested_archives")
                break
            if info.file_size > args.max_nested_archive_bytes:
                warnings.append(
                    f"Skipped oversized nested archive {safe_name} ({info.file_size} bytes)."
                )
                stop_reasons.append("max_nested_archive_bytes")
                continue
            dest = _nested_archive_destination(dest_root, safe_name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(zf.read(info))
            extracted.append(dest)
    return extracted, warnings, _dedupe(stop_reasons)


def _nested_archive_destination(dest_root: Path, archive_entry: str) -> Path:
    basename = PurePosixPath(archive_entry).name
    dest = dest_root / basename
    if not dest.exists():
        return dest
    digest = hashlib.sha256(archive_entry.encode("utf-8")).hexdigest()[:8]
    return dest_root / f"{dest.stem}-{digest}{dest.suffix}"


def _safe_archive_path(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _finish(result: JavaRecoverProjectResult, kb: KnowledgeBase) -> None:
    result.stop_reasons = _dedupe(result.stop_reasons)
    result.warnings = _dedupe(result.warnings)
    if not result.quality_summary:
        if result.success:
            result.quality_summary = "clean_enough: recovery flow completed."
        else:
            result.quality_summary = "not_clean_enough: recovery flow did not pass."
    _add_recovery_node(kb, result)


def _add_recovery_node(
    kb: KnowledgeBase,
    result: JavaRecoverProjectResult,
) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                result.archive_path,
                result.source_project_root or "",
                str(result.compile_success),
                str(result.validation_passed),
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    node = Node(
        kind=NodeKind.java_recovery_project,
        label=f"recovery project {digest}",
        text=(
            "Recovered Java project passed the selected recovery flow."
            if result.success
            else "Recovered Java project did not pass the selected recovery flow."
        ),
        props={
            "tool": "java_recover_project",
            "java_recovery_project_id": digest,
            **result.model_dump(exclude={"recovery_node_id"}),
        },
        tags=["java", "source-recovery", "project"],
    )
    kb.add_node(node)
    result.recovery_node_id = node.id


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _relative_or_str(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_tool() -> MemoryTool[JavaRecoverProjectArgs, JavaRecoverProjectResult]:
    return JavaRecoverProjectTool()
