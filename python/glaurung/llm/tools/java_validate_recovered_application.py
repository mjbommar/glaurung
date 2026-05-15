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
from .java_compare_rebuilt_abi import (
    AbiScope,
    JavaAbiDifference,
    build_tool as build_java_compare_rebuilt_abi,
)
from .java_compile_recovered_project import (
    JavaCompilerDiagnostic,
    build_tool as build_java_compile_recovered_project,
)


ValidationProfile = Literal["compile_only", "abi", "resources", "full_static"]
ValidationStatus = Literal["valid", "invalid", "partial", "unsupported"]
ResourceDifferenceKind = Literal[
    "missing_resource",
    "extra_resource",
    "changed_resource",
]


class JavaValidateRecoveredApplicationArgs(BaseModel):
    original_path: str | None = Field(
        None,
        description="Original JAR/ZIP archive. Defaults to the memory context path.",
    )
    source_project_root: str | None = Field(
        None,
        description="Recovered Java source project root.",
    )
    rebuilt_path: str | None = Field(
        None,
        description=(
            "Optional rebuilt JAR/class directory. If omitted and compilation runs, "
            "the generated classes directory is used for ABI comparison."
        ),
    )
    profile: ValidationProfile = "full_static"
    java_release: int | None = Field(None, ge=1)
    classpath: list[str] = Field(default_factory=list)
    run_compile: bool = True
    allow_generated_stubs: bool = False
    abi_scope: AbiScope = "all"
    include_annotations: bool = Field(
        False,
        description="Include class/member annotation parity in ABI validation.",
    )
    max_abi_differences: int = Field(64, ge=0)
    max_resource_differences: int = Field(64, ge=0)
    max_resources: int = Field(20_000, ge=0)
    max_resource_bytes: int = Field(20_000_000, ge=0)
    compile_timeout_seconds: int = Field(30, ge=1, le=600)


class JavaResourceDifference(BaseModel):
    kind: ResourceDifferenceKind
    resource_path: str
    original_size: int | None = None
    recovered_size: int | None = None
    original_sha256: str | None = None
    recovered_sha256: str | None = None
    message: str


class JavaValidateRecoveredApplicationResult(BaseModel):
    original_path: str
    source_project_root: str | None = None
    rebuilt_path: str | None = None
    profile: ValidationProfile
    status: ValidationStatus
    validation_passed: bool
    compile_success: bool | None = None
    compile_diagnostic_count: int = 0
    compile_diagnostics: list[JavaCompilerDiagnostic] = Field(default_factory=list)
    abi_match: bool | None = None
    abi_difference_count: int = 0
    abi_differences: list[JavaAbiDifference] = Field(default_factory=list)
    resource_match: bool | None = None
    original_resource_count: int = 0
    recovered_resource_count: int = 0
    resource_difference_count: int = 0
    resource_differences: list[JavaResourceDifference] = Field(default_factory=list)
    stub_source_count: int = 0
    stub_sources: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    truncated: bool = False


class _ResourceRecord(BaseModel):
    size: int
    sha256: str


class _ResourceLoadResult(BaseModel):
    resources: dict[str, _ResourceRecord] = Field(default_factory=dict)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class JavaValidateRecoveredApplicationTool(
    MemoryTool[
        JavaValidateRecoveredApplicationArgs,
        JavaValidateRecoveredApplicationResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_validate_recovered_application",
                description=(
                    "Validate a recovered Java source project by compiling it, "
                    "comparing rebuilt ABI against the original archive, checking "
                    "resource parity, and rejecting generated stubs unless allowed."
                ),
                tags=("java", "source-recovery", "verification", "resources", "kb"),
            ),
            JavaValidateRecoveredApplicationArgs,
            JavaValidateRecoveredApplicationResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaValidateRecoveredApplicationArgs,
    ) -> JavaValidateRecoveredApplicationResult:
        original_path = Path(args.original_path or ctx.file_path)
        project_root = (
            Path(args.source_project_root) if args.source_project_root else None
        )
        stop_reasons: list[str] = []
        warnings: list[str] = []

        if project_root is None or not project_root.is_dir():
            return _result(
                original_path=original_path,
                project_root=project_root,
                rebuilt_path=Path(args.rebuilt_path) if args.rebuilt_path else None,
                profile=args.profile,
                status="unsupported",
                validation_passed=False,
                stop_reasons=["source_project_root_missing"],
            )
        if args.profile != "compile_only" and not original_path.exists():
            return _result(
                original_path=original_path,
                project_root=project_root,
                rebuilt_path=Path(args.rebuilt_path) if args.rebuilt_path else None,
                profile=args.profile,
                status="unsupported",
                validation_passed=False,
                stop_reasons=["original_path_missing"],
            )

        stub_sources = _find_generated_stubs(project_root)
        if stub_sources and not args.allow_generated_stubs:
            stop_reasons.append("generated_stubs_present")

        compile_success: bool | None = None
        compile_diagnostic_count = 0
        compile_diagnostics: list[JavaCompilerDiagnostic] = []
        rebuilt_path = Path(args.rebuilt_path) if args.rebuilt_path else None
        if args.run_compile:
            compile_tool = build_java_compile_recovered_project()
            compile_result = compile_tool.run(
                ctx,
                kb,
                compile_tool.input_model(
                    source_project_root=str(project_root),
                    java_release=args.java_release,
                    classpath=args.classpath,
                    timeout_seconds=args.compile_timeout_seconds,
                ),
            )
            compile_success = compile_result.success
            compile_diagnostic_count = compile_result.diagnostic_count
            compile_diagnostics = compile_result.diagnostics
            warnings.extend(compile_result.warnings)
            stop_reasons.extend(compile_result.stop_reasons)
            if rebuilt_path is None and compile_result.generated_classes_dir:
                rebuilt_path = Path(compile_result.generated_classes_dir)

        abi_match: bool | None = None
        abi_difference_count = 0
        abi_differences: list[JavaAbiDifference] = []
        if args.profile in {"abi", "full_static"}:
            if rebuilt_path is None or not rebuilt_path.exists():
                stop_reasons.append("rebuilt_path_missing_for_abi")
                abi_match = False
            else:
                abi_tool = build_java_compare_rebuilt_abi()
                abi_result = abi_tool.run(
                    ctx,
                    kb,
                    abi_tool.input_model(
                        original_path=str(original_path),
                        rebuilt_path=str(rebuilt_path),
                        scope=args.abi_scope,
                        include_annotations=args.include_annotations,
                        max_differences=args.max_abi_differences,
                    ),
                )
                abi_match = abi_result.abi_match
                abi_difference_count = abi_result.difference_count
                abi_differences = abi_result.differences
                stop_reasons.extend(abi_result.stop_reasons)

        resource_match: bool | None = None
        original_resource_count = 0
        recovered_resource_count = 0
        resource_difference_count = 0
        resource_differences: list[JavaResourceDifference] = []
        resource_truncated = False
        if args.profile in {"resources", "full_static"}:
            resource_result = _compare_resources(
                original_path,
                project_root / "src" / "main" / "resources",
                args.max_resources,
                args.max_resource_bytes,
                args.max_resource_differences,
            )
            resource_match = not resource_result.differences and not (
                resource_result.original.stop_reasons
                or resource_result.recovered.stop_reasons
            )
            original_resource_count = len(resource_result.original.resources)
            recovered_resource_count = len(resource_result.recovered.resources)
            resource_difference_count = len(resource_result.differences)
            resource_differences = resource_result.differences
            resource_truncated = (
                resource_result.original.truncated
                or resource_result.recovered.truncated
                or resource_result.truncated
            )
            stop_reasons.extend(resource_result.original.stop_reasons)
            stop_reasons.extend(resource_result.recovered.stop_reasons)
            stop_reasons.extend(resource_result.stop_reasons)
            warnings.extend(resource_result.original.warnings)
            warnings.extend(resource_result.recovered.warnings)

        stop_reasons = _dedupe(stop_reasons)
        validation_passed = _passes_validation(
            compile_success=compile_success,
            abi_match=abi_match,
            resource_match=resource_match,
            stub_sources=stub_sources,
            allow_generated_stubs=args.allow_generated_stubs,
            stop_reasons=stop_reasons,
        )
        result = JavaValidateRecoveredApplicationResult(
            original_path=str(original_path),
            source_project_root=str(project_root),
            rebuilt_path=str(rebuilt_path) if rebuilt_path else None,
            profile=args.profile,
            status=_status(validation_passed, stop_reasons),
            validation_passed=validation_passed,
            compile_success=compile_success,
            compile_diagnostic_count=compile_diagnostic_count,
            compile_diagnostics=compile_diagnostics,
            abi_match=abi_match,
            abi_difference_count=abi_difference_count,
            abi_differences=abi_differences,
            resource_match=resource_match,
            original_resource_count=original_resource_count,
            recovered_resource_count=recovered_resource_count,
            resource_difference_count=resource_difference_count,
            resource_differences=resource_differences,
            stub_source_count=len(stub_sources),
            stub_sources=stub_sources,
            stop_reasons=stop_reasons,
            warnings=_dedupe(warnings),
            truncated=resource_truncated,
        )
        _add_validation_node(kb, result)
        return result


class _ResourceComparison(BaseModel):
    original: _ResourceLoadResult
    recovered: _ResourceLoadResult
    differences: list[JavaResourceDifference] = Field(default_factory=list)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


def _result(
    *,
    original_path: Path,
    project_root: Path | None,
    rebuilt_path: Path | None,
    profile: ValidationProfile,
    status: ValidationStatus,
    validation_passed: bool,
    stop_reasons: list[str],
) -> JavaValidateRecoveredApplicationResult:
    return JavaValidateRecoveredApplicationResult(
        original_path=str(original_path),
        source_project_root=str(project_root) if project_root else None,
        rebuilt_path=str(rebuilt_path) if rebuilt_path else None,
        profile=profile,
        status=status,
        validation_passed=validation_passed,
        stop_reasons=stop_reasons,
    )


def _find_generated_stubs(project_root: Path) -> list[str]:
    source_root = project_root / "src" / "main" / "java"
    if not source_root.is_dir():
        return []
    stubs: list[str] = []
    for source in sorted(source_root.rglob("*.java")):
        text = source.read_text(encoding="utf-8", errors="replace")
        if "GLAURUNG GENERATED STUB" in text:
            stubs.append(_relative(project_root, source))
    return stubs


def _compare_resources(
    original_path: Path,
    recovered_root: Path,
    max_resources: int,
    max_resource_bytes: int,
    max_differences: int,
) -> _ResourceComparison:
    original = _archive_resources(original_path, max_resources, max_resource_bytes)
    recovered = _directory_resources(recovered_root, max_resources, max_resource_bytes)
    differences: list[JavaResourceDifference] = []
    for resource_path in sorted(set(original.resources) - set(recovered.resources)):
        record = original.resources[resource_path]
        _add_resource_difference(
            differences,
            max_differences,
            JavaResourceDifference(
                kind="missing_resource",
                resource_path=resource_path,
                original_size=record.size,
                original_sha256=record.sha256,
                message=f"Recovered project is missing resource {resource_path}.",
            ),
        )
    for resource_path in sorted(set(recovered.resources) - set(original.resources)):
        record = recovered.resources[resource_path]
        _add_resource_difference(
            differences,
            max_differences,
            JavaResourceDifference(
                kind="extra_resource",
                resource_path=resource_path,
                recovered_size=record.size,
                recovered_sha256=record.sha256,
                message=f"Recovered project adds resource {resource_path}.",
            ),
        )
    for resource_path in sorted(set(original.resources) & set(recovered.resources)):
        original_record = original.resources[resource_path]
        recovered_record = recovered.resources[resource_path]
        if original_record.sha256 == recovered_record.sha256:
            continue
        _add_resource_difference(
            differences,
            max_differences,
            JavaResourceDifference(
                kind="changed_resource",
                resource_path=resource_path,
                original_size=original_record.size,
                recovered_size=recovered_record.size,
                original_sha256=original_record.sha256,
                recovered_sha256=recovered_record.sha256,
                message=f"Recovered project changed resource {resource_path}.",
            ),
        )
    stop_reasons = []
    truncated = len(differences) >= max_differences > 0
    if truncated:
        stop_reasons.append("max_resource_differences")
    return _ResourceComparison(
        original=original,
        recovered=recovered,
        differences=differences,
        truncated=truncated,
        stop_reasons=stop_reasons,
    )


def _archive_resources(
    path: Path,
    max_resources: int,
    max_resource_bytes: int,
) -> _ResourceLoadResult:
    result = _ResourceLoadResult()
    if not zipfile.is_zipfile(path):
        result.stop_reasons.append("original_not_zip_for_resources")
        return result
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            normalized = _safe_archive_path(info.filename)
            if normalized is None:
                result.warnings.append(f"Skipped unsafe resource path {info.filename}.")
                continue
            if _skip_archive_resource(normalized):
                continue
            if len(result.resources) >= max_resources:
                result.truncated = True
                result.stop_reasons.append("max_resources")
                break
            if info.file_size > max_resource_bytes:
                result.truncated = True
                result.stop_reasons.append("max_resource_bytes")
                continue
            data = zf.read(info)
            result.resources[normalized] = _resource_record(data)
    result.stop_reasons = _dedupe(result.stop_reasons)
    return result


def _directory_resources(
    root: Path,
    max_resources: int,
    max_resource_bytes: int,
) -> _ResourceLoadResult:
    result = _ResourceLoadResult()
    if not root.is_dir():
        return result
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        resource_path = _relative(root, path)
        if len(result.resources) >= max_resources:
            result.truncated = True
            result.stop_reasons.append("max_resources")
            break
        size = path.stat().st_size
        if size > max_resource_bytes:
            result.truncated = True
            result.stop_reasons.append("max_resource_bytes")
            continue
        result.resources[resource_path] = _resource_record(path.read_bytes())
    result.stop_reasons = _dedupe(result.stop_reasons)
    return result


def _skip_archive_resource(path: str) -> bool:
    return path.endswith(".class") or _is_signature_file(path)


def _is_signature_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if len(parts) != 2 or parts[0].upper() != "META-INF":
        return False
    return parts[1].upper().endswith((".SF", ".RSA", ".DSA", ".EC"))


def _safe_archive_path(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _resource_record(data: bytes) -> _ResourceRecord:
    return _ResourceRecord(size=len(data), sha256=hashlib.sha256(data).hexdigest())


def _add_resource_difference(
    differences: list[JavaResourceDifference],
    max_differences: int,
    difference: JavaResourceDifference,
) -> None:
    if max_differences == 0 or len(differences) < max_differences:
        differences.append(difference)


def _passes_validation(
    *,
    compile_success: bool | None,
    abi_match: bool | None,
    resource_match: bool | None,
    stub_sources: list[str],
    allow_generated_stubs: bool,
    stop_reasons: list[str],
) -> bool:
    if stub_sources and not allow_generated_stubs:
        return False
    if any(
        reason for reason in stop_reasons if reason not in {"generated_stubs_present"}
    ):
        return False
    if compile_success is False or abi_match is False or resource_match is False:
        return False
    return True


def _status(validation_passed: bool, stop_reasons: list[str]) -> ValidationStatus:
    if validation_passed:
        return "valid"
    if any(reason.endswith("_missing") for reason in stop_reasons) or any(
        reason.startswith("original_not_zip") for reason in stop_reasons
    ):
        return "unsupported"
    if any(reason.startswith("max_") for reason in stop_reasons):
        return "partial"
    return "invalid"


def _add_validation_node(
    kb: KnowledgeBase,
    result: JavaValidateRecoveredApplicationResult,
) -> None:
    digest = hashlib.sha256(
        "|".join(
            [
                result.original_path,
                result.source_project_root or "",
                result.rebuilt_path or "",
                result.profile,
                result.status,
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    kb.add_node(
        Node(
            kind=NodeKind.java_recovery_validation,
            label=f"recovery {result.status}: {digest}",
            text=(
                "Recovered Java application passed static validation."
                if result.validation_passed
                else "Recovered Java application failed static validation."
            ),
            props={
                "tool": "java_validate_recovered_application",
                "java_recovery_validation_id": digest,
                **result.model_dump(),
            },
            tags=["java", "source-recovery", "verification"],
        )
    )


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def build_tool() -> MemoryTool[
    JavaValidateRecoveredApplicationArgs,
    JavaValidateRecoveredApplicationResult,
]:
    return JavaValidateRecoveredApplicationTool()
