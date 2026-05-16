from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

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
ValidationCheckStatus = Literal["pass", "fail", "skip"]
ResourceDifferenceKind = Literal[
    "missing_resource",
    "extra_resource",
    "changed_resource",
]
MetadataDifferenceKind = Literal[
    "manifest",
    "service",
    "module_info",
]
SemanticDifferenceKind = Literal[
    "record_components",
    "permitted_subclasses",
    "method_parameter_annotations",
    "annotation_default",
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


class JavaValidationCheck(BaseModel):
    name: str
    status: ValidationCheckStatus
    message: str


class JavaMetadataDifference(BaseModel):
    kind: MetadataDifferenceKind
    resource_path: str
    message: str


class JavaSemanticDifference(BaseModel):
    kind: SemanticDifferenceKind
    class_name: str
    member_name: str | None = None
    descriptor: str | None = None
    original_value: str | None = None
    rebuilt_value: str | None = None
    message: str


class JavaValidateRecoveredApplicationResult(BaseModel):
    original_path: str
    source_project_root: str | None = None
    rebuilt_path: str | None = None
    profile: ValidationProfile
    status: ValidationStatus
    validation_passed: bool
    quality_summary: str = ""
    blocking_issue_count: int = 0
    checks: list[JavaValidationCheck] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
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
    metadata_match: bool | None = None
    metadata_difference_count: int = 0
    metadata_differences: list[JavaMetadataDifference] = Field(default_factory=list)
    semantic_match: bool | None = None
    semantic_difference_count: int = 0
    semantic_differences: list[JavaSemanticDifference] = Field(default_factory=list)
    compatibility_score: float = 0.0
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


class _ClassSemantic(BaseModel):
    class_name: str
    record_components: list[str] = Field(default_factory=list)
    permitted_subclasses: list[str] = Field(default_factory=list)
    method_parameter_annotation_counts: dict[str, int] = Field(default_factory=dict)
    annotation_defaults: dict[str, str] = Field(default_factory=dict)


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

        semantic_match: bool | None = None
        semantic_differences: list[JavaSemanticDifference] = []
        if args.profile in {"abi", "full_static"} and rebuilt_path is not None:
            if rebuilt_path.exists():
                semantic_differences = _compare_semantics(
                    original_path,
                    rebuilt_path,
                    args.max_abi_differences,
                )
                semantic_match = not semantic_differences

        resource_match: bool | None = None
        original_resource_count = 0
        recovered_resource_count = 0
        resource_difference_count = 0
        resource_differences: list[JavaResourceDifference] = []
        resource_truncated = False
        metadata_match: bool | None = None
        metadata_differences: list[JavaMetadataDifference] = []
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
            metadata_differences = _compare_metadata(
                original_path,
                project_root / "src" / "main" / "resources",
                rebuilt_path,
                args.max_resource_differences,
            )
            metadata_match = not metadata_differences

        stop_reasons = _dedupe(stop_reasons)
        validation_passed = _passes_validation(
            compile_success=compile_success,
            abi_match=abi_match,
            resource_match=resource_match,
            metadata_match=metadata_match,
            semantic_match=semantic_match,
            stub_sources=stub_sources,
            allow_generated_stubs=args.allow_generated_stubs,
            stop_reasons=stop_reasons,
        )
        checks = _validation_checks(
            compile_success=compile_success,
            abi_match=abi_match,
            resource_match=resource_match,
            metadata_match=metadata_match,
            semantic_match=semantic_match,
            stub_sources=stub_sources,
            allow_generated_stubs=args.allow_generated_stubs,
            stop_reasons=stop_reasons,
        )
        next_actions = _next_actions(
            compile_success=compile_success,
            compile_diagnostic_count=compile_diagnostic_count,
            abi_match=abi_match,
            abi_difference_count=abi_difference_count,
            resource_match=resource_match,
            resource_difference_count=resource_difference_count,
            metadata_match=metadata_match,
            metadata_difference_count=len(metadata_differences),
            semantic_match=semantic_match,
            semantic_difference_count=len(semantic_differences),
            stub_sources=stub_sources,
            stop_reasons=stop_reasons,
        )
        result = JavaValidateRecoveredApplicationResult(
            original_path=str(original_path),
            source_project_root=str(project_root),
            rebuilt_path=str(rebuilt_path) if rebuilt_path else None,
            profile=args.profile,
            status=_status(validation_passed, stop_reasons),
            validation_passed=validation_passed,
            quality_summary=_quality_summary(validation_passed, checks),
            blocking_issue_count=sum(1 for check in checks if check.status == "fail"),
            checks=checks,
            next_actions=next_actions,
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
            metadata_match=metadata_match,
            metadata_difference_count=len(metadata_differences),
            metadata_differences=metadata_differences,
            semantic_match=semantic_match,
            semantic_difference_count=len(semantic_differences),
            semantic_differences=semantic_differences,
            compatibility_score=_compatibility_score(
                compile_success=compile_success,
                abi_difference_count=abi_difference_count,
                resource_difference_count=resource_difference_count,
                metadata_difference_count=len(metadata_differences),
                semantic_difference_count=len(semantic_differences),
                stub_source_count=len(stub_sources),
            ),
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


def _compare_metadata(
    original_path: Path,
    recovered_root: Path,
    rebuilt_path: Path | None,
    max_differences: int,
) -> list[JavaMetadataDifference]:
    differences: list[JavaMetadataDifference] = []
    if not zipfile.is_zipfile(original_path):
        return differences
    with zipfile.ZipFile(original_path) as zf:
        names = {
            normalized
            for info in zf.infolist()
            if not info.is_dir()
            for normalized in [_safe_archive_path(info.filename)]
            if normalized is not None
        }
        for metadata_path in sorted(_metadata_resource_paths(names)):
            original_data = zf.read(metadata_path)
            recovered_file = recovered_root / metadata_path
            if not recovered_file.is_file():
                _add_metadata_difference(
                    differences,
                    max_differences,
                    JavaMetadataDifference(
                        kind=_metadata_kind(metadata_path),
                        resource_path=metadata_path,
                        message=f"Recovered project is missing metadata {metadata_path}.",
                    ),
                )
                continue
            if recovered_file.read_bytes() != original_data:
                _add_metadata_difference(
                    differences,
                    max_differences,
                    JavaMetadataDifference(
                        kind=_metadata_kind(metadata_path),
                        resource_path=metadata_path,
                        message=f"Recovered project changed metadata {metadata_path}.",
                    ),
                )
        for metadata_path in sorted(_directory_metadata_paths(recovered_root)):
            if metadata_path in names:
                continue
            _add_metadata_difference(
                differences,
                max_differences,
                JavaMetadataDifference(
                    kind=_metadata_kind(metadata_path),
                    resource_path=metadata_path,
                    message=f"Recovered project adds metadata {metadata_path}.",
                ),
            )
        if "module-info.class" in names and not _rebuilt_has_module_info(rebuilt_path):
            _add_metadata_difference(
                differences,
                max_differences,
                JavaMetadataDifference(
                    kind="module_info",
                    resource_path="module-info.class",
                    message=(
                        "Original archive has module-info.class, but rebuilt output "
                        "does not contain a module descriptor."
                    ),
                ),
            )
    return differences


def _compare_semantics(
    original_path: Path,
    rebuilt_path: Path,
    max_differences: int,
) -> list[JavaSemanticDifference]:
    original = _load_semantics(original_path)
    rebuilt = _load_semantics(rebuilt_path)
    differences: list[JavaSemanticDifference] = []
    for class_name in sorted(set(original) & set(rebuilt)):
        original_class = original[class_name]
        rebuilt_class = rebuilt[class_name]
        if original_class.record_components != rebuilt_class.record_components:
            _add_semantic_difference(
                differences,
                max_differences,
                JavaSemanticDifference(
                    kind="record_components",
                    class_name=class_name,
                    original_value=", ".join(original_class.record_components),
                    rebuilt_value=", ".join(rebuilt_class.record_components),
                    message=f"Record components differ for {class_name}.",
                ),
            )
        if original_class.permitted_subclasses != rebuilt_class.permitted_subclasses:
            _add_semantic_difference(
                differences,
                max_differences,
                JavaSemanticDifference(
                    kind="permitted_subclasses",
                    class_name=class_name,
                    original_value=", ".join(original_class.permitted_subclasses),
                    rebuilt_value=", ".join(rebuilt_class.permitted_subclasses),
                    message=f"Permitted subclasses differ for {class_name}.",
                ),
            )
        for method_key in sorted(
            set(original_class.method_parameter_annotation_counts)
            | set(rebuilt_class.method_parameter_annotation_counts)
        ):
            original_count = original_class.method_parameter_annotation_counts.get(
                method_key, 0
            )
            rebuilt_count = rebuilt_class.method_parameter_annotation_counts.get(
                method_key, 0
            )
            if original_count == rebuilt_count:
                continue
            name, _, descriptor = method_key.partition(":")
            _add_semantic_difference(
                differences,
                max_differences,
                JavaSemanticDifference(
                    kind="method_parameter_annotations",
                    class_name=class_name,
                    member_name=name,
                    descriptor=descriptor,
                    original_value=str(original_count),
                    rebuilt_value=str(rebuilt_count),
                    message=(
                        "Method parameter annotation counts differ for "
                        f"{class_name}.{name}{descriptor}."
                    ),
                ),
            )
        for method_key in sorted(
            set(original_class.annotation_defaults)
            | set(rebuilt_class.annotation_defaults)
        ):
            original_default = original_class.annotation_defaults.get(method_key)
            rebuilt_default = rebuilt_class.annotation_defaults.get(method_key)
            if original_default == rebuilt_default:
                continue
            name, _, descriptor = method_key.partition(":")
            _add_semantic_difference(
                differences,
                max_differences,
                JavaSemanticDifference(
                    kind="annotation_default",
                    class_name=class_name,
                    member_name=name,
                    descriptor=descriptor,
                    original_value=original_default,
                    rebuilt_value=rebuilt_default,
                    message=(
                        "Annotation default differs for "
                        f"{class_name}.{name}{descriptor}."
                    ),
                ),
            )
    return differences


def _load_semantics(path: Path) -> dict[str, _ClassSemantic]:
    out: dict[str, _ClassSemantic] = {}
    for data in _class_bytes(path):
        try:
            parsed = getattr(g, "analysis").parse_java_class_bytes(data)
        except RuntimeError:
            continue
        if parsed is None:
            continue
        class_name = str(parsed.get("class_name", ""))
        if not class_name:
            continue
        out[class_name] = _class_semantic(parsed)
    return out


def _class_bytes(path: Path) -> list[bytes]:
    if path.is_dir():
        return [item.read_bytes() for item in sorted(path.rglob("*.class"))]
    if path.is_file() and path.suffix == ".class":
        return [path.read_bytes()]
    if zipfile.is_zipfile(path):
        out: list[bytes] = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if (
                    not info.is_dir()
                    and info.filename.endswith(".class")
                    and not info.filename.startswith("META-INF/versions/")
                ):
                    out.append(zf.read(info))
        return out
    return []


def _class_semantic(parsed: dict[str, Any]) -> _ClassSemantic:
    return _ClassSemantic(
        class_name=str(parsed.get("class_name", "")),
        record_components=[
            f"{item.get('name')}:{item.get('descriptor')}"
            for item in parsed.get("record_components", [])
            if isinstance(item, dict)
        ],
        permitted_subclasses=[
            item
            for item in parsed.get("permitted_subclasses", [])
            if isinstance(item, str)
        ],
        method_parameter_annotation_counts=_method_parameter_annotation_counts(parsed),
        annotation_defaults=_annotation_defaults(parsed),
    )


def _method_parameter_annotation_counts(parsed: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for method in parsed.get("methods", []):
        if not isinstance(method, dict):
            continue
        key = _method_key(method)
        count = 0
        for parameter in method.get("parameter_annotations", []):
            if not isinstance(parameter, dict):
                continue
            annotations = parameter.get("annotations")
            if isinstance(annotations, list):
                count += len(annotations)
        if count:
            out[key] = count
    return out


def _annotation_defaults(parsed: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for method in parsed.get("methods", []):
        if not isinstance(method, dict):
            continue
        if method.get("has_annotation_default") or method.get("annotation_default"):
            out[_method_key(method)] = repr(method.get("annotation_default"))
    return out


def _method_key(method: dict[str, Any]) -> str:
    return f"{method.get('name')}:{method.get('descriptor')}"


def _add_semantic_difference(
    differences: list[JavaSemanticDifference],
    max_differences: int,
    difference: JavaSemanticDifference,
) -> None:
    if max_differences == 0 or len(differences) < max_differences:
        differences.append(difference)


def _metadata_resource_paths(names: set[str]) -> set[str]:
    return {
        name
        for name in names
        if name == "META-INF/MANIFEST.MF" or name.startswith("META-INF/services/")
    }


def _directory_metadata_paths(root: Path) -> set[str]:
    if not root.is_dir():
        return set()
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and (
            path.relative_to(root).as_posix() == "META-INF/MANIFEST.MF"
            or path.relative_to(root).as_posix().startswith("META-INF/services/")
        )
    }


def _metadata_kind(path: str) -> MetadataDifferenceKind:
    if path == "module-info.class":
        return "module_info"
    if path.startswith("META-INF/services/"):
        return "service"
    return "manifest"


def _rebuilt_has_module_info(rebuilt_path: Path | None) -> bool:
    if rebuilt_path is None or not rebuilt_path.exists():
        return False
    if rebuilt_path.is_dir():
        return (rebuilt_path / "module-info.class").is_file()
    if zipfile.is_zipfile(rebuilt_path):
        with zipfile.ZipFile(rebuilt_path) as zf:
            return "module-info.class" in zf.namelist()
    return rebuilt_path.name == "module-info.class"


def _add_metadata_difference(
    differences: list[JavaMetadataDifference],
    max_differences: int,
    difference: JavaMetadataDifference,
) -> None:
    if max_differences == 0 or len(differences) < max_differences:
        differences.append(difference)


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
    metadata_match: bool | None,
    semantic_match: bool | None,
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
    if (
        compile_success is False
        or abi_match is False
        or resource_match is False
        or metadata_match is False
        or semantic_match is False
    ):
        return False
    return True


def _validation_checks(
    *,
    compile_success: bool | None,
    abi_match: bool | None,
    resource_match: bool | None,
    metadata_match: bool | None,
    semantic_match: bool | None,
    stub_sources: list[str],
    allow_generated_stubs: bool,
    stop_reasons: list[str],
) -> list[JavaValidationCheck]:
    checks = [
        _check(
            "compile",
            compile_success,
            "Recovered source compiles.",
            "Recovered source does not compile.",
            "Compilation was not requested.",
        ),
        _check(
            "abi",
            abi_match,
            "Rebuilt classes match the selected ABI surface.",
            "Rebuilt classes differ from the original ABI surface.",
            "ABI comparison was not requested.",
        ),
        _check(
            "resources",
            resource_match,
            "Recovered resources match the original archive resources.",
            "Recovered resources differ from the original archive resources.",
            "Resource comparison was not requested.",
        ),
        _check(
            "metadata",
            metadata_match,
            "Recovered manifest, service provider, and module metadata match.",
            "Recovered manifest, service provider, or module metadata differs.",
            "Metadata comparison was not requested.",
        ),
        _check(
            "semantics",
            semantic_match,
            "Recovered Java-specific semantic attributes match.",
            "Recovered Java-specific semantic attributes differ.",
            "Semantic attribute comparison was not requested.",
        ),
    ]
    if stub_sources and not allow_generated_stubs:
        checks.append(
            JavaValidationCheck(
                name="generated_stubs",
                status="fail",
                message=f"{len(stub_sources)} generated stub source file(s) remain.",
            )
        )
    else:
        checks.append(
            JavaValidationCheck(
                name="generated_stubs",
                status="pass",
                message="No blocking generated stubs remain.",
            )
        )
    if stop_reasons:
        checks.append(
            JavaValidationCheck(
                name="stop_reasons",
                status="fail",
                message="Validation reported: " + ", ".join(stop_reasons),
            )
        )
    return checks


def _check(
    name: str,
    value: bool | None,
    pass_message: str,
    fail_message: str,
    skip_message: str,
) -> JavaValidationCheck:
    if value is None:
        return JavaValidationCheck(name=name, status="skip", message=skip_message)
    return JavaValidationCheck(
        name=name,
        status="pass" if value else "fail",
        message=pass_message if value else fail_message,
    )


def _next_actions(
    *,
    compile_success: bool | None,
    compile_diagnostic_count: int,
    abi_match: bool | None,
    abi_difference_count: int,
    resource_match: bool | None,
    resource_difference_count: int,
    metadata_match: bool | None,
    metadata_difference_count: int,
    semantic_match: bool | None,
    semantic_difference_count: int,
    stub_sources: list[str],
    stop_reasons: list[str],
) -> list[str]:
    actions: list[str] = []
    if compile_success is False:
        actions.append(
            f"Repair compiler diagnostics ({compile_diagnostic_count} reported)."
        )
    if abi_match is False:
        actions.append(f"Repair ABI differences ({abi_difference_count} reported).")
    if resource_match is False:
        actions.append(
            f"Restore or explicitly omit resource differences ({resource_difference_count} reported)."
        )
    if metadata_match is False:
        actions.append(
            f"Restore manifest/service/module metadata differences ({metadata_difference_count} reported)."
        )
    if semantic_match is False:
        actions.append(
            f"Repair Java semantic attribute differences ({semantic_difference_count} reported)."
        )
    if stub_sources:
        actions.append(
            f"Replace generated stubs with decompiled/repaired source ({len(stub_sources)} file(s))."
        )
    for reason in stop_reasons:
        if reason.startswith("max_"):
            actions.append(f"Increase validation budget for {reason}.")
    return _dedupe(actions)


def _quality_summary(
    validation_passed: bool,
    checks: list[JavaValidationCheck],
) -> str:
    if validation_passed:
        return "clean_enough: compile, ABI, resources, and stub policy passed for the selected profile."
    failed = [check.name for check in checks if check.status == "fail"]
    if not failed:
        return "not_clean_enough: validation did not pass, but no failing check was recorded."
    return "not_clean_enough: failing checks: " + ", ".join(failed)


def _compatibility_score(
    *,
    compile_success: bool | None,
    abi_difference_count: int,
    resource_difference_count: int,
    metadata_difference_count: int,
    semantic_difference_count: int,
    stub_source_count: int,
) -> float:
    penalty = 0.0
    if compile_success is False:
        penalty += 0.30
    penalty += min(0.35, abi_difference_count * 0.02)
    penalty += min(0.15, resource_difference_count * 0.01)
    penalty += min(0.10, metadata_difference_count * 0.03)
    penalty += min(0.20, semantic_difference_count * 0.04)
    penalty += min(0.20, stub_source_count * 0.05)
    return max(0.0, round(1.0 - penalty, 4))


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
