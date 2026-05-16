from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field

from glaurung.java import JavaHelperError, run_jvm_tool

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


ResourcePolicy = Literal["copy_all", "copy_runtime", "none"]
JavaDecompilerEngine = Literal["auto", "cfr", "vineflower"]


class JavaReconstructSourceTreeArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    output_root: str | None = Field(
        None,
        description=(
            "Destination project root. Required for writes; omitted calls return a "
            "structured stop reason instead of choosing a surprising path."
        ),
    )
    resource_policy: ResourcePolicy = "copy_runtime"
    decompile_sources: bool = False
    decompiler_engine: JavaDecompilerEngine = "auto"
    helper_jar: str | None = Field(
        None,
        description="Optional path to the glaurung-jvm-tools fat JAR",
    )
    emit_stub_sources: bool = False
    overwrite: bool = True
    max_classes: int = Field(20_000, ge=0)
    max_decompile_classes: int = Field(256, ge=0)
    decompile_timeout_seconds: int = Field(60, ge=1, le=600)
    max_decompile_source_chars: int = Field(200_000, ge=0)
    max_resources: int = Field(20_000, ge=0)
    max_resource_bytes: int = Field(10_000_000, ge=0)


class JavaReconstructSourceTreeResult(BaseModel):
    archive_path: str
    sha256: str
    source_project_root: str | None = None
    wrote_files: bool = False
    class_count: int = 0
    resource_count: int = 0
    java_source_files: list[str] = Field(default_factory=list)
    decompiled_source_files: list[str] = Field(default_factory=list)
    resource_files: list[str] = Field(default_factory=list)
    preserved_metadata_files: list[str] = Field(default_factory=list)
    skipped_signature_files: list[str] = Field(default_factory=list)
    skipped_resource_files: list[str] = Field(default_factory=list)
    skipped_unsafe_paths: list[str] = Field(default_factory=list)
    classes_requiring_decompile: list[str] = Field(default_factory=list)
    classes_requiring_stubs: list[str] = Field(default_factory=list)
    failed_decompile_classes: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    truncated: bool = False


class JavaReconstructSourceTreeTool(
    MemoryTool[JavaReconstructSourceTreeArgs, JavaReconstructSourceTreeResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_reconstruct_source_tree",
                description=(
                    "Create an initial recovered Java source-project scaffold from "
                    "a JAR by preserving runtime resources and metadata while "
                    "optionally decompiling top-level classes through the JVM "
                    "helper and tracking classes that still require repair or "
                    "explicit stubs."
                ),
                tags=("java", "jar", "source-recovery", "resources", "kb"),
            ),
            JavaReconstructSourceTreeArgs,
            JavaReconstructSourceTreeResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaReconstructSourceTreeArgs,
    ) -> JavaReconstructSourceTreeResult:
        archive_path = Path(args.path or ctx.file_path)
        digest = _sha256(archive_path)
        if not zipfile.is_zipfile(archive_path):
            return JavaReconstructSourceTreeResult(
                archive_path=str(archive_path),
                sha256=digest,
                stop_reasons=["input_not_zip"],
            )
        if not args.output_root:
            return JavaReconstructSourceTreeResult(
                archive_path=str(archive_path),
                sha256=digest,
                stop_reasons=["output_root_missing"],
            )

        output_root = Path(args.output_root)
        java_root = output_root / "src" / "main" / "java"
        resource_root = output_root / "src" / "main" / "resources"
        java_root.mkdir(parents=True, exist_ok=True)
        resource_root.mkdir(parents=True, exist_ok=True)

        result = JavaReconstructSourceTreeResult(
            archive_path=str(archive_path),
            sha256=digest,
            source_project_root=str(output_root),
            wrote_files=True,
        )
        with zipfile.ZipFile(archive_path) as zf:
            _copy_or_plan_entries(
                zf,
                archive_path,
                args,
                result,
                java_root,
                resource_root,
            )
        if result.java_source_files:
            (output_root / "sources.txt").write_text(
                "\n".join(result.java_source_files) + "\n",
                encoding="utf-8",
            )
        _add_source_tree_node(kb, archive_path, result)
        return result


def _copy_or_plan_entries(
    zf: zipfile.ZipFile,
    archive_path: Path,
    args: JavaReconstructSourceTreeArgs,
    result: JavaReconstructSourceTreeResult,
    java_root: Path,
    resource_root: Path,
) -> None:
    class_seen = 0
    decompile_seen = 0
    resource_seen = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        normalized = _safe_archive_path(info.filename)
        if normalized is None:
            result.skipped_unsafe_paths.append(info.filename)
            continue
        if normalized.endswith(".class"):
            if class_seen >= args.max_classes:
                result.truncated = True
                _append_once(result.stop_reasons, "max_classes")
                continue
            class_seen += 1
            result.class_count += 1
            if (
                args.decompile_sources
                and _is_decompilable_top_level_class(normalized)
                and decompile_seen < args.max_decompile_classes
            ):
                decompile_seen += 1
                source_path = _decompile_class_to_source(
                    archive_path=archive_path,
                    class_entry=normalized,
                    java_root=java_root,
                    args=args,
                    result=result,
                )
                if source_path is not None:
                    rel = _relative_to_project(
                        source_path, java_root.parent.parent.parent
                    )
                    result.java_source_files.append(rel)
                    result.decompiled_source_files.append(rel)
                    continue
            elif args.decompile_sources and _is_decompilable_top_level_class(
                normalized
            ):
                result.truncated = True
                _append_once(result.stop_reasons, "max_decompile_classes")

            result.classes_requiring_decompile.append(normalized)
            if args.emit_stub_sources:
                stub_path = _emit_stub_source(normalized, java_root, args.overwrite)
                if stub_path is not None:
                    rel = _relative_to_project(
                        stub_path, java_root.parent.parent.parent
                    )
                    result.java_source_files.append(rel)
                    result.classes_requiring_stubs.append(normalized)
                else:
                    result.failed_decompile_classes.append(normalized)
            continue
        if _is_signature_file(normalized):
            result.skipped_signature_files.append(normalized)
            continue
        if args.resource_policy == "none":
            continue
        if resource_seen >= args.max_resources:
            result.truncated = True
            _append_once(result.stop_reasons, "max_resources")
            continue
        if info.file_size > args.max_resource_bytes:
            result.skipped_resource_files.append(normalized)
            continue
        if args.resource_policy == "copy_runtime" and _is_nested_archive(normalized):
            result.skipped_resource_files.append(normalized)
            continue
        resource_seen += 1
        result.resource_count += 1
        dest = resource_root / normalized
        if args.overwrite or not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(zf.read(info))
        rel_resource = _relative_to_project(dest, resource_root.parent.parent.parent)
        result.resource_files.append(rel_resource)
        if _is_metadata_resource(normalized):
            result.preserved_metadata_files.append(normalized)


def _emit_stub_source(
    class_entry: str,
    java_root: Path,
    overwrite: bool,
) -> Path | None:
    if class_entry.startswith("META-INF/versions/"):
        return None
    class_name = class_entry.removesuffix(".class")
    if class_name in {"module-info", "package-info"} or "$" in class_name:
        return None
    parts = class_name.split("/")
    if not all(_is_java_identifier(part) for part in parts):
        return None
    package_parts = parts[:-1]
    simple_name = parts[-1]
    dest = java_root.joinpath(*package_parts, f"{simple_name}.java")
    if dest.exists() and not overwrite:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    package_line = f"package {'.'.join(package_parts)};\n\n" if package_parts else ""
    dest.write_text(
        (
            package_line
            + "/* GLAURUNG GENERATED STUB: original bytecode still requires "
            "decompilation and semantic repair. */\n"
            + f"public final class {simple_name} {{\n"
            + f"    private {simple_name}() {{\n"
            + '        throw new UnsupportedOperationException("generated stub");\n'
            + "    }\n"
            + "}\n"
        ),
        encoding="utf-8",
    )
    return dest


def _decompile_class_to_source(
    *,
    archive_path: Path,
    class_entry: str,
    java_root: Path,
    args: JavaReconstructSourceTreeArgs,
    result: JavaReconstructSourceTreeResult,
) -> Path | None:
    class_name = class_entry.removesuffix(".class")
    dest = java_root.joinpath(*class_name.split("/")).with_suffix(".java")
    if dest.exists() and not args.overwrite:
        return dest
    try:
        raw = run_jvm_tool(
            [
                "decompile",
                "--jar",
                str(archive_path),
                "--class",
                class_name,
                "--engine",
                args.decompiler_engine,
                "--max-source-chars",
                str(args.max_decompile_source_chars),
            ],
            helper_jar=args.helper_jar,
            timeout_seconds=args.decompile_timeout_seconds,
        )
    except JavaHelperError as exc:
        result.failed_decompile_classes.append(class_entry)
        result.warnings.append(f"{class_entry}: {exc}")
        _append_once(result.stop_reasons, "helper_unavailable")
        return None

    source = raw.get("source")
    if not raw.get("success") or not isinstance(source, str) or not source.strip():
        result.failed_decompile_classes.append(class_entry)
        stop_reasons = raw.get("stop_reasons")
        if isinstance(stop_reasons, list):
            for stop_reason in stop_reasons:
                if isinstance(stop_reason, str):
                    _append_once(result.stop_reasons, stop_reason)
        diagnostic = _first_string(raw.get("diagnostics"))
        if diagnostic is not None:
            result.warnings.append(f"{class_entry}: {diagnostic}")
        return None

    ast = raw.get("ast")
    if isinstance(ast, dict) and ast.get("parse_success") is False:
        result.warnings.append(
            f"{class_entry}: decompiled source did not parse cleanly"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(source.rstrip() + "\n", encoding="utf-8")
    if raw.get("source_truncated"):
        result.warnings.append(f"{class_entry}: decompiled source was truncated")
        _append_once(result.stop_reasons, "decompile_source_truncated")
    return dest


def _is_decompilable_top_level_class(class_entry: str) -> bool:
    if class_entry.startswith("META-INF/versions/"):
        return False
    class_name = class_entry.removesuffix(".class")
    if class_name in {"module-info", "package-info"} or "$" in class_name:
        return False
    return all(_is_java_identifier(part) for part in class_name.split("/"))


def _first_string(value: object) -> str | None:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                return item
    if isinstance(value, str):
        return value
    return None


def _safe_archive_path(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _is_signature_file(name: str) -> bool:
    path = PurePosixPath(name)
    if len(path.parts) != 2 or path.parts[0].upper() != "META-INF":
        return False
    upper = path.name.upper()
    return upper.endswith((".SF", ".RSA", ".DSA", ".EC"))


def _is_nested_archive(name: str) -> bool:
    return name.lower().endswith((".jar", ".zip"))


def _is_metadata_resource(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered == "meta-inf/manifest.mf"
        or lowered.startswith("meta-inf/services/")
        or lowered.startswith("meta-inf/maven/")
        or lowered.endswith(
            (
                "mods.toml",
                "fabric.mod.json",
                "quilt.mod.json",
                "plugin.yml",
                "paper-plugin.yml",
            )
        )
        or "license" in lowered
        or "notice" in lowered
    )


_JAVA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def _is_java_identifier(value: str) -> bool:
    return _JAVA_IDENTIFIER_RE.match(value) is not None


def _relative_to_project(path: Path, project_root: Path) -> str:
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return str(path)


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _add_source_tree_node(
    kb: KnowledgeBase,
    archive_path: Path,
    result: JavaReconstructSourceTreeResult,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_source_tree,
            label=result.source_project_root or "source-tree",
            text=(
                f"Recovered scaffold with {len(result.java_source_files)} source "
                f"file(s), {len(result.resource_files)} resource file(s), and "
                f"{len(result.classes_requiring_decompile)} class(es) requiring "
                "decompilation."
            ),
            props={
                "tool": "java_reconstruct_source_tree",
                "archive_path": str(archive_path),
                **result.model_dump(),
            },
            tags=["java", "source-recovery"],
        )
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    except FileNotFoundError:
        return ""
    return h.hexdigest()


def build_tool() -> MemoryTool[
    JavaReconstructSourceTreeArgs, JavaReconstructSourceTreeResult
]:
    return JavaReconstructSourceTreeTool()
