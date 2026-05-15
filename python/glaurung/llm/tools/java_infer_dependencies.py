from __future__ import annotations

import hashlib
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


DependencySource = Literal[
    "manifest_class_path",
    "maven_metadata",
    "nested_archive_path",
    "bytecode_external_package",
]
DependencyScope = Literal[
    "archive_identity", "embedded", "external", "provided", "unknown"
]


class JavaInferDependenciesArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    include_manifest: bool = True
    include_maven_metadata: bool = True
    include_nested_archives: bool = True
    include_bytecode_refs: bool = True
    max_classes: int = Field(10_000, ge=0)
    max_dependencies: int = Field(256, ge=0)
    max_external_packages: int = Field(128, ge=0)
    max_sample_owners: int = Field(8, ge=0)


class JavaDependencyFinding(BaseModel):
    dependency_id: str
    source: DependencySource
    scope: DependencyScope
    confidence: float
    group_id: str | None = None
    artifact_id: str | None = None
    version: str | None = None
    package_prefix: str | None = None
    class_path_entry: str | None = None
    archive_entry: str | None = None
    reference_count: int = 0
    sample_owners: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    message: str


class JavaInferDependenciesResult(BaseModel):
    archive_path: str
    sha256: str
    dependency_count: int
    dependencies: list[JavaDependencyFinding]
    manifest_class_path_count: int = 0
    maven_metadata_count: int = 0
    nested_archive_count: int = 0
    external_package_count: int = 0
    parsed_class_count: int = 0
    parse_error_count: int = 0
    summary_by_source: dict[str, int] = Field(default_factory=dict)
    truncated: bool = False
    stop_reasons: list[str] = Field(default_factory=list)


class JavaInferDependenciesTool(
    MemoryTool[JavaInferDependenciesArgs, JavaInferDependenciesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_infer_dependencies",
                description=(
                    "Infer Java classpath dependencies from manifest Class-Path, "
                    "Maven metadata, nested JAR paths, and bytecode references to "
                    "external packages. Does not download dependencies."
                ),
                tags=("java", "jar", "dependencies", "classpath", "kb"),
            ),
            JavaInferDependenciesArgs,
            JavaInferDependenciesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaInferDependenciesArgs,
    ) -> JavaInferDependenciesResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        if not zipfile.is_zipfile(path):
            return JavaInferDependenciesResult(
                archive_path=str(path),
                sha256=digest,
                dependency_count=0,
                dependencies=[],
                stop_reasons=["input_not_zip"],
            )

        dependencies: list[JavaDependencyFinding] = []
        parsed_class_count = 0
        parse_error_count = 0
        truncated = False
        stop_reasons: list[str] = []

        with zipfile.ZipFile(path) as zf:
            if args.include_manifest:
                dependencies.extend(_manifest_class_path_dependencies(zf))
            if args.include_maven_metadata:
                dependencies.extend(_maven_metadata_dependencies(zf))
            if args.include_nested_archives:
                dependencies.extend(_nested_archive_dependencies(zf))
            if args.include_bytecode_refs:
                (
                    bytecode_deps,
                    parsed_class_count,
                    parse_error_count,
                    bytecode_truncated,
                ) = _bytecode_external_dependencies(zf, args)
                dependencies.extend(bytecode_deps)
                truncated = truncated or bytecode_truncated
                if bytecode_truncated:
                    stop_reasons.append("max_classes")

        dependencies = _dedupe_dependencies(dependencies)
        dependencies = sorted(
            dependencies,
            key=lambda dep: (
                dep.source,
                dep.group_id or "",
                dep.artifact_id or "",
                dep.package_prefix or "",
                dep.archive_entry or dep.class_path_entry or "",
            ),
        )
        if len(dependencies) > args.max_dependencies:
            dependencies = dependencies[: args.max_dependencies]
            truncated = True
            stop_reasons.append("max_dependencies")

        for dependency in dependencies:
            _add_dependency_node(kb, path, dependency)

        return JavaInferDependenciesResult(
            archive_path=str(path),
            sha256=digest,
            dependency_count=len(dependencies),
            dependencies=dependencies,
            manifest_class_path_count=sum(
                1 for dep in dependencies if dep.source == "manifest_class_path"
            ),
            maven_metadata_count=sum(
                1 for dep in dependencies if dep.source == "maven_metadata"
            ),
            nested_archive_count=sum(
                1 for dep in dependencies if dep.source == "nested_archive_path"
            ),
            external_package_count=sum(
                1 for dep in dependencies if dep.source == "bytecode_external_package"
            ),
            parsed_class_count=parsed_class_count,
            parse_error_count=parse_error_count,
            summary_by_source=_count_by_source(dependencies),
            truncated=truncated,
            stop_reasons=stop_reasons,
        )


def _manifest_class_path_dependencies(
    zf: zipfile.ZipFile,
) -> list[JavaDependencyFinding]:
    attrs = _manifest_attrs(zf)
    class_path = attrs.get("Class-Path", "")
    out: list[JavaDependencyFinding] = []
    for entry in class_path.split():
        group_id, artifact_id, version = _coordinate_from_filename(Path(entry).name)
        out.append(
            _finding(
                source="manifest_class_path",
                scope="external",
                confidence=0.82,
                group_id=group_id,
                artifact_id=artifact_id,
                version=version,
                class_path_entry=entry,
                evidence=["Manifest Class-Path entry"],
                message=f"Manifest declares classpath entry {entry}.",
            )
        )
    return out


def _maven_metadata_dependencies(zf: zipfile.ZipFile) -> list[JavaDependencyFinding]:
    out: list[JavaDependencyFinding] = []
    for info in zf.infolist():
        normalized = info.filename.replace("\\", "/")
        lowered = normalized.lower()
        if not (
            lowered.startswith("meta-inf/maven/")
            and lowered.endswith("/pom.properties")
        ):
            continue
        try:
            props = _parse_properties(zf.read(info).decode("utf-8", errors="replace"))
        except (KeyError, RuntimeError, zipfile.BadZipFile):
            props = {}
        group_id = props.get("groupId")
        artifact_id = props.get("artifactId")
        version = props.get("version")
        if not artifact_id:
            continue
        out.append(
            _finding(
                source="maven_metadata",
                scope="archive_identity",
                confidence=0.95,
                group_id=group_id,
                artifact_id=artifact_id,
                version=version,
                archive_entry=info.filename,
                evidence=["META-INF/maven pom.properties"],
                message=(
                    "Archive contains Maven artifact metadata for "
                    f"{_coordinate(group_id, artifact_id, version)}."
                ),
            )
        )
    return out


def _nested_archive_dependencies(zf: zipfile.ZipFile) -> list[JavaDependencyFinding]:
    out: list[JavaDependencyFinding] = []
    for info in zf.infolist():
        if info.is_dir() or not _is_nested_archive(info.filename):
            continue
        group_id, artifact_id, version = _coordinate_from_nested_path(info.filename)
        out.append(
            _finding(
                source="nested_archive_path",
                scope="embedded",
                confidence=0.9 if artifact_id and version else 0.72,
                group_id=group_id,
                artifact_id=artifact_id,
                version=version,
                archive_entry=info.filename,
                evidence=[
                    "Nested JAR/ZIP entry",
                    f"uncompressed_size={info.file_size}",
                ],
                message=(
                    f"Archive embeds nested dependency {info.filename}"
                    + (
                        f" ({_coordinate(group_id, artifact_id, version)})."
                        if artifact_id
                        else "."
                    )
                ),
            )
        )
    return out


def _bytecode_external_dependencies(
    zf: zipfile.ZipFile,
    args: JavaInferDependenciesArgs,
) -> tuple[list[JavaDependencyFinding], int, int, bool]:
    java_analysis = getattr(g, "analysis")
    defined_classes = {
        info.filename.removesuffix(".class")
        for info in zf.infolist()
        if not info.is_dir()
        and info.filename.endswith(".class")
        and not info.filename.startswith("META-INF/versions/")
    }
    package_counts: Counter[str] = Counter()
    sample_owners: dict[str, set[str]] = defaultdict(set)
    parsed_class_count = 0
    parse_error_count = 0
    truncated = False
    for info in zf.infolist():
        if info.is_dir() or not info.filename.endswith(".class"):
            continue
        if info.filename.startswith("META-INF/versions/"):
            continue
        if parsed_class_count >= args.max_classes:
            truncated = True
            break
        try:
            parsed = java_analysis.parse_java_class_bytes(zf.read(info))
        except RuntimeError:
            parse_error_count += 1
            continue
        if parsed is None:
            parse_error_count += 1
            continue
        parsed_class_count += 1
        for owner in _method_xref_owners(parsed):
            if owner in defined_classes or _is_jdk_or_platform_owner(owner):
                continue
            prefix = _package_prefix(owner)
            if prefix is None:
                continue
            package_counts[prefix] += 1
            if len(sample_owners[prefix]) < args.max_sample_owners:
                sample_owners[prefix].add(owner)

    out: list[JavaDependencyFinding] = []
    for prefix, count in package_counts.most_common(args.max_external_packages):
        hint = _known_dependency_hint(prefix)
        group_id, artifact_id = hint if hint is not None else (None, None)
        scope: DependencyScope = (
            "provided" if _is_common_provided_prefix(prefix) else "external"
        )
        confidence = 0.72 if hint is not None else 0.55
        if scope == "provided":
            confidence = max(confidence, 0.78)
        out.append(
            _finding(
                source="bytecode_external_package",
                scope=scope,
                confidence=confidence,
                group_id=group_id,
                artifact_id=artifact_id,
                package_prefix=prefix,
                reference_count=count,
                sample_owners=sorted(sample_owners[prefix]),
                evidence=[
                    f"external_method_owner_references={count}",
                    "target classes are not defined in archive",
                ],
                message=(
                    f"Bytecode references external package {prefix} {count} time(s)."
                ),
            )
        )
    return out, parsed_class_count, parse_error_count, truncated


def _method_xref_owners(parsed: dict[str, Any]) -> list[str]:
    owners: list[str] = []
    for method in parsed.get("methods", []):
        if not isinstance(method, dict):
            continue
        code = method.get("code")
        if not isinstance(code, dict):
            continue
        for xref in code.get("xrefs", []):
            if not isinstance(xref, dict):
                continue
            if xref.get("kind") not in {"method", "interface_method", "field", "class"}:
                continue
            owner = xref.get("owner")
            if isinstance(owner, str) and owner:
                normalized = _normalize_owner(owner)
                if normalized is not None:
                    owners.append(normalized)
    return owners


def _normalize_owner(owner: str) -> str | None:
    normalized = owner.strip()
    if not normalized or normalized.startswith("("):
        return None
    while normalized.startswith("["):
        normalized = normalized[1:]
    if normalized in {"B", "C", "D", "F", "I", "J", "S", "Z", "V"}:
        return None
    if normalized.startswith("L") and normalized.endswith(";"):
        normalized = normalized[1:-1]
    if normalized.endswith(";"):
        normalized = normalized[:-1]
    if "/" not in normalized:
        return None
    return normalized


_NESTED_MAVEN_PATH_RE = re.compile(
    r"(?:^|/)META-INF/libraries/(?P<group_path>.+)/(?P<artifact>[^/]+)/"
    r"(?P<version>[^/]+)/(?P<filename>[^/]+\.(?:jar|zip))$",
    re.IGNORECASE,
)
_FILENAME_COORDINATE_RE = re.compile(
    r"^(?P<artifact>[A-Za-z0-9_.+-]+)-(?P<version>[0-9][A-Za-z0-9_.+-]*)"
    r"\.(?:jar|zip)$",
    re.IGNORECASE,
)


def _coordinate_from_nested_path(
    entry_name: str,
) -> tuple[str | None, str | None, str | None]:
    normalized = entry_name.replace("\\", "/")
    match = _NESTED_MAVEN_PATH_RE.search(normalized)
    if match is not None:
        return (
            match.group("group_path").replace("/", "."),
            match.group("artifact"),
            match.group("version"),
        )
    return _coordinate_from_filename(Path(normalized).name)


def _coordinate_from_filename(
    filename: str,
) -> tuple[str | None, str | None, str | None]:
    match = _FILENAME_COORDINATE_RE.match(filename)
    if match is None:
        return None, filename.removesuffix(".jar").removesuffix(".zip") or None, None
    return None, match.group("artifact"), match.group("version")


def _is_nested_archive(name: str) -> bool:
    lowered = name.lower()
    return lowered.endswith((".jar", ".zip"))


def _manifest_attrs(zf: zipfile.ZipFile) -> dict[str, str]:
    try:
        raw = zf.read("META-INF/MANIFEST.MF")
    except KeyError:
        return {}
    return _parse_manifest(raw.decode("utf-8", errors="replace"))


def _parse_manifest(text: str) -> dict[str, str]:
    lines: list[str] = []
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw_line.startswith(" ") and lines:
            lines[-1] += raw_line[1:]
        elif raw_line:
            lines.append(raw_line)
    attrs: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep:
            attrs[key] = value.strip()
    return attrs


def _parse_properties(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


def _is_jdk_or_platform_owner(owner: str) -> bool:
    return owner.startswith(
        (
            "java/",
            "javax/",
            "jdk/",
            "sun/",
            "com/sun/",
            "org/w3c/",
            "org/xml/",
        )
    )


def _package_prefix(owner: str) -> str | None:
    parts = owner.split("/")
    if not parts:
        return None
    if len(parts) > 1 and _looks_like_class_segment(parts[-1]):
        parts = parts[:-1]
    if not parts:
        return None
    dotted = ".".join(parts)
    explicit_prefixes = (
        "ca.weblite.objc",
        "com.google.common",
        "com.google.gson",
        "com.mojang",
        "com.ibm.icu",
        "com.electronwill.nightconfig",
        "com.fasterxml.jackson",
        "com.jcraft.jogg",
        "com.jcraft.jorbis",
        "com.llamalad7.mixinextras",
        "com.microsoft.aad",
        "cpw.mods",
        "io.netty",
        "it.unimi.dsi",
        "joptsimple",
        "kotlin",
        "net.fabricmc",
        "net.minecraft",
        "net.minecraftforge",
        "net.neoforged",
        "net.jpountz.lz4",
        "org.apache.commons",
        "org.apache.http",
        "org.apache.logging",
        "org.jetbrains",
        "org.joml",
        "org.lwjgl",
        "org.objectweb.asm",
        "org.slf4j",
        "org.spongepowered",
        "oshi",
    )
    for prefix in explicit_prefixes:
        if dotted == prefix or dotted.startswith(prefix + "."):
            return prefix
    if len(parts) >= 3:
        return ".".join(parts[:3])
    if len(parts) == 1:
        return parts[0]
    return ".".join(parts[:2])


def _looks_like_class_segment(segment: str) -> bool:
    base = segment.split("$", 1)[0]
    return segment in {"module-info", "package-info"} or (
        bool(base) and (base[0].isupper() or base[0].isdigit())
    )


_KNOWN_DEPENDENCY_HINTS: dict[str, tuple[str, str]] = {
    "com.fasterxml.jackson": ("com.fasterxml.jackson.core", "jackson"),
    "ca.weblite.objc": ("ca.weblite", "java-objc-bridge"),
    "com.ibm.icu": ("com.ibm.icu", "icu4j"),
    "com.electronwill.nightconfig": ("com.electronwill.night-config", "core"),
    "com.google.common": ("com.google.guava", "guava"),
    "com.google.gson": ("com.google.code.gson", "gson"),
    "com.jcraft.jogg": ("com.jcraft", "jogg"),
    "com.jcraft.jorbis": ("com.jcraft", "jorbis"),
    "com.llamalad7.mixinextras": ("io.github.llamalad7", "mixinextras-common"),
    "com.microsoft.aad": ("com.microsoft.azure", "msal4j"),
    "com.mojang": ("com.mojang", "minecraft-provided"),
    "cpw.mods": ("cpw.mods", "modlauncher"),
    "io.netty": ("io.netty", "netty"),
    "it.unimi.dsi": ("it.unimi.dsi", "fastutil"),
    "joptsimple": ("net.sf.jopt-simple", "jopt-simple"),
    "kotlin": ("org.jetbrains.kotlin", "kotlin-stdlib"),
    "net.fabricmc": ("net.fabricmc", "fabric-loader"),
    "net.minecraft": ("net.minecraft", "minecraft"),
    "net.minecraftforge": ("net.minecraftforge", "forge"),
    "net.neoforged": ("net.neoforged", "neoforge"),
    "net.jpountz.lz4": ("net.jpountz.lz4", "lz4"),
    "org.apache.commons": ("org.apache.commons", "commons"),
    "org.apache.http": ("org.apache.httpcomponents", "httpclient"),
    "org.apache.log4j": ("log4j", "log4j"),
    "org.apache.logging": ("org.apache.logging.log4j", "log4j"),
    "org.jetbrains": ("org.jetbrains", "annotations"),
    "org.joml": ("org.joml", "joml"),
    "org.lwjgl": ("org.lwjgl", "lwjgl"),
    "org.objectweb.asm": ("org.ow2.asm", "asm"),
    "org.slf4j": ("org.slf4j", "slf4j-api"),
    "org.spongepowered": ("org.spongepowered", "mixin"),
    "oshi": ("com.github.oshi", "oshi-core"),
}


def _known_dependency_hint(prefix: str) -> tuple[str, str] | None:
    return _KNOWN_DEPENDENCY_HINTS.get(prefix)


def _is_common_provided_prefix(prefix: str) -> bool:
    return prefix.startswith(
        (
            "com.mojang",
            "net.minecraft",
            "net.minecraftforge",
            "net.neoforged",
            "net.fabricmc",
            "org.spongepowered",
        )
    )


def _dedupe_dependencies(
    dependencies: list[JavaDependencyFinding],
) -> list[JavaDependencyFinding]:
    merged: dict[tuple[Any, ...], JavaDependencyFinding] = {}
    for dep in dependencies:
        key = (
            dep.source,
            dep.group_id,
            dep.artifact_id,
            dep.version,
            dep.package_prefix,
            dep.class_path_entry,
            dep.archive_entry,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = dep
            continue
        existing.reference_count += dep.reference_count
        existing.confidence = max(existing.confidence, dep.confidence)
        existing.evidence = sorted(set(existing.evidence + dep.evidence))
        existing.sample_owners = sorted(set(existing.sample_owners + dep.sample_owners))
    return list(merged.values())


def _finding(
    *,
    source: DependencySource,
    scope: DependencyScope,
    confidence: float,
    message: str,
    group_id: str | None = None,
    artifact_id: str | None = None,
    version: str | None = None,
    package_prefix: str | None = None,
    class_path_entry: str | None = None,
    archive_entry: str | None = None,
    reference_count: int = 0,
    sample_owners: list[str] | None = None,
    evidence: list[str] | None = None,
) -> JavaDependencyFinding:
    key = "|".join(
        [
            source,
            scope,
            group_id or "",
            artifact_id or "",
            version or "",
            package_prefix or "",
            class_path_entry or "",
            archive_entry or "",
        ]
    )
    return JavaDependencyFinding(
        dependency_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        source=source,
        scope=scope,
        confidence=confidence,
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
        package_prefix=package_prefix,
        class_path_entry=class_path_entry,
        archive_entry=archive_entry,
        reference_count=reference_count,
        sample_owners=sample_owners or [],
        evidence=evidence or [],
        message=message,
    )


def _coordinate(
    group_id: str | None,
    artifact_id: str | None,
    version: str | None,
) -> str:
    return ":".join(part for part in (group_id, artifact_id, version) if part)


def _add_dependency_node(
    kb: KnowledgeBase,
    archive_path: Path,
    dependency: JavaDependencyFinding,
) -> None:
    label = dependency.package_prefix or _coordinate(
        dependency.group_id, dependency.artifact_id, dependency.version
    )
    if not label:
        label = dependency.archive_entry or dependency.class_path_entry or "dependency"
    kb.add_node(
        Node(
            kind=NodeKind.java_dependency,
            label=label,
            text=dependency.message,
            props={
                "tool": "java_infer_dependencies",
                "archive_path": str(archive_path),
                **dependency.model_dump(),
            },
            tags=["java", "dependency", dependency.source, dependency.scope],
        )
    )


def _count_by_source(dependencies: list[JavaDependencyFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dependency in dependencies:
        counts[dependency.source] = counts.get(dependency.source, 0) + 1
    return counts


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
    except FileNotFoundError:
        return ""
    return h.hexdigest()


def build_tool() -> MemoryTool[JavaInferDependenciesArgs, JavaInferDependenciesResult]:
    return JavaInferDependenciesTool()
