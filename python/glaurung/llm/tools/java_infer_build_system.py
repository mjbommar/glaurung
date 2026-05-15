from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_infer_dependencies import (
    JavaDependencyFinding,
    JavaInferDependenciesResult,
    build_tool as build_java_infer_dependencies,
)


PreferredJavaBuildTool = Literal["auto", "javac", "maven", "gradle"]
SelectedJavaBuildTool = Literal["unknown", "javac", "maven", "gradle"]
BuildFileSource = Literal["generated", "recovered", "existing"]


class JavaInferBuildSystemArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    source_project_root: str | None = Field(
        None,
        description=(
            "Optional recovered source root. Existing pom.xml/build.gradle files "
            "there are treated as stronger evidence than archive heuristics."
        ),
    )
    preferred_build_tool: PreferredJavaBuildTool = "auto"
    project_name: str | None = None
    include_dependencies: bool = True
    supplied_classpath: list[str] = Field(default_factory=list)
    max_dependencies: int = Field(128, ge=0)
    max_classpath_entries: int = Field(128, ge=0)


class JavaBuildFile(BaseModel):
    path: str
    content: str
    source: BuildFileSource = "generated"
    message: str


class JavaBuildDependency(BaseModel):
    group_id: str | None = None
    artifact_id: str | None = None
    version: str | None = None
    package_prefix: str | None = None
    scope: str = "unknown"
    source: str = "unknown"
    reference_count: int = 0
    confidence: float = 0.0


class JavaInferBuildSystemResult(BaseModel):
    archive_path: str
    sha256: str
    selected_build_tool: SelectedJavaBuildTool
    confidence: float
    rationale: str
    project_name: str | None = None
    group_id: str | None = None
    version: str | None = None
    java_release: int | None = None
    class_file_major_min: int | None = None
    class_file_major_max: int | None = None
    manifest_main_class: str | None = None
    module_name: str | None = None
    dependency_count: int = 0
    dependencies: list[JavaBuildDependency] = Field(default_factory=list)
    classpath_entries: list[str] = Field(default_factory=list)
    local_library_entries: list[str] = Field(default_factory=list)
    build_files: list[JavaBuildFile] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)


class _ArchiveBuildEvidence(BaseModel):
    manifest: dict[str, str] = Field(default_factory=dict)
    maven_group_id: str | None = None
    maven_artifact_id: str | None = None
    maven_version: str | None = None
    embedded_pom: str | None = None
    embedded_pom_path: str | None = None
    has_gradle_plugin_metadata: bool = False
    has_minecraft_mod_metadata: bool = False
    has_module_info: bool = False
    class_file_major_min: int | None = None
    class_file_major_max: int | None = None


class JavaInferBuildSystemTool(
    MemoryTool[JavaInferBuildSystemArgs, JavaInferBuildSystemResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_infer_build_system",
                description=(
                    "Infer an initial Java source-recovery build plan from JAR "
                    "metadata, classfile versions, dependency evidence, and "
                    "optional recovered source-root build files. Does not fetch "
                    "dependencies or execute archive code."
                ),
                tags=("java", "jar", "build", "source-recovery", "kb"),
            ),
            JavaInferBuildSystemArgs,
            JavaInferBuildSystemResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaInferBuildSystemArgs,
    ) -> JavaInferBuildSystemResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        if not zipfile.is_zipfile(path):
            return JavaInferBuildSystemResult(
                archive_path=str(path),
                sha256=digest,
                selected_build_tool="unknown",
                confidence=0.0,
                rationale="Input is not a ZIP/JAR archive.",
                stop_reasons=["input_not_zip"],
            )

        with zipfile.ZipFile(path) as zf:
            evidence = _archive_build_evidence(zf)

        dependency_result = _infer_dependencies(ctx, kb, path, args)
        dependencies = _build_dependencies(dependency_result, args.max_dependencies)
        classpath_entries = _classpath_entries(
            dependency_result,
            args.supplied_classpath,
            args.max_classpath_entries,
        )
        local_library_entries = [
            entry
            for entry in classpath_entries
            if entry.startswith("libs/") or entry.startswith("lib/")
        ]
        selected, confidence, rationale, warnings = _select_build_tool(
            evidence=evidence,
            source_project_root=Path(args.source_project_root)
            if args.source_project_root
            else None,
            preferred=args.preferred_build_tool,
            dependency_count=len(dependencies),
        )
        project_name = _project_name(args, path, evidence)
        java_release = _java_release_from_major(evidence.class_file_major_max)
        warnings.extend(_release_warnings(java_release, evidence.class_file_major_max))
        build_files = _build_files(
            selected=selected,
            project_name=project_name,
            group_id=evidence.maven_group_id,
            version=evidence.maven_version,
            java_release=java_release,
            dependencies=dependencies,
            classpath_entries=classpath_entries,
            evidence=evidence,
            source_project_root=Path(args.source_project_root)
            if args.source_project_root
            else None,
        )

        result = JavaInferBuildSystemResult(
            archive_path=str(path),
            sha256=digest,
            selected_build_tool=selected,
            confidence=confidence,
            rationale=rationale,
            project_name=project_name,
            group_id=evidence.maven_group_id,
            version=evidence.maven_version,
            java_release=java_release,
            class_file_major_min=evidence.class_file_major_min,
            class_file_major_max=evidence.class_file_major_max,
            manifest_main_class=evidence.manifest.get("Main-Class"),
            module_name=_module_name(evidence),
            dependency_count=len(dependencies),
            dependencies=dependencies,
            classpath_entries=classpath_entries,
            local_library_entries=local_library_entries,
            build_files=build_files,
            warnings=_dedupe(warnings),
            stop_reasons=[],
        )
        _add_build_system_node(kb, path, result)
        return result


def _infer_dependencies(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    path: Path,
    args: JavaInferBuildSystemArgs,
) -> JavaInferDependenciesResult | None:
    if not args.include_dependencies:
        return None
    tool = build_java_infer_dependencies()
    return tool.run(
        ctx,
        kb,
        tool.input_model(
            path=str(path),
            max_dependencies=args.max_dependencies,
            max_external_packages=args.max_dependencies,
        ),
    )


def _archive_build_evidence(zf: zipfile.ZipFile) -> _ArchiveBuildEvidence:
    evidence = _ArchiveBuildEvidence()
    evidence.manifest = _manifest_attrs(zf)
    evidence.maven_group_id, evidence.maven_artifact_id, evidence.maven_version = (
        _maven_identity(zf)
    )
    evidence.embedded_pom_path, evidence.embedded_pom = _embedded_pom(zf)
    names = {info.filename for info in zf.infolist() if not info.is_dir()}
    lowered = {name.lower() for name in names}
    evidence.has_gradle_plugin_metadata = any(
        name.startswith("meta-inf/gradle-plugins/") and name.endswith(".properties")
        for name in lowered
    )
    evidence.has_minecraft_mod_metadata = bool(
        {
            "meta-inf/mods.toml",
            "meta-inf/neoforge.mods.toml",
            "fabric.mod.json",
            "quilt.mod.json",
            "plugin.yml",
            "paper-plugin.yml",
        }
        & lowered
    )
    evidence.has_module_info = "module-info.class" in names
    majors = _class_file_majors(zf)
    if majors:
        evidence.class_file_major_min = min(majors)
        evidence.class_file_major_max = max(majors)
    return evidence


def _select_build_tool(
    *,
    evidence: _ArchiveBuildEvidence,
    source_project_root: Path | None,
    preferred: PreferredJavaBuildTool,
    dependency_count: int,
) -> tuple[SelectedJavaBuildTool, float, str, list[str]]:
    warnings: list[str] = []
    if preferred != "auto":
        return (
            preferred,
            0.9,
            f"Preferred build tool was explicitly set to {preferred}.",
            warnings,
        )
    existing = _existing_build_tool(source_project_root)
    if existing is not None:
        return (
            existing,
            0.97,
            f"Recovered source root already contains a {existing} build file.",
            warnings,
        )
    if evidence.has_minecraft_mod_metadata:
        warnings.append(
            "Minecraft mod metadata usually needs loader-specific Gradle plugins; "
            "the generated Gradle file is a recovery starting point, not a full "
            "ForgeGradle/Fabric Loom project."
        )
        return (
            "gradle",
            0.78,
            "Minecraft mod metadata suggests a Gradle-based source project.",
            warnings,
        )
    if evidence.has_gradle_plugin_metadata:
        return (
            "gradle",
            0.82,
            "Gradle plugin metadata was found in META-INF/gradle-plugins.",
            warnings,
        )
    if evidence.embedded_pom is not None or evidence.maven_artifact_id is not None:
        return (
            "maven",
            0.86,
            "Embedded Maven metadata can seed a recovered Maven project.",
            warnings,
        )
    if dependency_count:
        warnings.append(
            "No embedded Maven or Gradle metadata was found; dependency evidence "
            "will be exposed as a local javac classpath plan."
        )
    else:
        warnings.append(
            "No embedded Maven or Gradle metadata was found; using a minimal javac "
            "argfile plan."
        )
    return "javac", 0.68, "Plain JAR metadata is best represented by javac.", warnings


def _build_files(
    *,
    selected: SelectedJavaBuildTool,
    project_name: str,
    group_id: str | None,
    version: str | None,
    java_release: int | None,
    dependencies: list[JavaBuildDependency],
    classpath_entries: list[str],
    evidence: _ArchiveBuildEvidence,
    source_project_root: Path | None,
) -> list[JavaBuildFile]:
    existing = _read_existing_build_file(source_project_root, selected)
    if existing is not None:
        path, content = existing
        return [
            JavaBuildFile(
                path=path,
                content=content,
                source="existing",
                message=f"Existing {selected} build file from recovered source root.",
            )
        ]
    if selected == "maven":
        content = _generate_pom(
            project_name=project_name,
            group_id=group_id,
            version=version,
            java_release=java_release,
            dependencies=dependencies,
            embedded_pom=evidence.embedded_pom,
        )
        source: BuildFileSource = "recovered" if evidence.embedded_pom else "generated"
        message = (
            f"Generated Maven build file seeded by {evidence.embedded_pom_path}."
            if evidence.embedded_pom
            else "Generated Maven build file from inferred metadata."
        )
        return [
            JavaBuildFile(
                path="pom.xml", content=content, source=source, message=message
            )
        ]
    if selected == "gradle":
        return [
            JavaBuildFile(
                path="build.gradle",
                content=_generate_gradle(
                    project_name=project_name,
                    java_release=java_release,
                    dependencies=dependencies,
                ),
                source="generated",
                message="Generated Gradle build file from inferred metadata.",
            )
        ]
    if selected == "javac":
        return [
            JavaBuildFile(
                path="javac.args",
                content=_generate_javac_args(java_release, classpath_entries),
                source="generated",
                message="Generated javac argfile for recovered sources.",
            ),
            JavaBuildFile(
                path="sources.txt",
                content="# Populated by java_reconstruct_source_tree.\n",
                source="generated",
                message="Placeholder source list for javac argfile.",
            ),
        ]
    return []


def _build_dependencies(
    dependency_result: JavaInferDependenciesResult | None,
    max_dependencies: int,
) -> list[JavaBuildDependency]:
    if dependency_result is None:
        return []
    out: list[JavaBuildDependency] = []
    for dep in dependency_result.dependencies[:max_dependencies]:
        out.append(_build_dependency(dep))
    return out


def _build_dependency(dep: JavaDependencyFinding) -> JavaBuildDependency:
    return JavaBuildDependency(
        group_id=dep.group_id,
        artifact_id=dep.artifact_id,
        version=dep.version,
        package_prefix=dep.package_prefix,
        scope=dep.scope,
        source=dep.source,
        reference_count=dep.reference_count,
        confidence=dep.confidence,
    )


def _classpath_entries(
    dependency_result: JavaInferDependenciesResult | None,
    supplied_classpath: list[str],
    max_classpath_entries: int,
) -> list[str]:
    entries: list[str] = []
    entries.extend(supplied_classpath)
    if dependency_result is not None:
        for dep in dependency_result.dependencies:
            if dep.class_path_entry:
                entries.append(dep.class_path_entry)
            elif dep.archive_entry and dep.source == "nested_archive_path":
                entries.append(f"libs/{Path(dep.archive_entry).name}")
    return _dedupe(entries)[:max_classpath_entries]


def _generate_pom(
    *,
    project_name: str,
    group_id: str | None,
    version: str | None,
    java_release: int | None,
    dependencies: list[JavaBuildDependency],
    embedded_pom: str | None,
) -> str:
    group = _xml_text(group_id or "recovered")
    artifact = _xml_text(project_name)
    ver = _xml_text(version or "0.1.0")
    release = str(java_release or 17)
    deps = [
        dep
        for dep in dependencies
        if dep.group_id
        and dep.artifact_id
        and dep.version
        and dep.scope != "archive_identity"
    ]
    dependency_xml = "\n".join(_maven_dependency_xml(dep) for dep in deps)
    embedded_note = ""
    if embedded_pom:
        embedded_note = (
            "\n  <!-- Embedded Maven metadata was present in the archive; this "
            "file is regenerated for source recovery. -->"
        )
    dependencies_block = (
        f"\n  <dependencies>\n{dependency_xml}\n  </dependencies>"
        if dependency_xml
        else ""
    )
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"\n'
        '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
        '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 '
        'https://maven.apache.org/xsd/maven-4.0.0.xsd">\n'
        "  <modelVersion>4.0.0</modelVersion>"
        f"{embedded_note}\n"
        f"  <groupId>{group}</groupId>\n"
        f"  <artifactId>{artifact}</artifactId>\n"
        f"  <version>{ver}</version>\n"
        "  <properties>\n"
        f"    <maven.compiler.release>{release}</maven.compiler.release>\n"
        "    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\n"
        "  </properties>"
        f"{dependencies_block}\n"
        "</project>\n"
    )


def _maven_dependency_xml(dep: JavaBuildDependency) -> str:
    scope = "provided" if dep.scope == "provided" else "compile"
    return (
        "    <dependency>\n"
        f"      <groupId>{_xml_text(dep.group_id or '')}</groupId>\n"
        f"      <artifactId>{_xml_text(dep.artifact_id or '')}</artifactId>\n"
        f"      <version>{_xml_text(dep.version or '')}</version>\n"
        f"      <scope>{scope}</scope>\n"
        "    </dependency>"
    )


def _generate_gradle(
    *,
    project_name: str,
    java_release: int | None,
    dependencies: list[JavaBuildDependency],
) -> str:
    release = java_release or 17
    lines = [
        "plugins {",
        "    id 'java'",
        "}",
        "",
        f"group = 'recovered.{_gradle_identifier(project_name)}'",
        "version = '0.1.0'",
        "",
        "java {",
        f"    toolchain.languageVersion = JavaLanguageVersion.of({release})",
        "}",
        "",
        "repositories {",
        "    mavenCentral()",
        "}",
        "",
        "dependencies {",
    ]
    for dep in dependencies:
        if not dep.group_id or not dep.artifact_id or not dep.version:
            continue
        conf = "compileOnly" if dep.scope == "provided" else "implementation"
        coord = f"{dep.group_id}:{dep.artifact_id}:{dep.version}"
        lines.append(f"    {conf} '{coord}'")
    lines.extend(["}", ""])
    return "\n".join(lines)


def _generate_javac_args(
    java_release: int | None,
    classpath_entries: list[str],
) -> str:
    lines = [
        "# javac argfile for recovered Java source",
        "--release",
        str(java_release or 17),
        "-d",
        "build/classes",
    ]
    if classpath_entries:
        lines.extend(["-classpath", ":".join(classpath_entries)])
    lines.append("@sources.txt")
    return "\n".join(lines) + "\n"


def _existing_build_tool(root: Path | None) -> SelectedJavaBuildTool | None:
    if root is None:
        return None
    if (root / "pom.xml").is_file():
        return "maven"
    if (root / "build.gradle").is_file() or (root / "build.gradle.kts").is_file():
        return "gradle"
    if (root / "javac.args").is_file():
        return "javac"
    return None


def _read_existing_build_file(
    root: Path | None,
    selected: SelectedJavaBuildTool,
) -> tuple[str, str] | None:
    if root is None:
        return None
    candidates: dict[SelectedJavaBuildTool, tuple[str, ...]] = {
        "maven": ("pom.xml",),
        "gradle": ("build.gradle", "build.gradle.kts"),
        "javac": ("javac.args",),
        "unknown": (),
    }
    for rel in candidates[selected]:
        path = root / rel
        if path.is_file():
            return rel, path.read_text(encoding="utf-8", errors="replace")[:200_000]
    return None


def _project_name(
    args: JavaInferBuildSystemArgs,
    archive_path: Path,
    evidence: _ArchiveBuildEvidence,
) -> str:
    if args.project_name:
        return _safe_project_name(args.project_name)
    if evidence.maven_artifact_id:
        return _safe_project_name(evidence.maven_artifact_id)
    return _safe_project_name(archive_path.stem)


def _module_name(evidence: _ArchiveBuildEvidence) -> str | None:
    return evidence.manifest.get("Automatic-Module-Name")


def _release_warnings(java_release: int | None, major: int | None) -> list[str]:
    if java_release is None:
        return ["No classfile major version was available to infer Java release."]
    if major is not None and java_release >= 21:
        return [
            f"Classfile major {major} maps to Java {java_release}; make sure a "
            "matching JDK is selected before compiling recovered sources."
        ]
    return []


def _maven_identity(
    zf: zipfile.ZipFile,
) -> tuple[str | None, str | None, str | None]:
    for info in zf.infolist():
        lowered = info.filename.lower()
        if not (
            lowered.startswith("meta-inf/maven/")
            and lowered.endswith("/pom.properties")
        ):
            continue
        props = _parse_properties(zf.read(info).decode("utf-8", errors="replace"))
        artifact_id = props.get("artifactId")
        if artifact_id:
            return props.get("groupId"), artifact_id, props.get("version")
    return None, None, None


def _embedded_pom(zf: zipfile.ZipFile) -> tuple[str | None, str | None]:
    for info in zf.infolist():
        lowered = info.filename.lower()
        if lowered.startswith("meta-inf/maven/") and lowered.endswith("/pom.xml"):
            return info.filename, zf.read(info).decode("utf-8", errors="replace")
    return None, None


def _class_file_majors(zf: zipfile.ZipFile) -> list[int]:
    majors: list[int] = []
    for info in zf.infolist():
        if info.is_dir() or not info.filename.endswith(".class"):
            continue
        if info.filename.startswith("META-INF/versions/"):
            continue
        data = zf.read(info, pwd=None)
        if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
            continue
        majors.append(int.from_bytes(data[6:8], "big"))
    return majors


def _java_release_from_major(major: int | None) -> int | None:
    if major is None:
        return None
    if major >= 49:
        return major - 44
    return None


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


def _safe_project_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip())
    cleaned = cleaned.strip(".-")
    return cleaned or "recovered-java"


def _gradle_identifier(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", name.strip())
    return cleaned.strip("_") or "recovered_java"


def _xml_text(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _add_build_system_node(
    kb: KnowledgeBase,
    archive_path: Path,
    result: JavaInferBuildSystemResult,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.java_build_system,
            label=f"{result.selected_build_tool}: {result.project_name or 'unknown'}",
            text=result.rationale,
            props={
                "tool": "java_infer_build_system",
                "archive_path": str(archive_path),
                **result.model_dump(),
            },
            tags=["java", "build", result.selected_build_tool],
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


def build_tool() -> MemoryTool[JavaInferBuildSystemArgs, JavaInferBuildSystemResult]:
    return JavaInferBuildSystemTool()
