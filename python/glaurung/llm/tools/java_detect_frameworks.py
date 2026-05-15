from __future__ import annotations

import hashlib
import json
import tomllib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaDetectFrameworksArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    max_frameworks: int = Field(512, ge=0)


class JavaFrameworkSummary(BaseModel):
    framework_id: str
    kind: str
    name: str
    version: str | None = None
    source_path: str
    detail: str
    confidence: float


class JavaDetectFrameworksResult(BaseModel):
    archive_path: str
    framework_count: int
    frameworks: list[JavaFrameworkSummary] = Field(default_factory=list)
    summary_by_kind: dict[str, int] = Field(default_factory=dict)
    truncated: bool = False


class JavaDetectFrameworksTool(
    MemoryTool[JavaDetectFrameworksArgs, JavaDetectFrameworksResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_detect_frameworks",
                description=(
                    "Detect generic JVM framework, launcher, module, service, "
                    "plugin, and mod-loader metadata from a JAR archive."
                ),
                tags=("java", "jar", "framework", "metadata", "kb"),
            ),
            JavaDetectFrameworksArgs,
            JavaDetectFrameworksResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDetectFrameworksArgs,
    ) -> JavaDetectFrameworksResult:
        path = Path(args.path or ctx.file_path)
        frameworks: list[JavaFrameworkSummary] = []
        truncated = False
        if not zipfile.is_zipfile(path):
            return JavaDetectFrameworksResult(
                archive_path=str(path),
                framework_count=0,
                frameworks=[],
                summary_by_kind={},
                truncated=False,
            )

        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            detected = [
                *_manifest_frameworks(zf),
                *_service_loader_frameworks(zf),
                *_maven_frameworks(zf),
                *_minecraft_frameworks(zf),
                *_plugin_frameworks(zf),
                *_path_presence_frameworks(names),
            ]
            truncated = len(detected) > args.max_frameworks
            frameworks = detected[: args.max_frameworks]

        summary_by_kind: dict[str, int] = {}
        for framework in frameworks:
            summary_by_kind[framework.kind] = summary_by_kind.get(framework.kind, 0) + 1
            kb.add_node(
                Node(
                    kind=NodeKind.java_framework,
                    label=f"{framework.kind}: {framework.name}",
                    text=framework.detail,
                    props={
                        "tool": "java_detect_frameworks",
                        "archive_path": str(path),
                        **framework.model_dump(),
                    },
                    tags=["java", "framework", framework.kind],
                )
            )

        return JavaDetectFrameworksResult(
            archive_path=str(path),
            framework_count=len(frameworks),
            frameworks=frameworks,
            summary_by_kind=summary_by_kind,
            truncated=truncated,
        )


def _manifest_frameworks(zf: zipfile.ZipFile) -> list[JavaFrameworkSummary]:
    manifest = _manifest_attrs(zf)
    out: list[JavaFrameworkSummary] = []
    main_class = manifest.get("Main-Class")
    if main_class:
        out.append(
            _framework(
                kind="java_application",
                name=main_class,
                source_path="META-INF/MANIFEST.MF",
                detail=f"Main-Class: {main_class}",
                confidence=0.95,
            )
        )
    for attr, kind in (
        ("Premain-Class", "java_agent"),
        ("Agent-Class", "java_agent"),
    ):
        class_name = manifest.get(attr)
        if class_name:
            out.append(
                _framework(
                    kind=kind,
                    name=class_name,
                    source_path="META-INF/MANIFEST.MF",
                    detail=f"{attr}: {class_name}",
                    confidence=0.95,
                )
            )
    spring_version = manifest.get("Spring-Boot-Version")
    start_class = manifest.get("Start-Class") or main_class
    if spring_version or _looks_like_spring_boot(main_class):
        out.append(
            _framework(
                kind="spring_boot",
                name=start_class or "spring-boot-application",
                version=spring_version,
                source_path="META-INF/MANIFEST.MF",
                detail="Spring Boot manifest metadata",
                confidence=0.95 if spring_version else 0.75,
            )
        )
    bundle_name = manifest.get("Bundle-SymbolicName")
    if bundle_name:
        out.append(
            _framework(
                kind="osgi_bundle",
                name=bundle_name.split(";", 1)[0].strip(),
                version=manifest.get("Bundle-Version"),
                source_path="META-INF/MANIFEST.MF",
                detail="OSGi bundle manifest metadata",
                confidence=0.95,
            )
        )
    return out


def _service_loader_frameworks(zf: zipfile.ZipFile) -> list[JavaFrameworkSummary]:
    out: list[JavaFrameworkSummary] = []
    for info in zf.infolist():
        if info.is_dir() or not info.filename.startswith("META-INF/services/"):
            continue
        service = info.filename.removeprefix("META-INF/services/")
        providers = [
            line.split("#", 1)[0].strip()
            for line in zf.read(info).decode("utf-8", errors="replace").splitlines()
        ]
        providers = [provider for provider in providers if provider]
        out.append(
            _framework(
                kind="service_loader",
                name=service,
                source_path=info.filename,
                detail=f"{len(providers)} ServiceLoader provider(s)",
                confidence=0.9,
            )
        )
    return out


def _maven_frameworks(zf: zipfile.ZipFile) -> list[JavaFrameworkSummary]:
    out: list[JavaFrameworkSummary] = []
    for info in zf.infolist():
        if (
            info.is_dir()
            or not info.filename.startswith("META-INF/maven/")
            or not info.filename.endswith("/pom.properties")
        ):
            continue
        props = _parse_properties(zf.read(info).decode("utf-8", errors="replace"))
        group_id = props.get("groupId")
        artifact_id = props.get("artifactId")
        if not group_id or not artifact_id:
            continue
        out.append(
            _framework(
                kind="maven_artifact",
                name=f"{group_id}:{artifact_id}",
                version=props.get("version"),
                source_path=info.filename,
                detail="Maven pom.properties metadata",
                confidence=0.95,
            )
        )
    return out


def _minecraft_frameworks(zf: zipfile.ZipFile) -> list[JavaFrameworkSummary]:
    out: list[JavaFrameworkSummary] = []
    mods_toml = _read_toml(zf, "META-INF/mods.toml")
    if mods_toml:
        loader = str(mods_toml.get("modLoader", "")).lower()
        kind = (
            "minecraft_neoforge_mod" if "neoforge" in loader else "minecraft_forge_mod"
        )
        mods = mods_toml.get("mods", [])
        if isinstance(mods, list):
            for mod in mods:
                if not isinstance(mod, dict) or not isinstance(mod.get("modId"), str):
                    continue
                out.append(
                    _framework(
                        kind=kind,
                        name=mod["modId"],
                        version=_str_or_none(mod.get("version")),
                        source_path="META-INF/mods.toml",
                        detail=f"modLoader={mods_toml.get('modLoader', '')}",
                        confidence=0.95,
                    )
                )
    fabric = _read_json(zf, "fabric.mod.json")
    if isinstance(fabric.get("id"), str):
        out.append(
            _framework(
                kind="minecraft_fabric_mod",
                name=fabric["id"],
                version=_str_or_none(fabric.get("version")),
                source_path="fabric.mod.json",
                detail="Fabric mod metadata",
                confidence=0.95,
            )
        )
    quilt = _read_json(zf, "quilt.mod.json")
    quilt_loader = quilt.get("quilt_loader")
    if isinstance(quilt_loader, dict) and isinstance(quilt_loader.get("id"), str):
        out.append(
            _framework(
                kind="minecraft_quilt_mod",
                name=quilt_loader["id"],
                version=_str_or_none(quilt_loader.get("version")),
                source_path="quilt.mod.json",
                detail="Quilt mod metadata",
                confidence=0.95,
            )
        )
    mcmod_info = _read_json(zf, "mcmod.info")
    if isinstance(mcmod_info, list):
        for item in mcmod_info:
            if isinstance(item, dict) and isinstance(item.get("modid"), str):
                out.append(
                    _framework(
                        kind="minecraft_legacy_forge_mod",
                        name=item["modid"],
                        version=_str_or_none(item.get("version")),
                        source_path="mcmod.info",
                        detail="Legacy Forge mcmod.info metadata",
                        confidence=0.85,
                    )
                )
    return out


def _plugin_frameworks(zf: zipfile.ZipFile) -> list[JavaFrameworkSummary]:
    out: list[JavaFrameworkSummary] = []
    for path, kind in (
        ("plugin.yml", "bukkit_plugin"),
        ("paper-plugin.yml", "paper_plugin"),
        ("velocity-plugin.json", "velocity_plugin"),
    ):
        try:
            text = zf.read(path).decode("utf-8", errors="replace")
        except KeyError:
            continue
        if path.endswith(".json"):
            data = _parse_json(text)
            name = _str_or_none(data.get("id") or data.get("name"))
            version = _str_or_none(data.get("version"))
        else:
            data = _parse_simple_yaml(text)
            name = data.get("name")
            version = data.get("version")
        if name:
            out.append(
                _framework(
                    kind=kind,
                    name=name,
                    version=version,
                    source_path=path,
                    detail=f"{kind} descriptor",
                    confidence=0.9,
                )
            )
    return out


def _path_presence_frameworks(names: set[str]) -> list[JavaFrameworkSummary]:
    out: list[JavaFrameworkSummary] = []
    if "module-info.class" in names:
        out.append(
            _framework(
                kind="java_module",
                name="module-info",
                source_path="module-info.class",
                detail="JPMS module descriptor present",
                confidence=0.85,
            )
        )
    if any(name.startswith("BOOT-INF/") for name in names):
        out.append(
            _framework(
                kind="spring_boot",
                name="spring-boot-layout",
                source_path="BOOT-INF/",
                detail="Spring Boot executable JAR layout",
                confidence=0.8,
            )
        )
    if "WEB-INF/web.xml" in names or any(
        name.startswith("WEB-INF/classes/") for name in names
    ):
        out.append(
            _framework(
                kind="java_webapp",
                name="servlet-webapp",
                source_path="WEB-INF/",
                detail="Servlet WAR layout metadata",
                confidence=0.8,
            )
        )
    return out


def _framework(
    *,
    kind: str,
    name: str,
    source_path: str,
    detail: str,
    confidence: float,
    version: str | None = None,
) -> JavaFrameworkSummary:
    key = f"{kind}:{name}:{version}:{source_path}:{detail}"
    return JavaFrameworkSummary(
        framework_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        kind=kind,
        name=name,
        version=version,
        source_path=source_path,
        detail=detail,
        confidence=confidence,
    )


def _manifest_attrs(zf: zipfile.ZipFile) -> dict[str, str]:
    try:
        text = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
    except KeyError:
        return {}
    lines: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]
        elif line:
            lines.append(line)
    attrs: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep:
            attrs[key] = value.strip()
    return attrs


def _read_json(zf: zipfile.ZipFile, name: str) -> Any:
    try:
        return json.loads(zf.read(name).decode("utf-8"))
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _read_toml(zf: zipfile.ZipFile, name: str) -> dict[str, Any]:
    try:
        return tomllib.loads(zf.read(name).decode("utf-8"))
    except (KeyError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}


def _parse_properties(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


def _parse_json(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _parse_simple_yaml(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        out[key.strip()] = value.strip().strip("\"'")
    return out


def _looks_like_spring_boot(main_class: str | None) -> bool:
    return bool(
        main_class and main_class.startswith("org.springframework.boot.loader.")
    )


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def build_tool() -> MemoryTool[JavaDetectFrameworksArgs, JavaDetectFrameworksResult]:
    return JavaDetectFrameworksTool()
