from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaDetectEntrypointsArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    max_classes: int = Field(50_000, ge=0)
    max_entrypoints: int = Field(1_000, ge=0)


class JavaEntrypointSummary(BaseModel):
    entrypoint_id: str
    category: str
    class_name: str
    method_name: str | None = None
    method_descriptor: str | None = None
    bci: int | None = None
    source: str
    detail: str
    confidence: float


class JavaDetectEntrypointsResult(BaseModel):
    archive_path: str
    sha256: str
    class_count: int
    parsed_class_count: int
    parse_error_count: int
    entrypoint_count: int
    entrypoints: list[JavaEntrypointSummary]
    summary_by_category: dict[str, int]
    manifest_main_class: str | None = None
    truncated: bool = False


class JavaDetectEntrypointsTool(
    MemoryTool[JavaDetectEntrypointsArgs, JavaDetectEntrypointsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_detect_entrypoints",
                description=(
                    "Detect Java archive entrypoints from manifests, main methods, "
                    "Java agents, ServiceLoader descriptors, static initializers, "
                    "and scheduler registrations."
                ),
                tags=("java", "jar", "entrypoint", "kb"),
            ),
            JavaDetectEntrypointsArgs,
            JavaDetectEntrypointsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaDetectEntrypointsArgs,
    ) -> JavaDetectEntrypointsResult:
        path = Path(args.path or ctx.file_path)
        digest = _sha256(path)
        entrypoints: list[JavaEntrypointSummary] = []
        class_count = 0
        parsed_class_count = 0
        parse_error_count = 0
        manifest_main_class: str | None = None
        truncated = False
        java_analysis = getattr(g, "analysis")

        if not zipfile.is_zipfile(path):
            return JavaDetectEntrypointsResult(
                archive_path=str(path),
                sha256=digest,
                class_count=0,
                parsed_class_count=0,
                parse_error_count=1,
                entrypoint_count=0,
                entrypoints=[],
                summary_by_category={},
                manifest_main_class=None,
                truncated=False,
            )

        with zipfile.ZipFile(path) as zf:
            manifest = _manifest_attrs(zf)
            manifest_main_class = manifest.get("Main-Class")
            _append_manifest_entrypoints(entrypoints, manifest, args.max_entrypoints)
            _append_service_entrypoints(entrypoints, zf, args.max_entrypoints)

            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".class"):
                    continue
                class_count += 1
                if class_count > args.max_classes:
                    truncated = True
                    continue
                try:
                    parsed = java_analysis.parse_java_class_bytes(zf.read(info))
                except RuntimeError:
                    parse_error_count += 1
                    continue
                if parsed is None:
                    parse_error_count += 1
                    continue
                parsed_class_count += 1
                _append_class_entrypoints(entrypoints, parsed, args.max_entrypoints)
                if len(entrypoints) >= args.max_entrypoints:
                    truncated = True
                    break

        for entrypoint in entrypoints:
            _add_entrypoint_node(kb, path, entrypoint)

        summary_by_category: dict[str, int] = {}
        for entrypoint in entrypoints:
            summary_by_category[entrypoint.category] = (
                summary_by_category.get(entrypoint.category, 0) + 1
            )

        return JavaDetectEntrypointsResult(
            archive_path=str(path),
            sha256=digest,
            class_count=class_count,
            parsed_class_count=parsed_class_count,
            parse_error_count=parse_error_count,
            entrypoint_count=len(entrypoints),
            entrypoints=entrypoints,
            summary_by_category=summary_by_category,
            manifest_main_class=manifest_main_class,
            truncated=truncated,
        )


def _append_manifest_entrypoints(
    out: list[JavaEntrypointSummary],
    manifest: dict[str, str],
    limit: int,
) -> None:
    for attr, category, method_name, descriptor in (
        ("Main-Class", "manifest_main", "main", "([Ljava/lang/String;)V"),
        (
            "Premain-Class",
            "java_agent_premain",
            "premain",
            "(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V",
        ),
        (
            "Agent-Class",
            "java_agent_agentmain",
            "agentmain",
            "(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V",
        ),
    ):
        if len(out) >= limit:
            return
        class_name = manifest.get(attr)
        if not class_name:
            continue
        out.append(
            _entrypoint(
                category=category,
                class_name=_internal(class_name),
                method_name=method_name,
                method_descriptor=descriptor,
                source="META-INF/MANIFEST.MF",
                detail=f"{attr}: {class_name}",
                confidence=0.95,
            )
        )


def _append_service_entrypoints(
    out: list[JavaEntrypointSummary],
    zf: zipfile.ZipFile,
    limit: int,
) -> None:
    for info in zf.infolist():
        if len(out) >= limit:
            return
        if info.is_dir() or not info.filename.startswith("META-INF/services/"):
            continue
        service_name = info.filename.removeprefix("META-INF/services/")
        text = zf.read(info).decode("utf-8", errors="replace")
        for raw_line in text.splitlines():
            if len(out) >= limit:
                return
            provider = raw_line.split("#", 1)[0].strip()
            if not provider:
                continue
            out.append(
                _entrypoint(
                    category="service_provider",
                    class_name=_internal(provider),
                    source=info.filename,
                    detail=f"{service_name} provider {provider}",
                    confidence=0.9,
                )
            )


def _append_class_entrypoints(
    out: list[JavaEntrypointSummary],
    parsed: dict[str, Any],
    limit: int,
) -> None:
    class_name = str(parsed["class_name"])
    for method in parsed["methods"]:
        if len(out) >= limit:
            return
        method_name = str(method["name"])
        descriptor = str(method["descriptor"])
        access_flags = int(method["access_flags"])
        if (
            method_name == "main"
            and descriptor == "([Ljava/lang/String;)V"
            and access_flags & 0x0008
        ):
            out.append(
                _entrypoint(
                    category="main_method",
                    class_name=class_name,
                    method_name=method_name,
                    method_descriptor=descriptor,
                    source=f"{class_name}.class",
                    detail="public static main method",
                    confidence=0.9,
                )
            )
        if method_name == "<clinit>":
            out.append(
                _entrypoint(
                    category="static_initializer",
                    class_name=class_name,
                    method_name=method_name,
                    method_descriptor=descriptor,
                    source=f"{class_name}.class",
                    detail="class static initializer",
                    confidence=0.65,
                )
            )
        code = method.get("code")
        if not isinstance(code, dict):
            continue
        for xref in code.get("xrefs", []):
            if len(out) >= limit:
                return
            if not isinstance(xref, dict):
                continue
            if _is_scheduler_registration(xref):
                out.append(
                    _entrypoint(
                        category="scheduler_registration",
                        class_name=class_name,
                        method_name=method_name,
                        method_descriptor=descriptor,
                        bci=int(xref["bci"])
                        if isinstance(xref.get("bci"), int)
                        else None,
                        source=f"{class_name}.class",
                        detail=str(xref.get("target", "")),
                        confidence=0.8,
                    )
                )


def _is_scheduler_registration(xref: dict[str, Any]) -> bool:
    owner = str(xref.get("owner", ""))
    name = str(xref.get("name", ""))
    return owner in {
        "java/util/concurrent/ScheduledExecutorService",
        "java/util/Timer",
    } and name in {"schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay"}


def _entrypoint(
    *,
    category: str,
    class_name: str,
    source: str,
    detail: str,
    confidence: float,
    method_name: str | None = None,
    method_descriptor: str | None = None,
    bci: int | None = None,
) -> JavaEntrypointSummary:
    key = f"{category}:{class_name}:{method_name}:{method_descriptor}:{bci}:{source}:{detail}"
    return JavaEntrypointSummary(
        entrypoint_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
        category=category,
        class_name=class_name,
        method_name=method_name,
        method_descriptor=method_descriptor,
        bci=bci,
        source=source,
        detail=detail,
        confidence=confidence,
    )


def _add_entrypoint_node(
    kb: KnowledgeBase,
    archive_path: Path,
    entrypoint: JavaEntrypointSummary,
) -> None:
    label = f"{entrypoint.category}: {entrypoint.class_name}"
    if entrypoint.method_name:
        label += f"#{entrypoint.method_name}{entrypoint.method_descriptor or ''}"
    kb.add_node(
        Node(
            kind=NodeKind.java_entrypoint,
            label=label,
            props={
                "tool": "java_detect_entrypoints",
                "archive_path": str(archive_path),
                **entrypoint.model_dump(),
            },
            tags=["java", "entrypoint", entrypoint.category],
        )
    )


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


def _internal(class_name: str) -> str:
    return class_name.removesuffix(".class").replace(".", "/")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_tool() -> MemoryTool[JavaDetectEntrypointsArgs, JavaDetectEntrypointsResult]:
    return JavaDetectEntrypointsTool()
