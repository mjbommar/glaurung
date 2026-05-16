from __future__ import annotations

import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class JavaViewManifestArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    entry_name: str = "META-INF/MANIFEST.MF"


class JavaManifestSection(BaseModel):
    name: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class JavaViewManifestResult(BaseModel):
    archive_path: str
    manifest_found: bool = False
    entry_name: str = "META-INF/MANIFEST.MF"
    main_attributes: dict[str, str] = Field(default_factory=dict)
    sections: list[JavaManifestSection] = Field(default_factory=list)
    main_class: str | None = None
    premain_class: str | None = None
    agent_class: str | None = None
    launcher_agent_class: str | None = None
    class_path: list[str] = Field(default_factory=list)
    multi_release: bool = False
    sealed: bool = False
    signature_attributes: list[str] = Field(default_factory=list)
    build_attributes: dict[str, str] = Field(default_factory=dict)
    manifest_node_id: str | None = None
    stop_reasons: list[str] = Field(default_factory=list)


class JavaViewManifestTool(MemoryTool[JavaViewManifestArgs, JavaViewManifestResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_view_manifest",
                description=(
                    "Parse a JAR manifest with continuation-line support and "
                    "surface launch, agent, class-path, multi-release, sealed, "
                    "signature, and build attributes."
                ),
                tags=("java", "jar", "manifest", "kb"),
            ),
            JavaViewManifestArgs,
            JavaViewManifestResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaViewManifestArgs,
    ) -> JavaViewManifestResult:
        archive_path = Path(args.path or ctx.file_path)
        result = JavaViewManifestResult(
            archive_path=str(archive_path),
            entry_name=args.entry_name,
        )
        if not zipfile.is_zipfile(archive_path):
            result.stop_reasons.append("input_not_zip")
            return result
        with zipfile.ZipFile(archive_path) as zf:
            names = {info.filename for info in zf.infolist()}
            if args.entry_name not in names:
                result.stop_reasons.append("manifest_not_found")
                return result
            sections = _parse_manifest(zf.read(args.entry_name))
        result.manifest_found = True
        result.sections = sections
        result.main_attributes = sections[0].attributes if sections else {}
        result.main_class = _get_attr(result.main_attributes, "Main-Class")
        result.premain_class = _get_attr(result.main_attributes, "Premain-Class")
        result.agent_class = _get_attr(result.main_attributes, "Agent-Class")
        result.launcher_agent_class = _get_attr(
            result.main_attributes, "Launcher-Agent-Class"
        )
        result.class_path = _split_class_path(
            _get_attr(result.main_attributes, "Class-Path")
        )
        result.multi_release = _truthy(
            _get_attr(result.main_attributes, "Multi-Release")
        )
        result.sealed = _truthy(_get_attr(result.main_attributes, "Sealed"))
        result.signature_attributes = _signature_attributes(sections)
        result.build_attributes = {
            key: value
            for key, value in result.main_attributes.items()
            if key
            in {"Created-By", "Build-Jdk", "Build-Jdk-Spec", "Implementation-Version"}
        }
        node = kb.add_node(
            Node(
                kind=NodeKind.java_resource,
                label=args.entry_name,
                props={
                    "tool": "java_view_manifest",
                    "archive_path": str(archive_path),
                    **result.model_dump(exclude={"manifest_node_id"}),
                },
                tags=["java", "manifest"],
            )
        )
        result.manifest_node_id = node.id
        return result


def _parse_manifest(data: bytes) -> list[JavaManifestSection]:
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
    sections: list[list[str]] = [[]]
    for line in text.split("\n"):
        if line == "":
            if sections[-1]:
                sections.append([])
            continue
        if line.startswith(" ") and sections[-1]:
            sections[-1][-1] += line[1:]
        else:
            sections[-1].append(line)
    out: list[JavaManifestSection] = []
    for raw_section in sections:
        if not raw_section:
            continue
        attrs: dict[str, str] = {}
        for line in raw_section:
            key, sep, value = line.partition(":")
            if sep:
                attrs[key.strip()] = value.lstrip(" ")
        out.append(
            JavaManifestSection(
                name=attrs.get("Name"),
                attributes=attrs,
            )
        )
    return out


def _get_attr(attributes: dict[str, str], key: str) -> str | None:
    value = attributes.get(key)
    return value if value else None


def _split_class_path(value: str | None) -> list[str]:
    return value.split() if value else []


def _truthy(value: str | None) -> bool:
    return value is not None and value.lower() == "true"


def _signature_attributes(sections: list[JavaManifestSection]) -> list[str]:
    out: list[str] = []
    for section in sections:
        for key in section.attributes:
            if key == "Signature-Version" or key.endswith("-Digest"):
                out.append(key)
    return list(dict.fromkeys(out))


def build_tool() -> MemoryTool[JavaViewManifestArgs, JavaViewManifestResult]:
    return JavaViewManifestTool()
