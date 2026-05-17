from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class PeViewManifestArgs(BaseModel):
    path: str | None = Field(None, description="Path to the PE file")
    language_id: int | None = Field(None, description="Optional manifest language ID")
    max_text_bytes: int = Field(65_536, ge=0)
    add_to_kb: bool = True


class PeManifestResult(BaseModel):
    path: str
    found: bool = False
    evidence: str | None = None
    assembly_identity: dict[str, str] = Field(default_factory=dict)
    requested_execution_level: str | None = None
    ui_access: bool | None = None
    dpi_awareness: list[str] = Field(default_factory=list)
    compatibility_guids: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    text_preview: str | None = None
    text_truncated: bool = False
    warnings: list[str] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)


class PeViewManifestTool(MemoryTool[PeViewManifestArgs, PeManifestResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="pe_view_manifest",
                description=(
                    "Decode a Windows PE RT_MANIFEST resource into compact "
                    "security, compatibility, identity, and dependency fields."
                ),
                tags=("pe", "resource", "manifest", "windows", "kb"),
            ),
            PeViewManifestArgs,
            PeManifestResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: PeViewManifestArgs,
    ) -> PeManifestResult:
        path = Path(args.path or ctx.file_path)
        try:
            resource = g.analysis.pe_view_resource_path(
                str(path),
                type_filter="manifest",
                language_id=args.language_id,
                max_read_bytes=ctx.budgets.max_read_bytes,
                max_file_size=ctx.budgets.max_file_size,
                max_text_bytes=args.max_text_bytes,
            )
        except Exception as exc:
            return PeManifestResult(
                path=str(path),
                warnings=[str(exc)],
                stop_reasons=["input_not_pe_or_unparseable"],
            )
        if resource is None:
            return PeManifestResult(path=str(path), stop_reasons=["manifest_not_found"])

        text = resource.get("text") or ""
        result = _decode_manifest_text(str(path), text)
        result.found = True
        result.evidence = resource.get("evidence")
        result.text_preview = text[:1024]
        result.text_truncated = bool(resource.get("text_truncated", False))
        result.warnings.extend(resource.get("warnings") or [])
        if args.add_to_kb:
            _add_manifest_node(kb, path, result)
        return result


def _decode_manifest_text(path: str, text: str) -> PeManifestResult:
    result = PeManifestResult(path=path)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        result.warnings.append(f"manifest_xml_parse_error:{exc}")
        return result

    top_identity = _first_child_by_local_name(root, "assemblyIdentity")
    if top_identity is not None:
        result.assembly_identity = {
            str(key): str(value) for key, value in top_identity.attrib.items()
        }

    requested = _first_by_local_name(root, "requestedExecutionLevel")
    if requested is not None:
        result.requested_execution_level = requested.attrib.get("level")
        ui_access = requested.attrib.get("uiAccess")
        if ui_access is not None:
            result.ui_access = ui_access.lower() == "true"

    result.dpi_awareness = [
        (elem.text or "").strip()
        for elem in _iter_by_local_name(root, ("dpiAware", "dpiAwareness"))
        if (elem.text or "").strip()
    ]
    result.compatibility_guids = [
        elem.attrib["Id"]
        for elem in _iter_by_local_name(root, ("supportedOS",))
        if elem.attrib.get("Id")
    ]
    result.dependencies = _manifest_dependencies(root)
    return result


def _manifest_dependencies(root: ET.Element) -> list[str]:
    dependencies: list[str] = []
    for dependent in _iter_by_local_name(root, ("dependentAssembly",)):
        identity = _first_child_by_local_name(dependent, "assemblyIdentity")
        if identity is None:
            continue
        name = identity.attrib.get("name")
        if name:
            dependencies.append(name)
    return dependencies


def _iter_by_local_name(root: ET.Element, names: tuple[str, ...]):
    wanted = set(names)
    for elem in root.iter():
        if _local_name(elem.tag) in wanted:
            yield elem


def _first_by_local_name(root: ET.Element, name: str) -> ET.Element | None:
    return next(_iter_by_local_name(root, (name,)), None)


def _first_child_by_local_name(root: ET.Element, name: str) -> ET.Element | None:
    for child in list(root):
        if _local_name(child.tag) == name:
            return child
    return None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _add_manifest_node(
    kb: KnowledgeBase,
    path: Path,
    result: PeManifestResult,
) -> None:
    kb.add_node(
        Node(
            kind=NodeKind.pe_resource,
            label=result.evidence or "PE manifest",
            props={
                "tool": "pe_view_manifest",
                "path": str(path),
                **result.model_dump(),
            },
            tags=["pe", "resource", "manifest"],
        )
    )


def build_tool() -> MemoryTool[PeViewManifestArgs, PeManifestResult]:
    return PeViewManifestTool()
