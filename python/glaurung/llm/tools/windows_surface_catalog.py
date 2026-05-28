from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


class WindowsSurfaceCatalogArgs(BaseModel):
    surfaces_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-surfaces.yaml. Defaults to ASB_REPO "
            "or sibling repo."
        ),
    )
    sources_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-sources.yaml for reference joins.",
    )
    build_corpus_path: str | None = Field(
        None,
        description=(
            "Optional path to ASB data/kg/pe-build-corpus.yaml for target joins."
        ),
    )
    surface_id: str | None = Field(
        None,
        description="Optional surface id filter, e.g. syscall, ioctl, network.",
    )
    attacker_class: str | None = Field(
        None,
        description="Optional attacker class filter, e.g. windows-appcontainer.",
    )
    boundary: str | None = Field(
        None,
        description="Optional boundary filter, e.g. user_kernel or remote_network.",
    )
    min_ranking_weight: int | None = Field(
        None,
        description="Optional minimum ranking weight filter.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact surface-catalog evidence node to the KB.",
    )


class SurfaceReference(BaseModel):
    kind: str
    id: str
    symbols_or_filename: list[str] = Field(default_factory=list)


class SurfaceCatalogRecord(BaseModel):
    id: str
    boundary: str
    attacker_classes: list[str]
    validation_requirements: list[str]
    ranking_weight: int
    notes: str | None = None
    references: list[SurfaceReference] = Field(default_factory=list)


class WindowsSurfaceCatalogResult(BaseModel):
    surfaces_path: str
    sources_path: str | None = None
    build_corpus_path: str | None = None
    surface_count_total: int
    surfaces: list[SurfaceCatalogRecord]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSurfaceCatalogTool(
    MemoryTool[WindowsSurfaceCatalogArgs, WindowsSurfaceCatalogResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_surface_catalog",
                description=(
                    "Load ASB Windows attacker-surface semantics and join "
                    "them to source/corpus references when available."
                ),
                tags=("windows", "pe", "metadata", "surface", "reachability"),
            ),
            WindowsSurfaceCatalogArgs,
            WindowsSurfaceCatalogResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSurfaceCatalogArgs,
    ) -> WindowsSurfaceCatalogResult:
        surfaces_path = _resolve_metadata_path(
            args.surfaces_path,
            "data/kg/pe-surfaces.yaml",
        )
        sources_path = _optional_metadata_path(args.sources_path, "data/kg/pe-sources.yaml")
        build_corpus_path = _optional_metadata_path(
            args.build_corpus_path,
            "data/kg/pe-build-corpus.yaml",
        )

        references = _surface_references(sources_path, build_corpus_path)
        surfaces = [
            _surface_record(entry, surfaces_path, references)
            for entry in _load_yaml_list(surfaces_path)
        ]
        surface_count_total = len(surfaces)
        surfaces = _filter_surfaces(surfaces, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_surface_catalog",
                    props={
                        "surface_id": args.surface_id,
                        "attacker_class": args.attacker_class,
                        "boundary": args.boundary,
                        "min_ranking_weight": args.min_ranking_weight,
                        "surface_matches": len(surfaces),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSurfaceCatalogResult(
            surfaces_path=str(surfaces_path),
            sources_path=str(sources_path) if sources_path else None,
            build_corpus_path=str(build_corpus_path) if build_corpus_path else None,
            surface_count_total=surface_count_total,
            surfaces=surfaces,
            evidence_node_id=evidence_node_id,
            notes=[
                "surface metadata describes reachability context; it is not per-function proof"
            ],
        )


def _optional_metadata_path(raw_path: str | None, rel_path: str) -> Path | None:
    if raw_path:
        return _resolve_metadata_path(raw_path, rel_path)
    try:
        return _resolve_metadata_path(None, rel_path)
    except FileNotFoundError:
        return None


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: surface entry {idx} is not a mapping")
        out.append(entry)
    return out


def _surface_record(
    entry: dict[str, Any],
    path: Path,
    references: dict[str, list[SurfaceReference]],
) -> SurfaceCatalogRecord:
    surface_id = _required_str(entry, "id", path)
    return SurfaceCatalogRecord(
        id=surface_id,
        boundary=_required_str(entry, "boundary", path),
        attacker_classes=_required_str_list(entry, "attacker_classes", path),
        validation_requirements=_required_str_list(
            entry,
            "validation_requirements",
            path,
        ),
        ranking_weight=int(entry.get("ranking_weight", 0)),
        notes=entry.get("notes"),
        references=references.get(surface_id, []),
    )


def _filter_surfaces(
    surfaces: list[SurfaceCatalogRecord],
    args: WindowsSurfaceCatalogArgs,
) -> list[SurfaceCatalogRecord]:
    out = surfaces
    if args.surface_id:
        out = [surface for surface in out if surface.id == args.surface_id]
    if args.attacker_class:
        out = [
            surface
            for surface in out
            if args.attacker_class in surface.attacker_classes
        ]
    if args.boundary:
        out = [surface for surface in out if surface.boundary == args.boundary]
    if args.min_ranking_weight is not None:
        out = [
            surface
            for surface in out
            if surface.ranking_weight >= args.min_ranking_weight
        ]
    return out


def _surface_references(
    sources_path: Path | None,
    build_corpus_path: Path | None,
) -> dict[str, list[SurfaceReference]]:
    references: dict[str, list[SurfaceReference]] = {}
    if sources_path:
        for entry in _load_yaml_list(sources_path):
            surface = entry.get("surface")
            if isinstance(surface, str) and surface:
                references.setdefault(surface, []).append(
                    SurfaceReference(
                        kind="source",
                        id=_required_str(entry, "id", sources_path),
                        symbols_or_filename=_string_list(entry.get("symbols")),
                    )
                )
    if build_corpus_path:
        for entry in _load_yaml_list(build_corpus_path):
            target_id = _required_str(entry, "id", build_corpus_path)
            filename = _required_str(entry, "filename", build_corpus_path)
            for surface in _string_list(entry.get("surfaces")):
                references.setdefault(surface, []).append(
                    SurfaceReference(
                        kind="build_corpus_target",
                        id=target_id,
                        symbols_or_filename=[filename],
                    )
                )
    return references


def _string_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(value) for value in raw if str(value)]


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty list field {key!r}")
    out = [str(value) for value in values if str(value)]
    if len(out) != len(set(out)):
        raise ValueError(f"{path}: duplicate values in {key!r}")
    return out


def build_tool() -> MemoryTool[
    WindowsSurfaceCatalogArgs,
    WindowsSurfaceCatalogResult,
]:
    return WindowsSurfaceCatalogTool()
