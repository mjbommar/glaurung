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


class WindowsTargetSurfaceProfileArgs(BaseModel):
    manifest_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-build-corpus.yaml.",
    )
    surfaces_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-surfaces.yaml.",
    )
    target_id: str | None = Field(None, description="Optional build-corpus target id.")
    filename: str | None = Field(None, description="Optional target filename.")
    surface_id: str | None = Field(None, description="Optional target surface filter.")
    priority: str | None = Field(None, description="Optional target priority filter.")
    binary_kind: str | None = Field(None, description="Optional binary kind filter.")
    min_ranking_weight: int | None = Field(
        None,
        description="Optional minimum ranking weight among joined surfaces.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact target-surface evidence node to the KB.",
    )


class TargetSurfaceSemantics(BaseModel):
    id: str
    boundary: str | None = None
    attacker_classes: list[str] = Field(default_factory=list)
    validation_requirements: list[str] = Field(default_factory=list)
    ranking_weight: int | None = None
    notes: str | None = None
    missing: bool = False


class TargetSurfaceProfile(BaseModel):
    target_id: str
    filename: str
    binary_kind: str
    priority: str
    scan_roles: list[str]
    surfaces: list[TargetSurfaceSemantics]
    validation_requirements: list[str]
    attacker_classes: list[str]
    max_ranking_weight: int | None = None
    notes: str | None = None


class WindowsTargetSurfaceProfileResult(BaseModel):
    manifest_path: str
    surfaces_path: str
    target_count_total: int
    surface_count_total: int
    profiles: list[TargetSurfaceProfile]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsTargetSurfaceProfileTool(
    MemoryTool[WindowsTargetSurfaceProfileArgs, WindowsTargetSurfaceProfileResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_target_surface_profile",
                description=(
                    "Join ASB Windows build-corpus targets to surface semantics "
                    "to expose defensive validation requirements per binary."
                ),
                tags=("windows", "pe", "metadata", "corpus", "surface"),
            ),
            WindowsTargetSurfaceProfileArgs,
            WindowsTargetSurfaceProfileResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsTargetSurfaceProfileArgs,
    ) -> WindowsTargetSurfaceProfileResult:
        manifest_path = _resolve_metadata_path(
            args.manifest_path,
            "data/kg/pe-build-corpus.yaml",
        )
        surfaces_path = _resolve_metadata_path(
            args.surfaces_path,
            "data/kg/pe-surfaces.yaml",
        )
        targets = [_target_record(entry, manifest_path) for entry in _load_yaml_list(manifest_path)]
        surfaces = {
            surface["id"]: surface
            for surface in (
                _surface_record(entry, surfaces_path)
                for entry in _load_yaml_list(surfaces_path)
            )
        }
        target_count_total = len(targets)
        surface_count_total = len(surfaces)
        profiles = [_profile_target(target, surfaces) for target in targets]
        profiles = _filter_profiles(profiles, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_target_surface_profile",
                    props={
                        "target_id": args.target_id,
                        "filename": args.filename,
                        "surface_id": args.surface_id,
                        "priority": args.priority,
                        "binary_kind": args.binary_kind,
                        "profile_matches": len(profiles),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsTargetSurfaceProfileResult(
            manifest_path=str(manifest_path),
            surfaces_path=str(surfaces_path),
            target_count_total=target_count_total,
            surface_count_total=surface_count_total,
            profiles=profiles,
            evidence_node_id=evidence_node_id,
            notes=[
                "target surface profiles are prioritization context, not per-function reachability proof"
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: entry {idx} is not a mapping")
        out.append(entry)
    return out


def _target_record(entry: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "id": _required_str(entry, "id", path),
        "filename": _required_str(entry, "filename", path),
        "binary_kind": _required_str(entry, "binary_kind", path),
        "priority": _required_str(entry, "priority", path),
        "scan_roles": _required_str_list(entry, "scan_roles", path),
        "surfaces": _required_str_list(entry, "surfaces", path),
        "notes": str(entry.get("notes") or ""),
    }


def _surface_record(entry: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "id": _required_str(entry, "id", path),
        "boundary": _required_str(entry, "boundary", path),
        "attacker_classes": _required_str_list(entry, "attacker_classes", path),
        "validation_requirements": _required_str_list(
            entry,
            "validation_requirements",
            path,
        ),
        "ranking_weight": int(entry.get("ranking_weight", 0)),
        "notes": str(entry.get("notes") or ""),
    }


def _profile_target(
    target: dict[str, Any],
    surfaces: dict[str, dict[str, Any]],
) -> TargetSurfaceProfile:
    surface_semantics = [
        _surface_semantics(surface_id, surfaces.get(surface_id))
        for surface_id in target["surfaces"]
    ]
    validation_requirements = sorted(
        {
            requirement
            for surface in surface_semantics
            for requirement in surface.validation_requirements
        }
    )
    attacker_classes = sorted(
        {
            attacker_class
            for surface in surface_semantics
            for attacker_class in surface.attacker_classes
        }
    )
    weights = [
        surface.ranking_weight
        for surface in surface_semantics
        if surface.ranking_weight is not None
    ]
    return TargetSurfaceProfile(
        target_id=target["id"],
        filename=target["filename"],
        binary_kind=target["binary_kind"],
        priority=target["priority"],
        scan_roles=target["scan_roles"],
        surfaces=surface_semantics,
        validation_requirements=validation_requirements,
        attacker_classes=attacker_classes,
        max_ranking_weight=max(weights) if weights else None,
        notes=target.get("notes"),
    )


def _surface_semantics(
    surface_id: str,
    raw: dict[str, Any] | None,
) -> TargetSurfaceSemantics:
    if raw is None:
        return TargetSurfaceSemantics(id=surface_id, missing=True)
    return TargetSurfaceSemantics(
        id=surface_id,
        boundary=raw["boundary"],
        attacker_classes=raw["attacker_classes"],
        validation_requirements=raw["validation_requirements"],
        ranking_weight=raw["ranking_weight"],
        notes=raw.get("notes"),
    )


def _filter_profiles(
    profiles: list[TargetSurfaceProfile],
    args: WindowsTargetSurfaceProfileArgs,
) -> list[TargetSurfaceProfile]:
    out = profiles
    if args.target_id:
        out = [profile for profile in out if profile.target_id == args.target_id]
    if args.filename:
        filename = args.filename.lower()
        out = [profile for profile in out if profile.filename.lower() == filename]
    if args.surface_id:
        out = [
            profile
            for profile in out
            if any(surface.id == args.surface_id for surface in profile.surfaces)
        ]
    if args.priority:
        out = [profile for profile in out if profile.priority == args.priority]
    if args.binary_kind:
        out = [profile for profile in out if profile.binary_kind == args.binary_kind]
    if args.min_ranking_weight is not None:
        out = [
            profile
            for profile in out
            if (profile.max_ranking_weight or 0) >= args.min_ranking_weight
        ]
    return out


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
    WindowsTargetSurfaceProfileArgs,
    WindowsTargetSurfaceProfileResult,
]:
    return WindowsTargetSurfaceProfileTool()
