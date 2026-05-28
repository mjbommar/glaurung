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


class WindowsComponentProfileArgs(BaseModel):
    profiles_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-component-profiles.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(None, description="Optional build-corpus target id filter.")
    component: str | None = Field(None, description="Optional component filename filter.")
    priority: str | None = Field(None, description="Optional priority filter.")
    surface_id: str | None = Field(None, description="Optional attacker surface filter.")
    attacker_class: str | None = Field(None, description="Optional caller class filter.")
    required_gate: str | None = Field(None, description="Optional required-gate filter.")
    initial_rule: str | None = Field(None, description="Optional initial rule filter.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact component-profile evidence node to the KB.",
    )


class ComponentEntrypoint(BaseModel):
    kind: str
    symbols: list[str]
    source_roles: list[str]
    notes: str | None = None


class ComponentProfileRecord(BaseModel):
    id: str
    target_id: str
    component: str
    priority: str
    surfaces: list[str]
    attacker_classes: list[str]
    entrypoints: list[ComponentEntrypoint]
    required_gates: list[str]
    validation_requirements: list[str]
    harness_strategy: list[str]
    initial_rules: list[str]
    evidence_packet_fields: list[str]
    notes: str | None = None


class WindowsComponentProfileResult(BaseModel):
    profiles_path: str
    profile_count_total: int
    profiles: list[ComponentProfileRecord]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsComponentProfileTool(
    MemoryTool[WindowsComponentProfileArgs, WindowsComponentProfileResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_component_profile",
                description=(
                    "Load ASB high-risk Windows component profiles with "
                    "entrypoints, required gates, validation checklists, and "
                    "VM harness strategy."
                ),
                tags=("windows", "pe", "metadata", "component", "validation"),
            ),
            WindowsComponentProfileArgs,
            WindowsComponentProfileResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsComponentProfileArgs,
    ) -> WindowsComponentProfileResult:
        profiles_path = _resolve_metadata_path(
            args.profiles_path,
            "data/kg/pe-component-profiles.yaml",
        )
        profiles = [_profile_record(entry, profiles_path) for entry in _load_yaml_list(profiles_path)]
        profile_count_total = len(profiles)
        profiles = _filter_profiles(profiles, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_component_profile",
                    props={
                        "target_id": args.target_id,
                        "component": args.component,
                        "priority": args.priority,
                        "surface_id": args.surface_id,
                        "attacker_class": args.attacker_class,
                        "profile_matches": len(profiles),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsComponentProfileResult(
            profiles_path=str(profiles_path),
            profile_count_total=profile_count_total,
            profiles=profiles,
            evidence_node_id=evidence_node_id,
            notes=[
                "component profiles are routing and validation plans, not vulnerability verdicts"
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: component profile entry {idx} is not a mapping")
        out.append(entry)
    return out


def _profile_record(entry: dict[str, Any], path: Path) -> ComponentProfileRecord:
    entrypoints = [
        _entrypoint_record(raw_entrypoint, path, entry.get("id"))
        for raw_entrypoint in entry.get("entrypoints") or []
    ]
    if not entrypoints:
        raise ValueError(f"{path}: component profile {entry.get('id')!r} has no entrypoints")
    return ComponentProfileRecord(
        id=_required_str(entry, "id", path),
        target_id=_required_str(entry, "target_id", path),
        component=_required_str(entry, "component", path),
        priority=_required_str(entry, "priority", path),
        surfaces=_required_str_list(entry, "surfaces", path),
        attacker_classes=_required_str_list(entry, "attacker_classes", path),
        entrypoints=entrypoints,
        required_gates=_required_str_list(entry, "required_gates", path),
        validation_requirements=_required_str_list(
            entry,
            "validation_requirements",
            path,
        ),
        harness_strategy=_required_str_list(entry, "harness_strategy", path),
        initial_rules=_required_str_list(entry, "initial_rules", path),
        evidence_packet_fields=_required_str_list(
            entry,
            "evidence_packet_fields",
            path,
        ),
        notes=str(entry.get("notes") or ""),
    )


def _entrypoint_record(raw: Any, path: Path, owner: Any) -> ComponentEntrypoint:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: entrypoint for profile {owner!r} is not a mapping")
    return ComponentEntrypoint(
        kind=_required_str(raw, "kind", path),
        symbols=_required_str_list(raw, "symbols", path),
        source_roles=_required_str_list(raw, "source_roles", path),
        notes=str(raw.get("notes") or ""),
    )


def _filter_profiles(
    profiles: list[ComponentProfileRecord],
    args: WindowsComponentProfileArgs,
) -> list[ComponentProfileRecord]:
    out = profiles
    if args.target_id:
        out = [profile for profile in out if profile.target_id == args.target_id]
    if args.component:
        needle = args.component.lower()
        out = [profile for profile in out if profile.component.lower() == needle]
    if args.priority:
        out = [profile for profile in out if profile.priority == args.priority]
    if args.surface_id:
        out = [profile for profile in out if args.surface_id in profile.surfaces]
    if args.attacker_class:
        out = [
            profile
            for profile in out
            if args.attacker_class in profile.attacker_classes
        ]
    if args.required_gate:
        out = [profile for profile in out if args.required_gate in profile.required_gates]
    if args.initial_rule:
        out = [profile for profile in out if args.initial_rule in profile.initial_rules]
    return out


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty {key!r}")
    out = [str(value) for value in values if str(value)]
    if len(out) != len(set(out)):
        raise ValueError(f"{path}: duplicate values in {key!r}")
    return out


def build_tool() -> WindowsComponentProfileTool:
    return WindowsComponentProfileTool()
