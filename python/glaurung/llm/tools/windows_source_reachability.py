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


class WindowsSourceReachabilityArgs(BaseModel):
    sources_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sources.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    surfaces_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-surfaces.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    source_id: str | None = Field(None, description="Optional source id filter.")
    symbol: str | None = Field(
        None,
        description="Optional source symbol filter, e.g. NtDeviceIoControlFile.",
    )
    surface_id: str | None = Field(
        None,
        description="Optional surface id filter, e.g. syscall or ioctl.",
    )
    attacker_class: str | None = Field(
        None,
        description="Optional attacker class filter, e.g. windows-local-user.",
    )
    min_ranking_weight: int | None = Field(
        None,
        description="Optional minimum surface ranking weight filter.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact source-reachability evidence node to the KB.",
    )


class SourceReachabilityRole(BaseModel):
    index: int | None = None
    expression: str | None = None
    role: str
    paired_length: int | str | None = None
    selector: int | str | None = None


class SourceReachabilityRecord(BaseModel):
    source_id: str
    symbols: list[str]
    source_surface: str
    source_attacker_class: str
    roles: list[SourceReachabilityRole]
    surface_boundary: str | None = None
    surface_attacker_classes: list[str] = Field(default_factory=list)
    validation_requirements: list[str] = Field(default_factory=list)
    ranking_weight: int | None = None
    attacker_class_consistent: bool
    notes: list[str] = Field(default_factory=list)


class WindowsSourceReachabilityResult(BaseModel):
    sources_path: str
    surfaces_path: str
    source_count_total: int
    surface_count_total: int
    records: list[SourceReachabilityRecord]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSourceReachabilityTool(
    MemoryTool[WindowsSourceReachabilityArgs, WindowsSourceReachabilityResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_source_reachability",
                description=(
                    "Join ASB Windows source metadata to surface semantics "
                    "to expose attacker class and validation requirements."
                ),
                tags=("windows", "pe", "metadata", "source", "reachability"),
            ),
            WindowsSourceReachabilityArgs,
            WindowsSourceReachabilityResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSourceReachabilityArgs,
    ) -> WindowsSourceReachabilityResult:
        sources_path = _resolve_metadata_path(args.sources_path, "data/kg/pe-sources.yaml")
        surfaces_path = _resolve_metadata_path(
            args.surfaces_path,
            "data/kg/pe-surfaces.yaml",
        )
        sources = [_source_record(entry, sources_path) for entry in _load_yaml_list(sources_path)]
        surfaces = {
            surface["id"]: surface
            for surface in (
                _surface_record(entry, surfaces_path)
                for entry in _load_yaml_list(surfaces_path)
            )
        }

        source_count_total = len(sources)
        surface_count_total = len(surfaces)
        records = [_join_source_surface(source, surfaces) for source in sources]
        records = _filter_records(records, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_source_reachability",
                    props={
                        "source_id": args.source_id,
                        "symbol": args.symbol,
                        "surface_id": args.surface_id,
                        "attacker_class": args.attacker_class,
                        "record_matches": len(records),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSourceReachabilityResult(
            sources_path=str(sources_path),
            surfaces_path=str(surfaces_path),
            source_count_total=source_count_total,
            surface_count_total=surface_count_total,
            records=records,
            evidence_node_id=evidence_node_id,
            notes=[
                "source reachability context is metadata only; validate concrete path, policy, and build facts"
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


def _source_record(entry: dict[str, Any], path: Path) -> dict[str, Any]:
    roles = entry.get("roles") or []
    if not isinstance(roles, list) or not roles:
        raise ValueError(f"{path}: source {entry.get('id')!r} has no roles")
    return {
        "id": _required_str(entry, "id", path),
        "surface": _required_str(entry, "surface", path),
        "symbols": _required_str_list(entry, "symbols", path),
        "attacker_class": _required_str(entry, "attacker_class", path),
        "roles": [_source_role(role, path, entry.get("id")) for role in roles],
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


def _source_role(raw: Any, path: Path, owner: Any) -> SourceReachabilityRole:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: role for {owner!r} is not a mapping")
    if "index" in raw and "expression" in raw:
        raise ValueError(f"{path}: role for {owner!r} has both index and expression")
    role = raw.get("role")
    if not isinstance(role, str) or not role:
        raise ValueError(f"{path}: role for {owner!r} missing role")
    return SourceReachabilityRole(
        index=int(raw["index"]) if raw.get("index") is not None else None,
        expression=str(raw["expression"]) if raw.get("expression") is not None else None,
        role=role,
        paired_length=raw.get("paired_length"),
        selector=raw.get("selector"),
    )


def _join_source_surface(
    source: dict[str, Any],
    surfaces: dict[str, dict[str, Any]],
) -> SourceReachabilityRecord:
    surface = surfaces.get(source["surface"])
    if surface is None:
        return SourceReachabilityRecord(
            source_id=source["id"],
            symbols=source["symbols"],
            source_surface=source["surface"],
            source_attacker_class=source["attacker_class"],
            roles=source["roles"],
            attacker_class_consistent=False,
            notes=[f"unknown surface {source['surface']!r}"],
        )
    consistent = source["attacker_class"] in surface["attacker_classes"]
    notes: list[str] = []
    if not consistent:
        notes.append(
            f"source attacker class {source['attacker_class']!r} is not listed for surface {surface['id']!r}"
        )
    return SourceReachabilityRecord(
        source_id=source["id"],
        symbols=source["symbols"],
        source_surface=source["surface"],
        source_attacker_class=source["attacker_class"],
        roles=source["roles"],
        surface_boundary=surface["boundary"],
        surface_attacker_classes=surface["attacker_classes"],
        validation_requirements=surface["validation_requirements"],
        ranking_weight=surface["ranking_weight"],
        attacker_class_consistent=consistent,
        notes=notes,
    )


def _filter_records(
    records: list[SourceReachabilityRecord],
    args: WindowsSourceReachabilityArgs,
) -> list[SourceReachabilityRecord]:
    out = records
    if args.source_id:
        out = [record for record in out if record.source_id == args.source_id]
    if args.symbol:
        out = [record for record in out if args.symbol in record.symbols]
    if args.surface_id:
        out = [record for record in out if record.source_surface == args.surface_id]
    if args.attacker_class:
        out = [
            record
            for record in out
            if args.attacker_class == record.source_attacker_class
            or args.attacker_class in record.surface_attacker_classes
        ]
    if args.min_ranking_weight is not None:
        out = [
            record
            for record in out
            if (record.ranking_weight or 0) >= args.min_ranking_weight
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
    WindowsSourceReachabilityArgs,
    WindowsSourceReachabilityResult,
]:
    return WindowsSourceReachabilityTool()
