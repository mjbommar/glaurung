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


class WindowsGhidraDeltaManifestArgs(BaseModel):
    ghidra_delta_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-ghidra-delta.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(None, description="Optional build-corpus target id filter.")
    component: str | None = Field(None, description="Optional component filename filter.")
    build_label: str | None = Field(None, description="Optional build/corpus label filter.")
    fact_class: str | None = Field(
        None,
        description="Optional fact-class filter such as cfg_path or type_layout.",
    )
    coverage_state: str | None = Field(
        None,
        description="Optional coverage-state filter such as present, partial, or missing.",
    )
    blocking_only: bool = Field(
        False,
        description="If true, return only entries marked as blocking automated triage.",
    )
    max_records: int = Field(
        64,
        ge=1,
        le=512,
        description="Maximum matching records to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact Ghidra-delta evidence node to the KB.",
    )


class GhidraDeltaRecord(BaseModel):
    id: str
    target_id: str
    component: str
    build_label: str
    fact_class: str
    coverage_state: str
    blocking: bool = False
    ghidra_baseline: str
    glaurung_status: str
    current_capabilities: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsGhidraDeltaManifestResult(BaseModel):
    ghidra_delta_path: str
    record_count_total: int
    blocking_gap_count_total: int
    records: list[GhidraDeltaRecord]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsGhidraDeltaManifestTool(
    MemoryTool[WindowsGhidraDeltaManifestArgs, WindowsGhidraDeltaManifestResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_ghidra_delta_manifest",
                description=(
                    "Load ASB Ghidra-parity gap records so agents can see "
                    "which Windows fact classes are present, partial, missing, "
                    "or blocking automated triage."
                ),
                tags=("windows", "pe", "metadata", "ghidra", "parity"),
            ),
            WindowsGhidraDeltaManifestArgs,
            WindowsGhidraDeltaManifestResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsGhidraDeltaManifestArgs,
    ) -> WindowsGhidraDeltaManifestResult:
        ghidra_delta_path = _resolve_metadata_path(
            args.ghidra_delta_path,
            "data/kg/pe-ghidra-delta.yaml",
        )
        records = [
            _record(entry, ghidra_delta_path)
            for entry in _load_yaml_list(ghidra_delta_path)
        ]
        record_count_total = len(records)
        blocking_gap_count_total = sum(record.blocking for record in records)
        records = _filter_records(records, args)[: args.max_records]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_ghidra_delta_manifest",
                    props={
                        "target_id": args.target_id,
                        "component": args.component,
                        "build_label": args.build_label,
                        "fact_class": args.fact_class,
                        "coverage_state": args.coverage_state,
                        "blocking_only": args.blocking_only,
                        "record_matches": len(records),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsGhidraDeltaManifestResult(
            ghidra_delta_path=str(ghidra_delta_path),
            record_count_total=record_count_total,
            blocking_gap_count_total=blocking_gap_count_total,
            records=records,
            evidence_node_id=evidence_node_id,
            notes=[
                "Ghidra-delta records are capability gaps, not vulnerability verdicts"
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: Ghidra-delta entry {idx} is not a mapping")
        out.append(entry)
    return out


def _record(entry: dict[str, Any], path: Path) -> GhidraDeltaRecord:
    return GhidraDeltaRecord(
        id=_required_str(entry, "id", path),
        target_id=_required_str(entry, "target_id", path),
        component=_required_str(entry, "component", path),
        build_label=_required_str(entry, "build_label", path),
        fact_class=_required_str(entry, "fact_class", path),
        coverage_state=_required_str(entry, "coverage_state", path),
        blocking=bool(entry.get("blocking")),
        ghidra_baseline=_required_str(entry, "ghidra_baseline", path),
        glaurung_status=_required_str(entry, "glaurung_status", path),
        current_capabilities=[str(x) for x in entry.get("current_capabilities") or []],
        missing_capabilities=[str(x) for x in entry.get("missing_capabilities") or []],
        next_actions=[str(x) for x in entry.get("next_actions") or []],
        evidence=[str(x) for x in entry.get("evidence") or []],
        notes=str(entry.get("notes") or ""),
    )


def _filter_records(
    records: list[GhidraDeltaRecord],
    args: WindowsGhidraDeltaManifestArgs,
) -> list[GhidraDeltaRecord]:
    out = records
    if args.target_id:
        out = [record for record in out if record.target_id == args.target_id]
    if args.component:
        needle = args.component.lower()
        out = [record for record in out if record.component.lower() == needle]
    if args.build_label:
        out = [record for record in out if record.build_label == args.build_label]
    if args.fact_class:
        out = [record for record in out if record.fact_class == args.fact_class]
    if args.coverage_state:
        out = [record for record in out if record.coverage_state == args.coverage_state]
    if args.blocking_only:
        out = [record for record in out if record.blocking]
    return out


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def build_tool() -> WindowsGhidraDeltaManifestTool:
    return WindowsGhidraDeltaManifestTool()
