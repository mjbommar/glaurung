from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


CacheStatus = Literal["cached", "missing_from_cache", "needs_extraction"]


class WindowsPdbIdentityManifestArgs(BaseModel):
    identity_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-identity-manifest.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(None, description="Optional build-corpus target id filter.")
    binary_filename: str | None = Field(None, description="Optional PE filename filter.")
    pdb_name: str | None = Field(None, description="Optional expected PDB filename filter.")
    build_label: str | None = Field(None, description="Optional build/corpus label filter.")
    cache_status: CacheStatus | None = Field(None, description="Optional PDB cache status filter.")
    requires_fact: str | None = Field(
        None,
        description="Optional fact coverage requirement, e.g. pdb_type_layouts.",
    )
    missing_fact: str | None = Field(
        None,
        description="Optional missing fact filter, e.g. cached_pdb.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact PDB identity evidence node to the KB.",
    )


class PdbIdentityRecord(BaseModel):
    id: str
    target_id: str
    build_label: str
    build_number: str
    architecture: str
    binary_filename: str
    expected_pdb_name: str
    codeview_guid_age: str | None = None
    cache_status: CacheStatus
    symbol_cache_path: str | None = None
    identity_sources: list[str] = Field(default_factory=list)
    fact_coverage: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsPdbIdentityManifestResult(BaseModel):
    identity_path: str
    record_count_total: int
    cached_count_total: int
    missing_count_total: int
    records: list[PdbIdentityRecord]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsPdbIdentityManifestTool(
    MemoryTool[WindowsPdbIdentityManifestArgs, WindowsPdbIdentityManifestResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_pdb_identity_manifest",
                description=(
                    "Load ASB Windows PE/PDB identity coverage so agents can "
                    "decide whether PDB symbols, type layouts, and prototypes "
                    "are available for a target build."
                ),
                tags=("windows", "pe", "pdb", "identity", "metadata"),
            ),
            WindowsPdbIdentityManifestArgs,
            WindowsPdbIdentityManifestResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsPdbIdentityManifestArgs,
    ) -> WindowsPdbIdentityManifestResult:
        identity_path = _resolve_metadata_path(
            args.identity_path,
            "data/kg/pe-identity-manifest.yaml",
        )
        records = [_record(entry, identity_path) for entry in _load_yaml_list(identity_path)]
        record_count_total = len(records)
        cached_count_total = sum(record.cache_status == "cached" for record in records)
        missing_count_total = sum(record.cache_status != "cached" for record in records)
        records = _filter_records(records, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_pdb_identity_manifest",
                    props={
                        "target_id": args.target_id,
                        "binary_filename": args.binary_filename,
                        "pdb_name": args.pdb_name,
                        "build_label": args.build_label,
                        "cache_status": args.cache_status,
                        "record_matches": len(records),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsPdbIdentityManifestResult(
            identity_path=str(identity_path),
            record_count_total=record_count_total,
            cached_count_total=cached_count_total,
            missing_count_total=missing_count_total,
            records=records,
            evidence_node_id=evidence_node_id,
            notes=[
                "PDB identity records describe available symbol/type backing, not vulnerability reachability"
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: identity entry {idx} is not a mapping")
        out.append(entry)
    return out


def _record(entry: dict[str, Any], path: Path) -> PdbIdentityRecord:
    cache_status = _required_str(entry, "cache_status", path)
    if cache_status not in {"cached", "missing_from_cache", "needs_extraction"}:
        raise ValueError(f"{path}: bad cache_status {cache_status!r}")
    return PdbIdentityRecord(
        id=_required_str(entry, "id", path),
        target_id=_required_str(entry, "target_id", path),
        build_label=_required_str(entry, "build_label", path),
        build_number=_required_str(entry, "build_number", path),
        architecture=_required_str(entry, "architecture", path),
        binary_filename=_required_str(entry, "binary_filename", path),
        expected_pdb_name=_required_str(entry, "expected_pdb_name", path),
        codeview_guid_age=_optional_str(entry.get("codeview_guid_age")),
        cache_status=cache_status,  # type: ignore[arg-type]
        symbol_cache_path=_optional_str(entry.get("symbol_cache_path")),
        identity_sources=[str(x) for x in entry.get("identity_sources") or []],
        fact_coverage=[str(x) for x in entry.get("fact_coverage") or []],
        missing_facts=[str(x) for x in entry.get("missing_facts") or []],
        notes=str(entry.get("notes") or ""),
    )


def _filter_records(
    records: list[PdbIdentityRecord],
    args: WindowsPdbIdentityManifestArgs,
) -> list[PdbIdentityRecord]:
    out = records
    if args.target_id:
        out = [record for record in out if record.target_id == args.target_id]
    if args.binary_filename:
        needle = args.binary_filename.lower()
        out = [record for record in out if record.binary_filename.lower() == needle]
    if args.pdb_name:
        needle = args.pdb_name.lower()
        out = [record for record in out if record.expected_pdb_name.lower() == needle]
    if args.build_label:
        out = [record for record in out if record.build_label == args.build_label]
    if args.cache_status:
        out = [record for record in out if record.cache_status == args.cache_status]
    if args.requires_fact:
        out = [record for record in out if args.requires_fact in record.fact_coverage]
    if args.missing_fact:
        out = [record for record in out if args.missing_fact in record.missing_facts]
    return out


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def build_tool() -> WindowsPdbIdentityManifestTool:
    return WindowsPdbIdentityManifestTool()
