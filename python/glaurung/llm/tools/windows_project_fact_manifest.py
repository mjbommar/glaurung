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


class WindowsProjectFactManifestArgs(BaseModel):
    project_facts_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-project-facts.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(
        None, description="Optional build-corpus target id filter."
    )
    binary_filename: str | None = Field(
        None, description="Optional PE filename filter."
    )
    build_label: str | None = Field(
        None, description="Optional build/corpus label filter."
    )
    requires_fact: str | None = Field(
        None,
        description="Optional required project fact, e.g. call_xrefs or persisted_cfg.",
    )
    missing_fact: str | None = Field(
        None,
        description="Optional missing project fact filter, e.g. call_xrefs.",
    )
    min_function_names: int = Field(
        0,
        ge=0,
        description="Optional minimum persisted function-name count.",
    )
    min_call_xrefs: int = Field(
        0,
        ge=0,
        description="Optional minimum persisted call-xref count.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact project-fact manifest evidence node to the KB.",
    )


class ProjectFactCounts(BaseModel):
    function_name_count: int = 0
    xref_count: int = 0
    call_xref_count: int = 0
    data_read_xref_count: int = 0
    data_write_xref_count: int = 0
    data_label_count: int = 0
    function_prototype_count: int = 0
    basic_block_count: int = 0
    cfg_edge_count: int = 0
    cfg_dominance_count: int = 0
    cfg_branch_fact_count: int = 0
    function_boundary_count: int = 0
    function_chunk_fact_count: int = 0
    memory_operand_fact_count: int = 0
    sysinfo_dispatch_count: int = 0
    callsite_argument_fact_count: int = 0
    callsite_path_condition_count: int = 0


class ProjectFactRecord(BaseModel):
    id: str
    target_id: str
    build_label: str
    build_number: str
    architecture: str
    binary_filename: str
    project_path: str
    project_sha256: str | None = None
    project_size_bytes: int | None = None
    fact_sources: list[str] = Field(default_factory=list)
    fact_coverage: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    counts: ProjectFactCounts
    notes: str | None = None


class WindowsProjectFactManifestResult(BaseModel):
    project_facts_path: str
    record_count_total: int
    records_with_call_xrefs_total: int
    records_with_cfg_total: int
    records: list[ProjectFactRecord]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectFactManifestTool(
    MemoryTool[WindowsProjectFactManifestArgs, WindowsProjectFactManifestResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_fact_manifest",
                description=(
                    "Load ASB .glaurung project fact coverage so agents can "
                    "decide whether function, xref, callsite, prototype, or "
                    "CFG facts are available for a Windows target build."
                ),
                tags=("windows", "pe", "project", "metadata", "xrefs", "cfg"),
            ),
            WindowsProjectFactManifestArgs,
            WindowsProjectFactManifestResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectFactManifestArgs,
    ) -> WindowsProjectFactManifestResult:
        project_facts_path = _resolve_metadata_path(
            args.project_facts_path,
            "data/kg/pe-project-facts.yaml",
        )
        records = [
            _record(entry, project_facts_path)
            for entry in _load_yaml_list(project_facts_path)
        ]
        record_count_total = len(records)
        records_with_call_xrefs_total = sum(
            record.counts.call_xref_count > 0 for record in records
        )
        records_with_cfg_total = sum(
            record.counts.cfg_edge_count > 0 for record in records
        )
        records = _filter_records(records, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_fact_manifest",
                    props={
                        "target_id": args.target_id,
                        "binary_filename": args.binary_filename,
                        "build_label": args.build_label,
                        "requires_fact": args.requires_fact,
                        "missing_fact": args.missing_fact,
                        "record_matches": len(records),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectFactManifestResult(
            project_facts_path=str(project_facts_path),
            record_count_total=record_count_total,
            records_with_call_xrefs_total=records_with_call_xrefs_total,
            records_with_cfg_total=records_with_cfg_total,
            records=records,
            evidence_node_id=evidence_node_id,
            notes=[
                "project fact records describe available analysis substrate, not vulnerability reachability"
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: project fact entry {idx} is not a mapping")
        out.append(entry)
    return out


def _record(entry: dict[str, Any], path: Path) -> ProjectFactRecord:
    counts_raw = entry.get("counts")
    if not isinstance(counts_raw, dict):
        raise ValueError(f"{path}: project fact {entry.get('id')!r} missing counts")
    return ProjectFactRecord(
        id=_required_str(entry, "id", path),
        target_id=_required_str(entry, "target_id", path),
        build_label=_required_str(entry, "build_label", path),
        build_number=_required_str(entry, "build_number", path),
        architecture=_required_str(entry, "architecture", path),
        binary_filename=_required_str(entry, "binary_filename", path),
        project_path=_required_str(entry, "project_path", path),
        project_sha256=_optional_str(entry.get("project_sha256")),
        project_size_bytes=_optional_int(entry.get("project_size_bytes")),
        fact_sources=[str(x) for x in entry.get("fact_sources") or []],
        fact_coverage=[str(x) for x in entry.get("fact_coverage") or []],
        missing_facts=[str(x) for x in entry.get("missing_facts") or []],
        counts=ProjectFactCounts(
            function_name_count=int(counts_raw.get("function_name_count") or 0),
            xref_count=int(counts_raw.get("xref_count") or 0),
            call_xref_count=int(counts_raw.get("call_xref_count") or 0),
            data_read_xref_count=int(counts_raw.get("data_read_xref_count") or 0),
            data_write_xref_count=int(counts_raw.get("data_write_xref_count") or 0),
            data_label_count=int(counts_raw.get("data_label_count") or 0),
            function_prototype_count=int(
                counts_raw.get("function_prototype_count") or 0
            ),
            basic_block_count=int(counts_raw.get("basic_block_count") or 0),
            cfg_edge_count=int(counts_raw.get("cfg_edge_count") or 0),
            cfg_dominance_count=int(counts_raw.get("cfg_dominance_count") or 0),
            cfg_branch_fact_count=int(counts_raw.get("cfg_branch_fact_count") or 0),
            function_boundary_count=int(counts_raw.get("function_boundary_count") or 0),
            function_chunk_fact_count=int(
                counts_raw.get("function_chunk_fact_count") or 0
            ),
            memory_operand_fact_count=int(
                counts_raw.get("memory_operand_fact_count") or 0
            ),
            sysinfo_dispatch_count=int(counts_raw.get("sysinfo_dispatch_count") or 0),
            callsite_argument_fact_count=int(
                counts_raw.get("callsite_argument_fact_count") or 0
            ),
            callsite_path_condition_count=int(
                counts_raw.get("callsite_path_condition_count") or 0
            ),
        ),
        notes=str(entry.get("notes") or ""),
    )


def _filter_records(
    records: list[ProjectFactRecord],
    args: WindowsProjectFactManifestArgs,
) -> list[ProjectFactRecord]:
    out = records
    if args.target_id:
        out = [record for record in out if record.target_id == args.target_id]
    if args.binary_filename:
        needle = args.binary_filename.lower()
        out = [record for record in out if record.binary_filename.lower() == needle]
    if args.build_label:
        out = [record for record in out if record.build_label == args.build_label]
    if args.requires_fact:
        out = [record for record in out if args.requires_fact in record.fact_coverage]
    if args.missing_fact:
        out = [record for record in out if args.missing_fact in record.missing_facts]
    if args.min_function_names:
        out = [
            record
            for record in out
            if record.counts.function_name_count >= args.min_function_names
        ]
    if args.min_call_xrefs:
        out = [
            record
            for record in out
            if record.counts.call_xref_count >= args.min_call_xrefs
        ]
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


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def build_tool() -> WindowsProjectFactManifestTool:
    return WindowsProjectFactManifestTool()
