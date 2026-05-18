from __future__ import annotations

import struct
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_pdb_identity_manifest import (
    PdbIdentityRecord,
    _load_yaml_list,
    _record,
)
from .windows_surface_metadata import _resolve_metadata_path


ManifestStatus = Literal[
    "not_checked",
    "no_matching_record",
    "match",
    "pdb_name_mismatch",
    "guid_age_mismatch",
    "cache_status_mismatch",
]
LiveCacheStatus = Literal["cached", "missing_from_cache", "unknown"]


class WindowsReconcilePdbIdentityArgs(BaseModel):
    pe_path: str = Field(..., description="Path to a PE binary to inspect for CodeView RSDS.")
    pdb_cache_dir: str | None = Field(
        None,
        description="Optional Microsoft-style PDB cache directory to check for a matching PDB.",
    )
    identity_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-identity-manifest.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(None, description="Optional manifest target id filter.")
    build_label: str | None = Field(None, description="Optional manifest build label filter.")
    struct_names: list[str] = Field(
        default_factory=list,
        description="Optional PDB struct/class names to request when cache analysis succeeds.",
    )
    analyze_types: bool = Field(
        True,
        description="If true, ask native PDB ingestion for counts when a cache hit is available.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact live PDB identity evidence node to the KB.",
    )


class LiveCodeViewIdentity(BaseModel):
    pdb_path: str
    pdb_name: str
    pdb_guid: str
    pdb_age: int
    pdb_guid_age: str


class LivePdbCacheSummary(BaseModel):
    cache_dir: str | None = None
    expected_symbol_cache_path: str | None = None
    flat_cache_path: str | None = None
    resolved_pdb_path: str | None = None
    cache_status: LiveCacheStatus = "unknown"


class LivePdbFactSummary(BaseModel):
    analysis_attempted: bool = False
    cache_hit: bool = False
    struct_layout_count: int = 0
    function_prototype_count: int = 0
    public_symbol_count: int = 0
    requested_structs_found: list[str] = Field(default_factory=list)
    fact_coverage: list[str] = Field(default_factory=list)


class PdbIdentityManifestComparison(BaseModel):
    status: ManifestStatus
    record: PdbIdentityRecord | None = None
    issues: list[str] = Field(default_factory=list)


class WindowsReconcilePdbIdentityResult(BaseModel):
    pe_path: str
    binary_filename: str
    codeview: LiveCodeViewIdentity | None = None
    cache: LivePdbCacheSummary
    pdb_facts: LivePdbFactSummary
    manifest: PdbIdentityManifestComparison
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsReconcilePdbIdentityTool(
    MemoryTool[WindowsReconcilePdbIdentityArgs, WindowsReconcilePdbIdentityResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_reconcile_pdb_identity",
                description=(
                    "Extract live CodeView/PDB identity from a PE, check local "
                    "PDB cache state, and compare it with ASB's identity manifest."
                ),
                tags=("windows", "pe", "pdb", "identity", "metadata"),
            ),
            WindowsReconcilePdbIdentityArgs,
            WindowsReconcilePdbIdentityResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsReconcilePdbIdentityArgs,
    ) -> WindowsReconcilePdbIdentityResult:
        pe_path = Path(args.pe_path)
        notes: list[str] = []
        codeview = _extract_codeview(pe_path, notes)
        cache = _cache_summary(codeview, args.pdb_cache_dir)
        pdb_facts = _pdb_fact_summary(pe_path, args, cache, notes)
        manifest = _compare_manifest(codeview, pe_path.name, args, cache, notes)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_reconcile_pdb_identity",
                    props={
                        "pe_path": str(pe_path),
                        "pdb_name": codeview.pdb_name if codeview else None,
                        "pdb_guid_age": codeview.pdb_guid_age if codeview else None,
                        "cache_status": cache.cache_status,
                        "manifest_status": manifest.status,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsReconcilePdbIdentityResult(
            pe_path=str(pe_path),
            binary_filename=pe_path.name,
            codeview=codeview,
            cache=cache,
            pdb_facts=pdb_facts,
            manifest=manifest,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _extract_codeview(path: Path, notes: list[str]) -> LiveCodeViewIdentity | None:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ValueError(f"{path}: unable to read PE bytes: {error}") from error

    marker = data.find(b"RSDS")
    if marker < 0:
        notes.append("no CodeView RSDS record found")
        return None
    record = data[marker:]
    if len(record) < 25:
        notes.append("truncated CodeView RSDS record")
        return None

    guid_bytes = record[4:20]
    age = struct.unpack_from("<I", record, 20)[0]
    path_bytes = record[24:].split(b"\x00", 1)[0]
    try:
        pdb_path = path_bytes.decode("utf-8")
    except UnicodeDecodeError:
        pdb_path = path_bytes.decode("latin-1", errors="replace")
        notes.append("CodeView PDB path was not valid UTF-8")

    pdb_name = _pdb_basename(pdb_path)
    pdb_guid = _format_codeview_guid(guid_bytes)
    return LiveCodeViewIdentity(
        pdb_path=pdb_path,
        pdb_name=pdb_name,
        pdb_guid=pdb_guid,
        pdb_age=age,
        pdb_guid_age=f"{pdb_guid}{age:X}",
    )


def _cache_summary(
    codeview: LiveCodeViewIdentity | None,
    cache_dir: str | None,
) -> LivePdbCacheSummary:
    if codeview is None or not cache_dir:
        return LivePdbCacheSummary(cache_dir=cache_dir)

    root = Path(cache_dir)
    expected = root / codeview.pdb_name / codeview.pdb_guid_age / codeview.pdb_name
    flat = root / codeview.pdb_name
    resolved = next((path for path in (expected, flat) if path.is_file()), None)
    return LivePdbCacheSummary(
        cache_dir=str(root),
        expected_symbol_cache_path=str(expected),
        flat_cache_path=str(flat),
        resolved_pdb_path=str(resolved) if resolved else None,
        cache_status="cached" if resolved else "missing_from_cache",
    )


def _pdb_fact_summary(
    pe_path: Path,
    args: WindowsReconcilePdbIdentityArgs,
    cache: LivePdbCacheSummary,
    notes: list[str],
) -> LivePdbFactSummary:
    if not args.analyze_types or not args.pdb_cache_dir or cache.cache_status != "cached":
        return LivePdbFactSummary()

    summary = LivePdbFactSummary(analysis_attempted=True)
    try:
        import glaurung as g

        analysis = g.debug.analyze_pe_pdb_cache_path(
            str(pe_path),
            args.pdb_cache_dir,
            args.struct_names,
        )
    except Exception as error:  # pragma: no cover - native error types vary.
        notes.append(f"PDB cache analysis failed: {error}")
        return summary

    if not analysis.get("cache_hit"):
        return summary

    struct_layouts = list(analysis.get("struct_layouts") or [])
    prototypes = list(analysis.get("function_prototypes") or [])
    public_symbols = list(analysis.get("public_symbols") or [])
    coverage = []
    if public_symbols:
        coverage.extend(["pdb_public_symbols", "pdb_function_names"])
    if struct_layouts:
        coverage.append("pdb_type_layouts")
    if prototypes:
        coverage.append("pdb_function_prototypes")
    return LivePdbFactSummary(
        analysis_attempted=True,
        cache_hit=True,
        struct_layout_count=len(struct_layouts),
        function_prototype_count=len(prototypes),
        public_symbol_count=len(public_symbols),
        requested_structs_found=[
            str(layout.get("name")) for layout in struct_layouts if layout.get("name")
        ],
        fact_coverage=coverage,
    )


def _compare_manifest(
    codeview: LiveCodeViewIdentity | None,
    binary_filename: str,
    args: WindowsReconcilePdbIdentityArgs,
    cache: LivePdbCacheSummary,
    notes: list[str],
) -> PdbIdentityManifestComparison:
    if args.identity_path is None and not (args.target_id or args.build_label):
        return PdbIdentityManifestComparison(status="not_checked")

    identity_path = _resolve_metadata_path(
        args.identity_path,
        "data/kg/pe-identity-manifest.yaml",
    )
    records = [_record(entry, identity_path) for entry in _load_yaml_list(identity_path)]
    record = _matching_record(records, binary_filename, codeview, args)
    if record is None:
        return PdbIdentityManifestComparison(
            status="no_matching_record",
            issues=[f"no manifest record matched {binary_filename}"],
        )

    issues: list[str] = []
    if codeview is not None:
        if record.expected_pdb_name.lower() != codeview.pdb_name.lower():
            issues.append(
                f"manifest expected {record.expected_pdb_name}, live PE has {codeview.pdb_name}"
            )
        if record.codeview_guid_age and record.codeview_guid_age != codeview.pdb_guid_age:
            issues.append(
                f"manifest GUID+age {record.codeview_guid_age} != live {codeview.pdb_guid_age}"
            )
        if record.cache_status == "cached" and cache.cache_status == "missing_from_cache":
            issues.append("manifest says cached but live cache path is missing")
        if record.cache_status != "cached" and cache.cache_status == "cached":
            issues.append("manifest says not cached but live cache path exists")

    if not issues:
        return PdbIdentityManifestComparison(status="match", record=record)

    notes.append("live PE/PDB identity differs from ASB manifest")
    if any("expected" in issue for issue in issues):
        status: ManifestStatus = "pdb_name_mismatch"
    elif any("GUID+age" in issue for issue in issues):
        status = "guid_age_mismatch"
    else:
        status = "cache_status_mismatch"
    return PdbIdentityManifestComparison(status=status, record=record, issues=issues)


def _matching_record(
    records: list[PdbIdentityRecord],
    binary_filename: str,
    codeview: LiveCodeViewIdentity | None,
    args: WindowsReconcilePdbIdentityArgs,
) -> PdbIdentityRecord | None:
    candidates = records
    if args.target_id:
        candidates = [record for record in candidates if record.target_id == args.target_id]
    if args.build_label:
        candidates = [record for record in candidates if record.build_label == args.build_label]
    if codeview is not None:
        by_guid = [
            record
            for record in candidates
            if record.codeview_guid_age == codeview.pdb_guid_age
        ]
        if by_guid:
            return by_guid[0]
        by_pdb = [
            record
            for record in candidates
            if record.expected_pdb_name.lower() == codeview.pdb_name.lower()
        ]
        if by_pdb:
            return by_pdb[0]
    by_binary = [
        record
        for record in candidates
        if record.binary_filename.lower() == binary_filename.lower()
    ]
    return by_binary[0] if by_binary else None


def _format_codeview_guid(guid: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", guid)
    tail = guid[8:].hex().upper()
    return f"{d1:08X}{d2:04X}{d3:04X}{tail}"


def _pdb_basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def build_tool() -> WindowsReconcilePdbIdentityTool:
    return WindowsReconcilePdbIdentityTool()
