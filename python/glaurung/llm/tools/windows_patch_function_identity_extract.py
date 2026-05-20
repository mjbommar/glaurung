from __future__ import annotations

from pathlib import Path
import json
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_binary_diff_summary import (
    BinaryDiffRow,
    WindowsBinaryDiffSummaryArgs,
    WindowsBinaryDiffSummaryTool,
)
from .windows_pdb_identity_manifest import (
    PdbIdentityRecord,
    WindowsPdbIdentityManifestArgs,
    WindowsPdbIdentityManifestTool,
)


PatchFunctionMatchBasis = Literal[
    "name_based",
    "hash_based",
    "pdb_backed",
    "similarity_backed",
    "manual_review",
    "uncertain",
]


class WindowsExtractedPatchFunctionIdentity(BaseModel):
    function: str
    status: str = "changed"
    match_basis: PatchFunctionMatchBasis
    pdb_symbol: str | None = None
    pdb_guid_age: str | None = None
    similarity_score: float | None = Field(None, ge=0.0, le=1.0)
    similarity_algorithm: str | None = None
    functionization_blockers: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class WindowsExternalPatchFunctionSimilarity(BaseModel):
    function: str
    matched_function: str | None = None
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    similarity_algorithm: str = "external_similarity_manifest"
    evidence: list[str] = Field(default_factory=list)


class WindowsPatchFunctionIdentityExtractArgs(BaseModel):
    binary_a: str = Field(..., description="Pre-change binary path.")
    binary_b: str = Field(..., description="Post-change binary path.")
    pdb_identity_manifest: WindowsPdbIdentityManifestArgs | None = Field(
        None,
        description="Optional PDB identity manifest query to attach symbol backing.",
    )
    max_rows: int = Field(64, ge=0, le=512)
    min_similarity_score: float = Field(0.55, ge=0.0, le=1.0)
    external_similarity_manifest_path: str | None = Field(
        None,
        description=(
            "Optional JSON/YAML manifest from an external similarity system "
            "such as BSim. Entries override deterministic size/hash similarity "
            "per function."
        ),
    )
    identity_output_path: str | None = Field(
        None,
        description=(
            "Optional YAML path to write identities in the shape consumed by "
            "windows_patch_diff_review.function_identity_path."
        ),
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact patch-function identity evidence node.",
    )


class WindowsPatchFunctionIdentityExtractResult(BaseModel):
    binary_a: str
    binary_b: str
    diff_row_count: int
    identity_count: int
    pdb_identity_record_count: int = 0
    pdb_identity_manifest_path: str | None = None
    external_similarity_record_count: int = 0
    external_similarity_manifest_path: str | None = None
    identity_output_path: str | None = None
    identities: list[WindowsExtractedPatchFunctionIdentity]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsPatchFunctionIdentityExtractTool(
    MemoryTool[
        WindowsPatchFunctionIdentityExtractArgs,
        WindowsPatchFunctionIdentityExtractResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_patch_function_identity_extract",
                description=(
                    "Extract reusable per-function patch identity facts from a "
                    "binary diff, optional PDB identity metadata, and deterministic "
                    "size/hash similarity signals."
                ),
                tags=("windows", "pe", "patch", "diff", "pdb", "similarity"),
            ),
            WindowsPatchFunctionIdentityExtractArgs,
            WindowsPatchFunctionIdentityExtractResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsPatchFunctionIdentityExtractArgs,
    ) -> WindowsPatchFunctionIdentityExtractResult:
        diff = WindowsBinaryDiffSummaryTool().run(
            ctx,
            kb,
            WindowsBinaryDiffSummaryArgs(
                binary_a=args.binary_a,
                binary_b=args.binary_b,
                max_rows=args.max_rows,
                add_to_kb=False,
            ),
        )
        pdb_records, pdb_manifest_path = _pdb_records(ctx, kb, args)
        external_similarity = _load_external_similarity(
            args.external_similarity_manifest_path
        )
        identities = _identities(
            diff.rows,
            pdb_records=pdb_records,
            external_similarity=external_similarity,
            min_similarity_score=args.min_similarity_score,
        )
        output_path = _write_identities(args.identity_output_path, identities)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_patch_function_identity_extract",
                    props={
                        "binary_a": args.binary_a,
                        "binary_b": args.binary_b,
                        "diff_row_count": len(diff.rows),
                        "identity_count": len(identities),
                        "pdb_identity_record_count": len(pdb_records),
                        "external_similarity_record_count": len(
                            external_similarity
                        ),
                        "external_similarity_manifest_path": args.external_similarity_manifest_path,
                        "identity_output_path": output_path,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
        return WindowsPatchFunctionIdentityExtractResult(
            binary_a=args.binary_a,
            binary_b=args.binary_b,
            diff_row_count=len(diff.rows),
            identity_count=len(identities),
            pdb_identity_record_count=len(pdb_records),
            pdb_identity_manifest_path=pdb_manifest_path,
            external_similarity_record_count=len(external_similarity),
            external_similarity_manifest_path=args.external_similarity_manifest_path,
            identity_output_path=output_path,
            identities=identities,
            evidence_node_id=evidence_node_id,
            notes=[
                "patch function identities are triage metadata, not vulnerability evidence",
                "similarity_score uses external similarity manifest records when supplied, otherwise deterministic size/hash signals",
            ],
        )


def _pdb_records(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsPatchFunctionIdentityExtractArgs,
) -> tuple[list[PdbIdentityRecord], str | None]:
    if args.pdb_identity_manifest is None:
        return [], None
    result = WindowsPdbIdentityManifestTool().run(
        ctx,
        kb,
        args.pdb_identity_manifest.model_copy(update={"add_to_kb": False}),
    )
    return [
        record for record in result.records if record.cache_status == "cached"
    ], result.identity_path


def _load_external_similarity(
    path_text: str | None,
) -> dict[str, WindowsExternalPatchFunctionSimilarity]:
    if not path_text:
        return {}
    path = Path(path_text).expanduser()
    raw_text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        raw = json.loads(raw_text)
    else:
        raw = yaml.safe_load(raw_text)
    if isinstance(raw, dict):
        entries = raw.get("similarities") or raw.get("functions") or []
    else:
        entries = raw
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected similarity entry list")
    loaded: dict[str, WindowsExternalPatchFunctionSimilarity] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        normalized: dict[str, Any] = dict(entry)
        if "function" not in normalized:
            for key in ("name", "function_name", "symbol"):
                if key in normalized:
                    normalized["function"] = normalized[key]
                    break
        if "similarity_score" not in normalized:
            for key in ("score", "similarity", "bsim_score"):
                if key in normalized:
                    normalized["similarity_score"] = normalized[key]
                    break
        record = WindowsExternalPatchFunctionSimilarity.model_validate(normalized)
        loaded[record.function] = record
    return loaded


def _identities(
    rows: list[BinaryDiffRow],
    *,
    pdb_records: list[PdbIdentityRecord],
    external_similarity: dict[str, WindowsExternalPatchFunctionSimilarity],
    min_similarity_score: float,
) -> list[WindowsExtractedPatchFunctionIdentity]:
    record = pdb_records[0] if pdb_records else None
    identities: list[WindowsExtractedPatchFunctionIdentity] = []
    for row in rows:
        if row.status not in {"changed", "added", "removed"}:
            continue
        external = external_similarity.get(row.name)
        score = (
            external.similarity_score if external is not None else _similarity_score(row)
        )
        if record is None and score is not None and score < min_similarity_score:
            continue
        algorithm = (
            external.similarity_algorithm
            if external is not None
            else "size_ratio_body_hash"
            if score is not None
            else None
        )
        basis: PatchFunctionMatchBasis = (
            "pdb_backed"
            if record is not None
            else "similarity_backed"
            if score is not None
            else "name_based"
        )
        identities.append(
            WindowsExtractedPatchFunctionIdentity(
                function=row.name,
                status=row.status,
                match_basis=basis,
                pdb_symbol=row.name if record is not None else None,
                pdb_guid_age=record.codeview_guid_age if record is not None else None,
                similarity_score=score,
                similarity_algorithm=algorithm,
                evidence=_dedupe(
                    [
                        "windows_binary_diff_summary",
                        f"status:{row.status}",
                        *(
                            [
                                "external_similarity_manifest",
                                f"similarity_algorithm:{external.similarity_algorithm}",
                                *external.evidence,
                            ]
                            if external is not None
                            else []
                        ),
                        *(
                            [
                                "windows_pdb_identity_manifest",
                                f"pdb:{record.expected_pdb_name}",
                                record.symbol_cache_path or "",
                                *record.identity_sources,
                                *record.fact_coverage,
                            ]
                            if record is not None
                            else []
                        ),
                    ]
                ),
            )
        )
    return identities


def _similarity_score(row: BinaryDiffRow) -> float | None:
    if row.a is None or row.b is None:
        return None
    if row.a.body_hash == row.b.body_hash:
        return 1.0
    larger = max(row.a.size, row.b.size)
    if larger <= 0:
        return 0.0
    size_ratio = min(row.a.size, row.b.size) / larger
    return round(size_ratio * 0.85, 4)


def _write_identities(
    path_text: str | None,
    identities: list[WindowsExtractedPatchFunctionIdentity],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            [identity.model_dump(mode="json") for identity in identities],
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return str(path)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsPatchFunctionIdentityExtractTool:
    return WindowsPatchFunctionIdentityExtractTool()
