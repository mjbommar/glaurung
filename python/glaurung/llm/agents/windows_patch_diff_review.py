"""Deterministic Windows patch-diff review workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import glaurung as g
import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.adapters import import_triage
from ..tools.windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from ..tools.windows_binary_diff_summary import (
    BinaryDiffRow,
    WindowsBinaryDiffSummaryArgs,
    WindowsBinaryDiffSummaryResult,
    WindowsBinaryDiffSummaryTool,
)
from ..tools.windows_diff_security_relevant_facts import (
    SecurityFactDelta,
    WindowsDiffSecurityRelevantFactsArgs,
    WindowsDiffSecurityRelevantFactsResult,
    WindowsDiffSecurityRelevantFactsTool,
)
from ..tools.windows_pdb_identity_manifest import (
    PdbIdentityRecord,
    WindowsPdbIdentityManifestArgs,
    WindowsPdbIdentityManifestTool,
)
from ..tools.windows_project_function_boundary_diff import (
    ProjectFunctionBoundaryDelta,
    WindowsProjectFunctionBoundaryDiffArgs,
    WindowsProjectFunctionBoundaryDiffResult,
    WindowsProjectFunctionBoundaryDiffTool,
)
from ..tools.windows_project_data_table_diff import (
    ProjectDataTableDelta,
    WindowsProjectDataTableDiffArgs,
    WindowsProjectDataTableDiffResult,
    WindowsProjectDataTableDiffTool,
)
from ..tools.windows_project_prototype_diff import (
    ProjectPrototypeDelta,
    WindowsProjectPrototypeDiffArgs,
    WindowsProjectPrototypeDiffResult,
    WindowsProjectPrototypeDiffTool,
)
from ..tools.windows_seed_binary_diff_triage import (
    SeedBinaryDiffTriageRecord,
    WindowsSeedBinaryDiffTriageArgs,
    WindowsSeedBinaryDiffTriageResult,
    WindowsSeedBinaryDiffTriageTool,
)


PatchDiffItemKind = Literal[
    "changed_function",
    "prototype_delta",
    "seed_function_change",
    "seed_function_missing",
    "security_fact_delta",
    "boundary_delta",
    "table_delta",
]
PatchFunctionMatchBasis = Literal[
    "name_based",
    "hash_based",
    "pdb_backed",
    "similarity_backed",
    "manual_review",
    "uncertain",
]


class WindowsPatchFunctionIdentity(BaseModel):
    function: str
    status: str = "changed"
    match_basis: PatchFunctionMatchBasis
    pdb_symbol: str | None = None
    pdb_guid_age: str | None = None
    similarity_score: float | None = Field(None, ge=0.0, le=1.0)
    similarity_algorithm: str | None = None
    functionization_blockers: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class WindowsPatchDiffReviewConfig(BaseModel):
    binary_a: str = Field(..., description="Pre-change binary path.")
    binary_b: str = Field(..., description="Post-change binary path.")
    seeds_path: str | None = Field(
        None,
        description="Optional ASB pe-vulnerability-seeds.yaml path.",
    )
    seed_id: str | None = None
    public_id: str | None = None
    target_id: str | None = None
    component: str | None = None
    gates_path: str | None = None
    sinks_path: str | None = None
    before_pseudocode: str | None = None
    after_pseudocode: str | None = None
    before_function_va: int | None = None
    after_function_va: int | None = None
    before_project_path: str | None = Field(
        None,
        description=(
            "Optional pre-change .glaurung project for prototype, boundary, "
            "and data-table diffing."
        ),
    )
    after_project_path: str | None = Field(
        None,
        description=(
            "Optional post-change .glaurung project for prototype, boundary, "
            "and data-table diffing."
        ),
    )
    pdb_backed: bool = Field(
        False,
        description="Set when the changed function identity is backed by PDB facts.",
    )
    functionization_blockers: list[str] = Field(
        default_factory=list,
        description=(
            "Boundary/functionization gaps that should reduce patch-review confidence."
        ),
    )
    function_identities: list[WindowsPatchFunctionIdentity] = Field(
        default_factory=list,
        description=(
            "Optional per-function identity facts from PDB matching, similarity, "
            "or manual analyst review."
        ),
    )
    function_identity_path: str | None = Field(
        None,
        description=(
            "Optional YAML list of WindowsPatchFunctionIdentity records emitted by "
            "PDB, BSim, or other similarity extraction jobs."
        ),
    )
    pdb_identity_manifest: WindowsPdbIdentityManifestArgs | None = Field(
        None,
        description=(
            "Optional PDB identity manifest query. Cached matching records are "
            "used to add PDB-backed identity evidence to changed diff rows."
        ),
    )
    max_diff_rows: int = Field(32, ge=0, le=512)
    max_prototype_delta_rows: int = Field(128, ge=0, le=512)
    max_boundary_delta_rows: int = Field(128, ge=0, le=512)
    max_table_delta_rows: int = Field(128, ge=0, le=512)
    max_items: int = Field(20, ge=1, le=128)


class WindowsPatchDiffReviewItem(BaseModel):
    rank: int
    kind: PatchDiffItemKind
    priority: int = Field(ge=0)
    function: str | None = None
    status: str | None = None
    summary: str
    match_basis: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list)
    next_tool: str
    next_args: dict[str, str | int] = Field(default_factory=dict)


class WindowsPatchDiffReviewResult(BaseModel):
    claim_level: str = "patch_diff_review_not_finding"
    binary_diff: WindowsBinaryDiffSummaryResult
    seed_triage: WindowsSeedBinaryDiffTriageResult | None = None
    security_facts: WindowsDiffSecurityRelevantFactsResult | None = None
    prototype_diff: WindowsProjectPrototypeDiffResult | None = None
    boundary_diff: WindowsProjectFunctionBoundaryDiffResult | None = None
    data_table_diff: WindowsProjectDataTableDiffResult | None = None
    review_items: list[WindowsPatchDiffReviewItem]
    function_identity_count: int = 0
    pdb_identity_record_count: int = 0
    pdb_identity_manifest_path: str | None = None
    tool_sequence: list[str]
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


class _FunctionIdentityLoad(BaseModel):
    identities: list[WindowsPatchFunctionIdentity] = Field(default_factory=list)
    pdb_identity_record_count: int = 0
    pdb_identity_manifest_path: str | None = None


def run_windows_patch_diff_review(
    config: WindowsPatchDiffReviewConfig,
) -> WindowsPatchDiffReviewResult:
    ctx = _ctx()
    binary_diff = WindowsBinaryDiffSummaryTool().run(
        ctx,
        ctx.kb,
        WindowsBinaryDiffSummaryArgs(
            binary_a=config.binary_a,
            binary_b=config.binary_b,
            max_rows=config.max_diff_rows,
        ),
    )
    identity_load = _load_function_identities(ctx, config, binary_diff.rows)
    effective_config = config.model_copy(
        update={"function_identities": identity_load.identities}
    )
    seed_triage = _seed_triage(ctx, effective_config)
    security_facts = _security_facts(ctx, effective_config)
    prototype_diff = _prototype_diff(ctx, effective_config)
    boundary_diff = _boundary_diff(ctx, effective_config)
    data_table_diff = _data_table_diff(ctx, effective_config)
    items = _rank_items(
        config=effective_config,
        binary_diff=binary_diff,
        seed_triage=seed_triage,
        security_facts=security_facts,
        prototype_diff=prototype_diff,
        boundary_diff=boundary_diff,
        data_table_diff=data_table_diff,
    )
    tool_sequence = ["windows_binary_diff_summary"]
    if seed_triage is not None:
        tool_sequence.append("windows_seed_binary_diff_triage")
    if security_facts is not None:
        tool_sequence.append("windows_diff_security_relevant_facts")
    if prototype_diff is not None:
        tool_sequence.append("windows_project_prototype_diff")
    if boundary_diff is not None:
        tool_sequence.append("windows_project_function_boundary_diff")
    if data_table_diff is not None:
        tool_sequence.append("windows_project_data_table_diff")
    if config.function_identities:
        tool_sequence.append("provided_windows_patch_function_identity")
    if config.function_identity_path:
        tool_sequence.append("windows_patch_function_identity_manifest")
    if config.pdb_identity_manifest is not None:
        tool_sequence.append("windows_pdb_identity_manifest")
    notes = [
        "Patch-diff review ranks changed areas for analysis; it is not a finding verdict.",
        "Public seed overlap is prior-art context, not proof of a novel issue.",
    ]
    return WindowsPatchDiffReviewResult(
        binary_diff=binary_diff,
        seed_triage=seed_triage,
        security_facts=security_facts,
        prototype_diff=prototype_diff,
        boundary_diff=boundary_diff,
        data_table_diff=data_table_diff,
        review_items=items,
        function_identity_count=len(identity_load.identities),
        pdb_identity_record_count=identity_load.pdb_identity_record_count,
        pdb_identity_manifest_path=identity_load.pdb_identity_manifest_path,
        tool_sequence=tool_sequence,
        evidence_bundle=_evidence_bundle(
            effective_config,
            items,
            tool_sequence,
            notes,
            prototype_diff=prototype_diff,
            boundary_diff=boundary_diff,
            data_table_diff=data_table_diff,
        ),
        notes=notes,
    )


def _load_function_identities(
    ctx: MemoryContext,
    config: WindowsPatchDiffReviewConfig,
    rows: list[BinaryDiffRow],
) -> _FunctionIdentityLoad:
    identities = list(config.function_identities)
    if config.function_identity_path:
        path = Path(config.function_identity_path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        if not isinstance(raw, list):
            raise ValueError(f"{path}: expected top-level identity list")
        for idx, entry in enumerate(raw):
            if not isinstance(entry, dict):
                raise ValueError(f"{path}: identity entry {idx} is not a mapping")
            identities.append(WindowsPatchFunctionIdentity.model_validate(entry))
    pdb_identity_manifest_path = None
    pdb_identity_record_count = 0
    if config.pdb_identity_manifest is not None:
        pdb_result = WindowsPdbIdentityManifestTool().run(
            ctx,
            ctx.kb,
            config.pdb_identity_manifest.model_copy(update={"add_to_kb": False}),
        )
        pdb_identity_manifest_path = pdb_result.identity_path
        cached_records = [
            record for record in pdb_result.records if record.cache_status == "cached"
        ]
        pdb_identity_record_count = len(cached_records)
        identities.extend(_pdb_identities_from_rows(rows, cached_records, identities))
    return _FunctionIdentityLoad(
        identities=identities,
        pdb_identity_record_count=pdb_identity_record_count,
        pdb_identity_manifest_path=pdb_identity_manifest_path,
    )


def _pdb_identities_from_rows(
    rows: list[BinaryDiffRow],
    records: list[PdbIdentityRecord],
    existing: list[WindowsPatchFunctionIdentity],
) -> list[WindowsPatchFunctionIdentity]:
    if not records:
        return []
    seen = {identity.function for identity in existing}
    record = records[0]
    identities: list[WindowsPatchFunctionIdentity] = []
    for row in rows:
        if row.status not in {"changed", "added", "removed"} or row.name in seen:
            continue
        seen.add(row.name)
        identities.append(
            WindowsPatchFunctionIdentity(
                function=row.name,
                status=row.status,
                match_basis="pdb_backed",
                pdb_symbol=row.name,
                pdb_guid_age=record.codeview_guid_age,
                evidence=_dedupe(
                    [
                        "windows_pdb_identity_manifest",
                        f"pdb:{record.expected_pdb_name}",
                        record.symbol_cache_path or "",
                        *record.identity_sources,
                        *record.fact_coverage,
                    ]
                ),
            )
        )
    return identities


def _seed_triage(
    ctx: MemoryContext,
    config: WindowsPatchDiffReviewConfig,
) -> WindowsSeedBinaryDiffTriageResult | None:
    if not config.seeds_path:
        return None
    return WindowsSeedBinaryDiffTriageTool().run(
        ctx,
        ctx.kb,
        WindowsSeedBinaryDiffTriageArgs(
            binary_a=config.binary_a,
            binary_b=config.binary_b,
            seeds_path=config.seeds_path,
            seed_id=config.seed_id,
            public_id=config.public_id,
            target_id=config.target_id,
            component=config.component,
        ),
    )


def _security_facts(
    ctx: MemoryContext,
    config: WindowsPatchDiffReviewConfig,
) -> WindowsDiffSecurityRelevantFactsResult | None:
    has_inputs = bool(
        config.before_pseudocode
        or config.after_pseudocode
        or config.before_function_va is not None
        or config.after_function_va is not None
    )
    if not has_inputs:
        return None
    return WindowsDiffSecurityRelevantFactsTool().run(
        ctx,
        ctx.kb,
        WindowsDiffSecurityRelevantFactsArgs(
            gates_path=config.gates_path,
            sinks_path=config.sinks_path,
            before_pseudocode=config.before_pseudocode,
            after_pseudocode=config.after_pseudocode,
            before_function_va=config.before_function_va,
            after_function_va=config.after_function_va,
            before_path=config.binary_a,
            after_path=config.binary_b,
        ),
    )


def _prototype_diff(
    ctx: MemoryContext,
    config: WindowsPatchDiffReviewConfig,
) -> WindowsProjectPrototypeDiffResult | None:
    if not config.before_project_path and not config.after_project_path:
        return None
    if not config.before_project_path or not config.after_project_path:
        raise ValueError(
            "before_project_path and after_project_path are required together"
        )
    return WindowsProjectPrototypeDiffTool().run(
        ctx,
        ctx.kb,
        WindowsProjectPrototypeDiffArgs(
            before_project_path=config.before_project_path,
            after_project_path=config.after_project_path,
            include_unchanged=False,
            max_rows=config.max_prototype_delta_rows,
        ),
    )


def _boundary_diff(
    ctx: MemoryContext,
    config: WindowsPatchDiffReviewConfig,
) -> WindowsProjectFunctionBoundaryDiffResult | None:
    if not config.before_project_path and not config.after_project_path:
        return None
    if not config.before_project_path or not config.after_project_path:
        raise ValueError(
            "before_project_path and after_project_path are required together"
        )
    return WindowsProjectFunctionBoundaryDiffTool().run(
        ctx,
        ctx.kb,
        WindowsProjectFunctionBoundaryDiffArgs(
            before_project_path=config.before_project_path,
            after_project_path=config.after_project_path,
            include_unchanged=False,
            max_rows=config.max_boundary_delta_rows,
        ),
    )


def _data_table_diff(
    ctx: MemoryContext,
    config: WindowsPatchDiffReviewConfig,
) -> WindowsProjectDataTableDiffResult | None:
    if not config.before_project_path and not config.after_project_path:
        return None
    if not config.before_project_path or not config.after_project_path:
        raise ValueError(
            "before_project_path and after_project_path are required together"
        )
    return WindowsProjectDataTableDiffTool().run(
        ctx,
        ctx.kb,
        WindowsProjectDataTableDiffArgs(
            before_project_path=config.before_project_path,
            after_project_path=config.after_project_path,
            before_binary_path=config.binary_a,
            after_binary_path=config.binary_b,
            include_unchanged=False,
            include_native_code_pointers=False,
            max_rows=config.max_table_delta_rows,
        ),
    )


def _rank_items(
    *,
    config: WindowsPatchDiffReviewConfig,
    binary_diff: WindowsBinaryDiffSummaryResult,
    seed_triage: WindowsSeedBinaryDiffTriageResult | None,
    security_facts: WindowsDiffSecurityRelevantFactsResult | None,
    prototype_diff: WindowsProjectPrototypeDiffResult | None,
    boundary_diff: WindowsProjectFunctionBoundaryDiffResult | None,
    data_table_diff: WindowsProjectDataTableDiffResult | None,
) -> list[WindowsPatchDiffReviewItem]:
    items: list[WindowsPatchDiffReviewItem] = []
    items.extend(_binary_items(config, binary_diff.rows))
    items.extend(_identity_only_items(config, binary_diff.rows))
    if seed_triage is not None:
        items.extend(_seed_items(config, seed_triage.records))
    if security_facts is not None:
        items.extend(_security_items(config, security_facts.deltas))
    if prototype_diff is not None:
        items.extend(_prototype_items(config, prototype_diff.deltas))
    if boundary_diff is not None:
        items.extend(_boundary_items(config, boundary_diff.deltas))
    if data_table_diff is not None:
        items.extend(_table_items(config, data_table_diff.deltas))
    items.sort(
        key=lambda item: (
            -item.priority,
            item.kind,
            item.function or "",
            item.summary,
        )
    )
    items = items[: config.max_items]
    for idx, item in enumerate(items, start=1):
        item.rank = idx
    return items


def _binary_items(
    config: WindowsPatchDiffReviewConfig,
    rows: list[BinaryDiffRow],
) -> list[WindowsPatchDiffReviewItem]:
    out: list[WindowsPatchDiffReviewItem] = []
    identities = _identities_by_function(config.function_identities)
    for row in rows:
        if row.status not in {"changed", "added", "removed"}:
            continue
        basis = ["name_based_function_match"]
        if row.status == "changed":
            basis.append("hash_based_body_delta")
        else:
            basis.append("uncertain_added_removed_name_match")
        if config.pdb_backed:
            basis.append("pdb_backed_identity")
        identity = identities.get(row.name)
        if identity is not None:
            basis.extend(_identity_basis(identity))
        confidence = _identity_confidence(
            config,
            identity,
            0.72 if row.status == "changed" else 0.42,
        )
        priority = 50
        if row.status == "changed":
            priority += _size_delta_score(row)
        else:
            priority += 10
        if identity is not None:
            priority += _identity_priority_bonus(identity)
        out.append(
            WindowsPatchDiffReviewItem(
                rank=0,
                kind="changed_function",
                priority=priority,
                function=row.name,
                status=row.status,
                summary=f"{row.name} is {row.status} between builds",
                match_basis=basis,
                confidence=confidence,
                reason_codes=_reason_codes(
                    config,
                    [
                        f"status_{row.status}",
                        *(
                            [f"identity:{identity.match_basis}"]
                            if identity is not None
                            else []
                        ),
                        *(identity.functionization_blockers if identity else []),
                    ],
                ),
                next_tool="windows_decompile_context_packet",
                next_args={"function": row.name},
            )
        )
    return out


def _identity_only_items(
    config: WindowsPatchDiffReviewConfig,
    rows: list[BinaryDiffRow],
) -> list[WindowsPatchDiffReviewItem]:
    row_names = {row.name for row in rows}
    out: list[WindowsPatchDiffReviewItem] = []
    for identity in config.function_identities:
        if identity.function in row_names:
            continue
        out.append(
            WindowsPatchDiffReviewItem(
                rank=0,
                kind="changed_function",
                priority=45 + _identity_priority_bonus(identity),
                function=identity.function,
                status=identity.status,
                summary=(
                    f"{identity.function} supplied by {identity.match_basis} "
                    "identity evidence but absent from binary diff rows"
                ),
                match_basis=_identity_basis(identity),
                confidence=_identity_confidence(config, identity, 0.38),
                reason_codes=_reason_codes(
                    config,
                    [
                        "provided_identity_not_in_binary_diff_rows",
                        f"identity:{identity.match_basis}",
                        *identity.functionization_blockers,
                    ],
                ),
                next_tool="windows_function_boundary_diff",
                next_args={"function": identity.function},
            )
        )
    return out


def _seed_items(
    config: WindowsPatchDiffReviewConfig,
    records: list[SeedBinaryDiffTriageRecord],
) -> list[WindowsPatchDiffReviewItem]:
    out: list[WindowsPatchDiffReviewItem] = []
    for record in records:
        for function in record.changed_functions:
            out.append(
                WindowsPatchDiffReviewItem(
                    rank=0,
                    kind="seed_function_change",
                    priority=95,
                    function=function,
                    status="changed",
                    summary=f"{function} changed and overlaps public seed {record.seed_id}",
                    match_basis=[
                        "seed_function_name_match",
                        "name_based_function_match",
                        *(("pdb_backed_identity",) if config.pdb_backed else ()),
                    ],
                    confidence=_confidence(config, 0.78),
                    reason_codes=_reason_codes(
                        config,
                        [
                            "public_seed_overlap_not_finding",
                            record.primitive,
                            record.invariant_family,
                        ],
                    ),
                    next_tool="windows_diff_security_relevant_facts",
                    next_args={"function": function, "seed_id": record.seed_id},
                )
            )
        for function in record.missing_functions:
            out.append(
                WindowsPatchDiffReviewItem(
                    rank=0,
                    kind="seed_function_missing",
                    priority=60,
                    function=function,
                    status="not_in_diff",
                    summary=f"{function} from seed {record.seed_id} was not matched",
                    match_basis=[
                        "seed_function_name_match_failed",
                        "uncertain_boundary",
                    ],
                    confidence=_confidence(config, 0.32),
                    reason_codes=_reason_codes(
                        config,
                        ["seed_function_missing_from_binary_diff"],
                    ),
                    next_tool="windows_function_boundary_diff",
                    next_args={"function": function, "seed_id": record.seed_id},
                )
            )
    return out


def _security_items(
    config: WindowsPatchDiffReviewConfig,
    deltas: list[SecurityFactDelta],
) -> list[WindowsPatchDiffReviewItem]:
    out: list[WindowsPatchDiffReviewItem] = []
    for delta in deltas:
        out.append(
            WindowsPatchDiffReviewItem(
                rank=0,
                kind="security_fact_delta",
                priority=_security_priority(delta),
                status=delta.direction,
                summary=f"{delta.direction} {delta.fact_kind}: {delta.item_id}",
                match_basis=["similarity_backed_pseudocode_fact_diff"],
                confidence=_confidence(config, 0.58),
                reason_codes=_reason_codes(
                    config,
                    [
                        f"{delta.direction}_{delta.fact_kind}",
                        delta.item_id,
                    ],
                ),
                next_tool="windows_sink_to_gate_review",
                next_args={
                    "fact_kind": delta.fact_kind,
                    "item_id": delta.item_id,
                },
            )
        )
    return out


def _prototype_items(
    config: WindowsPatchDiffReviewConfig,
    deltas: list[ProjectPrototypeDelta],
) -> list[WindowsPatchDiffReviewItem]:
    out: list[WindowsPatchDiffReviewItem] = []
    for delta in deltas:
        if delta.status == "unchanged":
            continue
        basis = ["project_prototype_diff"]
        if delta.security_relevance:
            basis.append("security_relevant_prototype_delta")
        next_tool = (
            "windows_sink_to_gate_review"
            if delta.security_relevance
            else "windows_decompile_context_packet"
        )
        out.append(
            WindowsPatchDiffReviewItem(
                rank=0,
                kind="prototype_delta",
                priority=_prototype_priority(delta),
                function=delta.function_name,
                status=delta.status,
                summary=(
                    f"{delta.function_name} prototype {delta.status}: "
                    f"{', '.join(delta.changed_fields) or 'signature'}"
                ),
                match_basis=basis,
                confidence=_confidence(
                    config,
                    0.66 if delta.security_relevance else 0.52,
                ),
                reason_codes=_reason_codes(
                    config,
                    [
                        f"prototype_{delta.status}",
                        *delta.reason_codes,
                        *delta.security_relevance,
                    ],
                ),
                next_tool=next_tool,
                next_args={"function": delta.function_name},
            )
        )
    return out


def _boundary_items(
    config: WindowsPatchDiffReviewConfig,
    deltas: list[ProjectFunctionBoundaryDelta],
) -> list[WindowsPatchDiffReviewItem]:
    out: list[WindowsPatchDiffReviewItem] = []
    for delta in deltas:
        if delta.status == "unchanged":
            continue
        basis = ["project_function_boundary_diff"]
        if delta.record_kind == "function_chunk":
            basis.append("project_function_chunk_delta")
        if delta.security_relevance:
            basis.append("functionization_delta")
        next_tool = (
            "windows_project_function_chunk_facts"
            if delta.record_kind == "function_chunk"
            else "windows_project_function_start_explain"
        )
        out.append(
            WindowsPatchDiffReviewItem(
                rank=0,
                kind="boundary_delta",
                priority=_boundary_priority(delta),
                function=delta.name,
                status=delta.status,
                summary=(
                    f"{delta.record_kind} {delta.status} at {delta.address}: "
                    f"{', '.join(delta.changed_fields) or 'record'}"
                ),
                match_basis=basis,
                confidence=_confidence(
                    config,
                    0.58 if delta.security_relevance else 0.46,
                ),
                reason_codes=_reason_codes(
                    config,
                    [
                        f"{delta.record_kind}_{delta.status}",
                        *delta.reason_codes,
                        *delta.security_relevance,
                    ],
                ),
                next_tool=next_tool,
                next_args={"va": delta.address_va},
            )
        )
    return out


def _table_items(
    config: WindowsPatchDiffReviewConfig,
    deltas: list[ProjectDataTableDelta],
) -> list[WindowsPatchDiffReviewItem]:
    out: list[WindowsPatchDiffReviewItem] = []
    for delta in deltas:
        if delta.status == "unchanged":
            continue
        basis = ["project_data_table_diff"]
        if delta.security_relevance:
            basis.append("security_relevant_table_delta")
        next_args: dict[str, str | int] = {"table_kind": delta.table_kind}
        if delta.name:
            next_args["name_contains"] = delta.name
        out.append(
            WindowsPatchDiffReviewItem(
                rank=0,
                kind="table_delta",
                priority=_table_priority(delta),
                function=delta.name,
                status=delta.status,
                summary=(
                    f"{delta.table_kind} {delta.status}: "
                    f"{delta.name or delta.table_key}: "
                    f"{', '.join(delta.changed_fields) or 'table'}"
                ),
                match_basis=basis,
                confidence=_confidence(
                    config,
                    0.58 if delta.security_relevance else 0.46,
                ),
                reason_codes=_reason_codes(
                    config,
                    [
                        f"{delta.table_kind}_{delta.status}",
                        *delta.reason_codes,
                        *delta.security_relevance,
                    ],
                ),
                next_tool="windows_project_data_table_facts",
                next_args=next_args,
            )
        )
    return out


def _prototype_priority(delta: ProjectPrototypeDelta) -> int:
    priority = 54
    if delta.status == "changed":
        priority += 10
    if delta.status in {"added", "removed"}:
        priority += 6
    if delta.security_relevance:
        priority += 18
    if any(
        "buffer" in relevance or "length" in relevance
        for relevance in delta.security_relevance
    ):
        priority += 8
    return priority


def _boundary_priority(delta: ProjectFunctionBoundaryDelta) -> int:
    priority = 46 + min(24, delta.review_priority // 3)
    if delta.status == "changed":
        priority += 8
    if delta.status in {"added", "removed"}:
        priority += 5
    if any(
        relevance in delta.security_relevance
        for relevance in {
            "function_range_delta",
            "thunk_delta",
            "tailcall_or_shared_tail_delta",
            "exception_funclet_delta",
            "split_body_delta",
        }
    ):
        priority += 12
    return priority


def _table_priority(delta: ProjectDataTableDelta) -> int:
    priority = 44 + min(28, delta.review_priority // 3)
    if delta.status == "changed":
        priority += 8
    if delta.status in {"added", "removed"}:
        priority += 5
    if any(
        relevance in delta.security_relevance
        for relevance in {
            "dispatch_table",
            "callback_table",
            "virtual_dispatch_table",
            "selector_indexed_control_flow",
            "import_thunk_table",
        }
    ):
        priority += 12
    if any(
        relevance in delta.security_relevance
        for relevance in {
            "table_target_delta",
            "table_entry_count_delta",
            "table_layout_delta",
        }
    ):
        priority += 10
    return priority


def _security_priority(delta: SecurityFactDelta) -> int:
    if delta.fact_kind == "gate" and delta.direction == "added":
        return 82
    if delta.fact_kind == "sink" and delta.direction == "removed":
        return 78
    if delta.fact_kind == "constant":
        return 52
    return 48


def _identities_by_function(
    identities: list[WindowsPatchFunctionIdentity],
) -> dict[str, WindowsPatchFunctionIdentity]:
    return {identity.function: identity for identity in identities}


def _identity_basis(identity: WindowsPatchFunctionIdentity) -> list[str]:
    basis: list[str] = [f"{identity.match_basis}_function_identity"]
    if identity.pdb_symbol or identity.pdb_guid_age:
        basis.append("pdb_backed_identity")
    if identity.similarity_score is not None:
        basis.append("similarity_backed_function_match")
        if identity.similarity_algorithm:
            basis.append(f"similarity_algorithm:{identity.similarity_algorithm}")
    return _dedupe(basis)


def _identity_priority_bonus(identity: WindowsPatchFunctionIdentity) -> int:
    bonus = 0
    if identity.match_basis == "pdb_backed":
        bonus += 24
    if identity.match_basis == "similarity_backed":
        bonus += 18
    if identity.similarity_score is not None:
        bonus += min(18, int(identity.similarity_score * 18))
    if identity.functionization_blockers:
        bonus += 8
    return bonus


def _size_delta_score(row: BinaryDiffRow) -> int:
    if row.a is None or row.b is None:
        return 0
    return min(40, abs(row.b.size - row.a.size))


def _identity_confidence(
    config: WindowsPatchDiffReviewConfig,
    identity: WindowsPatchFunctionIdentity | None,
    base: float,
) -> float:
    blockers = [
        *config.functionization_blockers,
        *(identity.functionization_blockers if identity else []),
    ]
    if blockers:
        return round(min(base, 0.45), 2)
    if identity is None:
        return round(base, 2)
    if identity.match_basis == "pdb_backed":
        base = max(base, 0.9)
    elif identity.match_basis == "similarity_backed":
        base = max(base, min(0.86, identity.similarity_score or 0.68))
    elif identity.match_basis == "manual_review":
        base = max(base, 0.74)
    elif identity.match_basis == "uncertain":
        base = min(base, 0.48)
    return round(base, 2)


def _confidence(config: WindowsPatchDiffReviewConfig, base: float) -> float:
    if config.functionization_blockers:
        return round(min(base, 0.45), 2)
    return round(base, 2)


def _reason_codes(
    config: WindowsPatchDiffReviewConfig,
    values: list[str],
) -> list[str]:
    return _dedupe([*values, *config.functionization_blockers])


def _evidence_bundle(
    config: WindowsPatchDiffReviewConfig,
    items: list[WindowsPatchDiffReviewItem],
    tool_sequence: list[str],
    notes: list[str],
    *,
    prototype_diff: WindowsProjectPrototypeDiffResult | None,
    boundary_diff: WindowsProjectFunctionBoundaryDiffResult | None,
    data_table_diff: WindowsProjectDataTableDiffResult | None,
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "binary_a": config.binary_a,
                "binary_b": config.binary_b,
                "item_count": len(items),
                "function_identity_count": len(config.function_identities),
                "prototype_delta_count": (
                    len(prototype_diff.deltas) if prototype_diff is not None else 0
                ),
                "boundary_delta_count": (
                    len(boundary_diff.deltas) if boundary_diff is not None else 0
                ),
                "table_delta_count": (
                    len(data_table_diff.deltas) if data_table_diff is not None else 0
                ),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_patch_diff_review",
                summary=f"rank {item.rank}: {item.summary}",
                confidence=item.confidence,
                reason_codes=item.reason_codes,
                provenance=[config.binary_a, config.binary_b],
            )
            for item in items[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[
                *tool_sequence,
                *(
                    ["per_function_patch_identity"]
                    if config.function_identities
                    else []
                ),
                *(["project_prototype_deltas"] if prototype_diff is not None else []),
                *(["project_boundary_deltas"] if boundary_diff is not None else []),
                *(["project_data_table_deltas"] if data_table_diff is not None else []),
            ],
            stale_or_blocking_facts=[
                *config.functionization_blockers,
                *[
                    blocker
                    for identity in config.function_identities
                    for blocker in identity.functionization_blockers
                ],
            ],
        ),
        reason_codes=_dedupe([code for item in items for code in item.reason_codes]),
        blockers=_dedupe(
            [
                *config.functionization_blockers,
                *[
                    blocker
                    for identity in config.function_identities
                    for blocker in identity.functionization_blockers
                ],
            ]
        ),
        next_actions=_dedupe([item.next_tool for item in items]),
        notes=notes,
    )


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-patch-diff-review>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-patch-diff-review>")
    return ctx


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
