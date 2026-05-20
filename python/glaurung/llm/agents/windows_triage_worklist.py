"""Deterministic Windows triage worklist workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import glaurung as g
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
    WindowsBinaryDiffSummaryTool,
)
from ..tools.windows_build_corpus import (
    WindowsBuildCorpusArgs,
    WindowsBuildCorpusTarget,
    WindowsBuildCorpusTool,
    WindowsCorpusPathMatch,
)
from ..tools.windows_candidate_start_worklist import (
    CandidateStartWorkItem,
    WindowsCandidateStartWorklistArgs,
    WindowsCandidateStartWorklistTool,
)
from ..tools.windows_function_body_split_candidates import (
    FunctionBodySplitCandidate,
    WindowsFunctionBodySplitCandidatesArgs,
    WindowsFunctionBodySplitCandidatesTool,
)
from ..tools.windows_function_boundary_diff import (
    WindowsFunctionBoundaryDiffArgs,
    WindowsFunctionBoundaryDiffRow,
    WindowsFunctionBoundaryDiffTool,
)
from ..tools.windows_import_thunk_catalog import (
    ImportThunkCatalogRow,
    WindowsImportThunkCatalogArgs,
    WindowsImportThunkCatalogTool,
)
from ..tools.windows_project_fact_manifest import (
    ProjectFactRecord,
    WindowsProjectFactManifestArgs,
    WindowsProjectFactManifestTool,
)
from ..tools.windows_project_operation_risk_summary import (
    WindowsProjectOperationRiskSummaryArgs,
    WindowsProjectOperationRiskSummaryTool,
    WindowsProjectOperationRiskGroup,
)


TriageQueueKind = Literal[
    "functionization_precision",
    "functionization_recall",
    "uncertain_start",
    "body_split",
    "import_thunk",
    "changed_function",
    "sink_heavy",
    "untyped_global",
    "gate_source_blocker",
    "high_volume_target",
]


class WindowsChangedFunctionFact(BaseModel):
    file: str
    function: str
    status: str = "changed"
    match_basis: str = "unknown"
    security_signals: list[str] = Field(default_factory=list)
    functionization_blockers: list[str] = Field(default_factory=list)


class WindowsTriageWorklistConfig(BaseModel):
    comparison_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    )
    diagnostics_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
    )
    max_items: int = Field(15, ge=1, le=128)
    max_tool_rows: int = Field(12, ge=1, le=128)
    changed_functions: list[WindowsChangedFunctionFact] = Field(default_factory=list)
    diff_binary_a: str | None = Field(
        None,
        description="Optional pre-change binary path used to derive changed-function facts.",
    )
    diff_binary_b: str | None = Field(
        None,
        description="Optional post-change binary path used to derive changed-function facts.",
    )
    max_changed_function_rows: int = Field(16, ge=0, le=512)
    project_fact_manifest_path: str | None = None
    project_fact_records: list[ProjectFactRecord] = Field(default_factory=list)
    build_corpus: WindowsBuildCorpusArgs | None = Field(
        None,
        description=(
            "Optional build-corpus lookup used to resolve target/component "
            "binary paths, project paths, and diff pairs before queue ranking."
        ),
    )
    auto_select_high_volume_targets: bool = Field(
        False,
        description=(
            "When build_corpus is supplied, add ranked high-value corpus targets "
            "to the analyst queue instead of requiring a preselected target id."
        ),
    )
    fanout_high_volume_target_batches: bool = Field(
        False,
        description=(
            "When high-volume targets are selected, also emit per-target "
            "validation-planning batch handoff arguments."
        ),
    )
    max_build_corpus_target_items: int = Field(8, ge=0, le=64)
    fanout_max_packets_per_target: int = Field(16, ge=1, le=256)
    fanout_attacker_class: str = "unknown"
    fanout_source_role: str = "unknown"
    fanout_infer_source_roles: bool = False
    fanout_refine_gates: bool = True
    fanout_attach_gate_predicates: bool = True
    auto_project_from_build_corpus: bool = Field(
        True,
        description=(
            "When build_corpus is supplied, use its first resolved project path "
            "and target filename unless explicit project fields are supplied."
        ),
    )
    auto_diff_from_build_corpus: bool = Field(
        True,
        description=(
            "When build_corpus resolves at least two corpus binaries, use the "
            "first two as diff_binary_a/diff_binary_b unless explicit diff "
            "paths are supplied."
        ),
    )
    project_path: str | None = Field(
        None,
        description="Optional .glaurung SQLite project used to derive operation-risk groups.",
    )
    project_binary: str | None = Field(
        None,
        description="Binary/driver filename for project operation-risk extraction.",
    )
    project_binary_path: str | None = Field(
        None,
        description="Optional PE path for source/sink value matching during risk extraction.",
    )
    project_build: str | None = None
    sinks_path: str | None = None
    gates_path: str | None = None
    sources_path: str | None = None
    project_binary_id: int | None = None
    project_function_va: int | None = None
    project_call_symbol: str | None = None
    project_sink_kind: str | None = None
    max_operation_risk_groups: int = Field(12, ge=0, le=256)
    operation_risk_groups: list[WindowsProjectOperationRiskGroup] = Field(
        default_factory=list
    )


class WindowsTriageBuildCorpusResolution(BaseModel):
    manifest_path: str
    corpus_root: str | None = None
    project_root: str | None = None
    target_count: int
    target_ids: list[str] = Field(default_factory=list)
    resolved_binary: str | None = None
    resolved_binary_path: str | None = None
    resolved_project_path: str | None = None
    resolved_diff_binary_a: str | None = None
    resolved_diff_binary_b: str | None = None
    selected_targets: list["WindowsTriageBuildCorpusTargetSelection"] = Field(
        default_factory=list
    )
    notes: list[str] = Field(default_factory=list)


class WindowsTriageTargetFanoutBatch(BaseModel):
    target_id: str
    binary: str
    status: Literal["ready", "blocked"]
    next_tool: str = "windows_validation_planning_batch"
    batch_kind: str = "build_corpus_project_sink_call_packets"
    build_corpus_manifest_path: str
    corpus_root: str | None = None
    project_root: str | None = None
    resolved_binary_path: str | None = None
    resolved_project_path: str | None = None
    max_packets: int = 16
    attacker_class: str = "unknown"
    source_role: str = "unknown"
    infer_source_roles: bool = False
    refine_gates: bool = True
    attach_gate_predicates: bool = True
    sinks_path: str | None = None
    sources_path: str | None = None
    gates_path: str | None = None
    next_args: dict[str, str | int | bool] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)


class WindowsTriageBuildCorpusTargetSelection(BaseModel):
    target_id: str
    filename: str
    binary_kind: str
    priority_label: str
    surfaces: list[str] = Field(default_factory=list)
    scan_roles: list[str] = Field(default_factory=list)
    resolved_binary_path: str | None = None
    resolved_project_path: str | None = None
    score: int = 0
    reasons: list[str] = Field(default_factory=list)


class WindowsTriageWorkItem(BaseModel):
    rank: int
    kind: TriageQueueKind
    priority: int = Field(ge=0)
    file: str
    address: str | None = None
    summary: str
    reason_codes: list[str] = Field(default_factory=list)
    next_tool: str
    next_args: dict[str, str | int] = Field(default_factory=dict)


class WindowsTriageWorklistResult(BaseModel):
    claim_level: str = "triage_worklist_not_finding"
    queue: list[WindowsTriageWorkItem]
    file_count_total: int
    total_missing_entries: int
    total_extra_entries: int
    project_fact_manifest_path: str | None = None
    project_fact_record_count: int = 0
    changed_function_fact_count: int = 0
    operation_risk_group_count: int = 0
    build_corpus_resolution: WindowsTriageBuildCorpusResolution | None = None
    target_fanout_batches: list[WindowsTriageTargetFanoutBatch] = Field(
        default_factory=list
    )
    tool_sequence: list[str]
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


def run_windows_triage_worklist(
    config: WindowsTriageWorklistConfig,
) -> WindowsTriageWorklistResult:
    ctx = _ctx()
    build_corpus_resolution = _resolve_build_corpus(ctx, config)
    effective_config = _apply_build_corpus_resolution(config, build_corpus_resolution)
    boundary_tool = WindowsFunctionBoundaryDiffTool()
    worklist_tool = WindowsCandidateStartWorklistTool()
    split_tool = WindowsFunctionBodySplitCandidatesTool()
    thunk_tool = WindowsImportThunkCatalogTool()
    project_fact_records = _load_project_fact_records(ctx, effective_config)
    changed_functions = _load_changed_function_facts(ctx, effective_config)
    operation_risk_groups = _load_operation_risk_groups(ctx, effective_config)
    build_corpus_targets = (
        build_corpus_resolution.selected_targets
        if build_corpus_resolution is not None
        and effective_config.auto_select_high_volume_targets
        else []
    )
    target_fanout_batches = _target_fanout_batches(
        effective_config,
        build_corpus_resolution,
        build_corpus_targets,
    )

    precision = boundary_tool.run(
        ctx,
        ctx.kb,
        WindowsFunctionBoundaryDiffArgs(
            comparison_path=effective_config.comparison_path,
            sort_by="extra",
            min_extra=1,
            max_rows=effective_config.max_tool_rows,
        ),
    )
    recall = boundary_tool.run(
        ctx,
        ctx.kb,
        WindowsFunctionBoundaryDiffArgs(
            comparison_path=effective_config.comparison_path,
            sort_by="missing",
            min_missing=1,
            max_rows=effective_config.max_tool_rows,
        ),
    )
    uncertain = worklist_tool.run(
        ctx,
        ctx.kb,
        WindowsCandidateStartWorklistArgs(
            comparison_path=effective_config.comparison_path,
            diagnostics_path=effective_config.diagnostics_path,
            diagnostic_kind="all",
            max_rows=effective_config.max_tool_rows,
        ),
    )
    split = split_tool.run(
        ctx,
        ctx.kb,
        WindowsFunctionBodySplitCandidatesArgs(
            comparison_path=effective_config.comparison_path,
            diagnostics_path=effective_config.diagnostics_path,
            max_rows=effective_config.max_tool_rows,
        ),
    )
    thunk = thunk_tool.run(
        ctx,
        ctx.kb,
        WindowsImportThunkCatalogArgs(
            comparison_path=effective_config.comparison_path,
            diagnostics_path=effective_config.diagnostics_path,
            file="win11-webservices.dll",
            shape="jmp_rel32",
            max_rows=min(effective_config.max_tool_rows, 8),
        ),
    )
    queue = _rank_queue(
        precision=precision.rows,
        recall=recall.rows,
        uncertain=uncertain.rows,
        split=split.rows,
        thunk=thunk.rows,
        changed_functions=changed_functions,
        project_fact_records=project_fact_records,
        operation_risk_groups=operation_risk_groups,
        build_corpus_targets=build_corpus_targets,
        target_fanout_batches=target_fanout_batches,
        max_items=effective_config.max_items,
    )
    tool_sequence = [
        "windows_function_boundary_diff:extra",
        "windows_function_boundary_diff:missing",
        "windows_candidate_start_worklist",
        "windows_function_body_split_candidates",
        "windows_import_thunk_catalog",
    ]
    if effective_config.build_corpus:
        tool_sequence.append("windows_build_corpus")
    if build_corpus_targets:
        tool_sequence.append("windows_build_corpus:auto_select_targets")
    if target_fanout_batches:
        tool_sequence.append("windows_triage_worklist:target_fanout_batches")
    if effective_config.changed_functions:
        tool_sequence.append("provided_changed_function_facts")
    if effective_config.diff_binary_a or effective_config.diff_binary_b:
        tool_sequence.append("windows_binary_diff_summary:changed")
    if effective_config.project_fact_manifest_path:
        tool_sequence.append("windows_project_fact_manifest")
    if effective_config.project_fact_records:
        tool_sequence.append("provided_project_fact_records")
    if effective_config.project_path:
        tool_sequence.append("windows_project_operation_risk_summary")
    if effective_config.operation_risk_groups:
        tool_sequence.append("provided_operation_risk_groups")
    notes = [
        "Triage worklist is an analyst queue, not vulnerability evidence.",
        "Each queue item carries the deterministic next tool and exact address or file.",
    ]
    if build_corpus_resolution is not None:
        notes.extend(build_corpus_resolution.notes)
        if build_corpus_targets:
            notes.append(
                f"selected {len(build_corpus_targets)} high-value build-corpus target(s)."
            )
        if target_fanout_batches:
            ready_count = sum(
                1 for batch in target_fanout_batches if batch.status == "ready"
            )
            notes.append(
                f"prepared {ready_count} ready target fanout batch(es) "
                f"from {len(target_fanout_batches)} selected target(s)."
            )
    return WindowsTriageWorklistResult(
        queue=queue,
        file_count_total=precision.file_count_total,
        total_missing_entries=precision.total_missing_entries,
        total_extra_entries=precision.total_extra_entries,
        project_fact_manifest_path=effective_config.project_fact_manifest_path,
        project_fact_record_count=len(project_fact_records),
        changed_function_fact_count=len(changed_functions),
        operation_risk_group_count=len(operation_risk_groups),
        build_corpus_resolution=build_corpus_resolution,
        target_fanout_batches=target_fanout_batches,
        tool_sequence=tool_sequence,
        evidence_bundle=_evidence_bundle(
            config=effective_config,
            build_corpus_resolution=build_corpus_resolution,
            target_fanout_batches=target_fanout_batches,
            queue=queue,
            total_missing=precision.total_missing_entries,
            total_extra=precision.total_extra_entries,
            tool_sequence=tool_sequence,
            notes=notes,
        ),
        notes=notes,
    )


def _resolve_build_corpus(
    ctx: MemoryContext,
    config: WindowsTriageWorklistConfig,
) -> WindowsTriageBuildCorpusResolution | None:
    if config.build_corpus is None:
        return None
    result = WindowsBuildCorpusTool().run(
        ctx,
        ctx.kb,
        config.build_corpus.model_copy(update={"add_to_kb": False}),
    )
    target = result.targets[0] if result.targets else None
    corpus_matches = _path_matches(result.targets, "corpus")
    project_matches = _path_matches(result.targets, "project")
    resolved_diff_binary_a = None
    resolved_diff_binary_b = None
    if len(corpus_matches) >= 2:
        resolved_diff_binary_a = corpus_matches[0].path
        resolved_diff_binary_b = corpus_matches[1].path
    notes = [
        f"build corpus matched {len(result.targets)} target(s) from {result.manifest_path}."
    ]
    if target and corpus_matches:
        notes.append(
            f"resolved {target.filename} binary path from build corpus: "
            f"{corpus_matches[0].path}"
        )
    if project_matches:
        notes.append(
            "resolved .glaurung project path from build corpus: "
            f"{project_matches[0].path}"
        )
    if resolved_diff_binary_a and resolved_diff_binary_b:
        notes.append(
            "resolved binary diff pair from build corpus: "
            f"{resolved_diff_binary_a} -> {resolved_diff_binary_b}"
        )
    selected_targets = _selected_build_corpus_targets(
        result.targets,
        max_items=config.max_build_corpus_target_items
        if config.auto_select_high_volume_targets
        else 0,
    )
    return WindowsTriageBuildCorpusResolution(
        manifest_path=result.manifest_path,
        corpus_root=result.corpus_root,
        project_root=result.project_root,
        target_count=len(result.targets),
        target_ids=[target.id for target in result.targets],
        resolved_binary=target.filename if target else None,
        resolved_binary_path=corpus_matches[0].path if corpus_matches else None,
        resolved_project_path=project_matches[0].path if project_matches else None,
        resolved_diff_binary_a=resolved_diff_binary_a,
        resolved_diff_binary_b=resolved_diff_binary_b,
        selected_targets=selected_targets,
        notes=notes,
    )


def _selected_build_corpus_targets(
    targets: list[WindowsBuildCorpusTarget],
    *,
    max_items: int,
) -> list[WindowsTriageBuildCorpusTargetSelection]:
    if max_items <= 0:
        return []
    selections = [_build_corpus_selection(target) for target in targets]
    selections.sort(
        key=lambda item: (
            -item.score,
            item.binary_kind,
            item.filename.lower(),
            item.target_id,
        )
    )
    return selections[:max_items]


def _build_corpus_selection(
    target: WindowsBuildCorpusTarget,
) -> WindowsTriageBuildCorpusTargetSelection:
    corpus_match = target.corpus_matches[0] if target.corpus_matches else None
    project_match = target.project_matches[0] if target.project_matches else None
    priority_score = {
        "critical": 500,
        "high": 400,
        "medium": 250,
        "low": 100,
    }.get(target.priority, 150)
    kind_score = {
        "kernel": 180,
        "win32k": 170,
        "driver": 160,
        "service": 120,
        "dll": 100,
        "exe": 80,
    }.get(target.binary_kind, 75)
    surface_score = sum(
        35
        for surface in target.surfaces
        if surface in {"syscall", "ioctl", "network", "rpc", "local_service"}
    )
    size_score = min(corpus_match.size_bytes // 1_000_000, 120) if corpus_match else 0
    evidence_score = (40 if corpus_match else 0) + (40 if project_match else 0)
    score = (
        priority_score + kind_score + surface_score + int(size_score) + evidence_score
    )
    reasons = _dedupe(
        [
            f"priority:{target.priority}",
            f"binary_kind:{target.binary_kind}",
            *(f"surface:{surface}" for surface in target.surfaces),
            *(f"scan_role:{role}" for role in target.scan_roles),
            *(
                [f"resolved_binary:{corpus_match.relative_path}"]
                if corpus_match
                else []
            ),
            *(
                [f"resolved_project:{project_match.relative_path}"]
                if project_match
                else []
            ),
        ]
    )
    return WindowsTriageBuildCorpusTargetSelection(
        target_id=target.id,
        filename=target.filename,
        binary_kind=target.binary_kind,
        priority_label=target.priority,
        surfaces=list(target.surfaces),
        scan_roles=list(target.scan_roles),
        resolved_binary_path=corpus_match.path if corpus_match else None,
        resolved_project_path=project_match.path if project_match else None,
        score=score,
        reasons=reasons,
    )


def _target_fanout_batches(
    config: WindowsTriageWorklistConfig,
    resolution: WindowsTriageBuildCorpusResolution | None,
    targets: list[WindowsTriageBuildCorpusTargetSelection],
) -> list[WindowsTriageTargetFanoutBatch]:
    if (
        not config.fanout_high_volume_target_batches
        or resolution is None
        or not targets
    ):
        return []
    batches: list[WindowsTriageTargetFanoutBatch] = []
    for target in targets:
        blockers: list[str] = []
        if not target.resolved_project_path:
            blockers.append("missing_project_path")
        status: Literal["ready", "blocked"] = "blocked" if blockers else "ready"
        args: dict[str, str | int | bool] = {
            "batch_kind": "build_corpus_project_sink_call_packets",
            "build_corpus_manifest_path": resolution.manifest_path,
            "target_id": target.target_id,
            "binary": target.filename,
            "max_packets": config.fanout_max_packets_per_target,
            "attacker_class": config.fanout_attacker_class,
            "source_role": config.fanout_source_role,
            "infer_source_roles": config.fanout_infer_source_roles,
            "refine_gates": config.fanout_refine_gates,
            "attach_gate_predicates": config.fanout_attach_gate_predicates,
        }
        _add_optional_arg(args, "corpus_root", resolution.corpus_root)
        _add_optional_arg(args, "project_root", resolution.project_root)
        _add_optional_arg(args, "binary_path", target.resolved_binary_path)
        _add_optional_arg(args, "project_path", target.resolved_project_path)
        _add_optional_arg(args, "sinks_path", config.sinks_path)
        _add_optional_arg(args, "sources_path", config.sources_path)
        _add_optional_arg(args, "gates_path", config.gates_path)
        batches.append(
            WindowsTriageTargetFanoutBatch(
                target_id=target.target_id,
                binary=target.filename,
                status=status,
                build_corpus_manifest_path=resolution.manifest_path,
                corpus_root=resolution.corpus_root,
                project_root=resolution.project_root,
                resolved_binary_path=target.resolved_binary_path,
                resolved_project_path=target.resolved_project_path,
                max_packets=config.fanout_max_packets_per_target,
                attacker_class=config.fanout_attacker_class,
                source_role=config.fanout_source_role,
                infer_source_roles=config.fanout_infer_source_roles,
                refine_gates=config.fanout_refine_gates,
                attach_gate_predicates=config.fanout_attach_gate_predicates,
                sinks_path=config.sinks_path,
                sources_path=config.sources_path,
                gates_path=config.gates_path,
                next_args=args,
                blockers=blockers,
            )
        )
    return batches


def _add_optional_arg(
    args: dict[str, str | int | bool],
    key: str,
    value: str | None,
) -> None:
    if value:
        args[key] = value


def _path_matches(
    targets,
    kind: str,
) -> list[WindowsCorpusPathMatch]:
    out: list[WindowsCorpusPathMatch] = []
    seen: set[str] = set()
    for target in targets:
        matches = target.corpus_matches if kind == "corpus" else target.project_matches
        for match in matches:
            if match.path in seen:
                continue
            seen.add(match.path)
            out.append(match)
    return out


def _apply_build_corpus_resolution(
    config: WindowsTriageWorklistConfig,
    resolution: WindowsTriageBuildCorpusResolution | None,
) -> WindowsTriageWorklistConfig:
    if resolution is None:
        return config
    updates: dict[str, str] = {}
    if config.auto_project_from_build_corpus:
        if not config.project_path and resolution.resolved_project_path:
            updates["project_path"] = resolution.resolved_project_path
        if not config.project_binary and resolution.resolved_binary:
            updates["project_binary"] = resolution.resolved_binary
        if not config.project_binary_path and resolution.resolved_binary_path:
            updates["project_binary_path"] = resolution.resolved_binary_path
    if (
        config.auto_diff_from_build_corpus
        and not config.diff_binary_a
        and not config.diff_binary_b
        and resolution.resolved_diff_binary_a
        and resolution.resolved_diff_binary_b
    ):
        updates["diff_binary_a"] = resolution.resolved_diff_binary_a
        updates["diff_binary_b"] = resolution.resolved_diff_binary_b
    if not updates:
        return config
    return config.model_copy(update=updates)


def _rank_queue(
    *,
    precision: list[WindowsFunctionBoundaryDiffRow],
    recall: list[WindowsFunctionBoundaryDiffRow],
    uncertain: list[CandidateStartWorkItem],
    split: list[FunctionBodySplitCandidate],
    thunk: list[ImportThunkCatalogRow],
    changed_functions: list[WindowsChangedFunctionFact],
    project_fact_records: list[ProjectFactRecord],
    operation_risk_groups: list[WindowsProjectOperationRiskGroup],
    build_corpus_targets: list[WindowsTriageBuildCorpusTargetSelection],
    target_fanout_batches: list[WindowsTriageTargetFanoutBatch],
    max_items: int,
) -> list[WindowsTriageWorkItem]:
    items: list[WindowsTriageWorkItem] = []
    items.extend(
        _build_corpus_target_items(build_corpus_targets, target_fanout_batches)
    )
    items.extend(_changed_function_items(changed_functions))
    items.extend(_operation_risk_items(operation_risk_groups))
    items.extend(_project_fact_items(project_fact_records))
    items.extend(_precision_items(precision))
    items.extend(_recall_items(recall))
    items.extend(_uncertain_items(uncertain))
    items.extend(_split_items(split))
    items.extend(_thunk_items(thunk))
    items.sort(
        key=lambda item: (-item.priority, item.kind, item.file, item.address or "")
    )
    items = items[:max_items]
    for idx, item in enumerate(items, start=1):
        item.rank = idx
    return items


def _build_corpus_target_items(
    targets: list[WindowsTriageBuildCorpusTargetSelection],
    fanout_batches: list[WindowsTriageTargetFanoutBatch],
) -> list[WindowsTriageWorkItem]:
    fanout_by_target = {batch.target_id: batch for batch in fanout_batches}
    items: list[WindowsTriageWorkItem] = []
    for target in targets:
        fanout = fanout_by_target.get(target.target_id)
        reason_codes = list(target.reasons)
        next_tool = "windows_triage_worklist"
        next_args: dict[str, str | int] = {
            "target_id": target.target_id,
            "binary": target.filename,
            "surface": target.surfaces[0] if target.surfaces else "",
        }
        if fanout is not None:
            if fanout.status == "ready":
                next_tool = fanout.next_tool
                next_args = {
                    "batch_kind": fanout.batch_kind,
                    "target_id": target.target_id,
                    "binary": target.filename,
                    "max_packets": fanout.max_packets,
                }
                if fanout.resolved_project_path:
                    next_args["project_path"] = fanout.resolved_project_path
                if fanout.resolved_binary_path:
                    next_args["binary_path"] = fanout.resolved_binary_path
                reason_codes.append("fanout:validation_batch_ready")
            else:
                reason_codes.extend(
                    f"fanout_blocker:{item}" for item in fanout.blockers
                )
        items.append(
            WindowsTriageWorkItem(
                rank=0,
                kind="high_volume_target",
                priority=780 + target.score,
                file=target.filename,
                summary=(
                    f"{target.priority_label} {target.binary_kind} target "
                    f"{target.target_id} covers {', '.join(target.surfaces[:4])}"
                ),
                reason_codes=_dedupe(reason_codes),
                next_tool=next_tool,
                next_args=next_args,
            )
        )
    return items


def _load_project_fact_records(
    ctx: MemoryContext,
    config: WindowsTriageWorklistConfig,
) -> list[ProjectFactRecord]:
    records = list(config.project_fact_records)
    if config.project_fact_manifest_path:
        manifest = WindowsProjectFactManifestTool().run(
            ctx,
            ctx.kb,
            WindowsProjectFactManifestArgs(
                project_facts_path=config.project_fact_manifest_path,
            ),
        )
        records.extend(manifest.records)
    return records


def _load_changed_function_facts(
    ctx: MemoryContext,
    config: WindowsTriageWorklistConfig,
) -> list[WindowsChangedFunctionFact]:
    facts = list(config.changed_functions)
    if not (config.diff_binary_a or config.diff_binary_b):
        return facts
    if not config.diff_binary_a or not config.diff_binary_b:
        raise ValueError("diff_binary_a and diff_binary_b must be supplied together")
    diff = WindowsBinaryDiffSummaryTool().run(
        ctx,
        ctx.kb,
        WindowsBinaryDiffSummaryArgs(
            binary_a=config.diff_binary_a,
            binary_b=config.diff_binary_b,
            max_rows=config.max_changed_function_rows,
        ),
    )
    facts.extend(_changed_facts_from_diff_rows(diff.rows, config.diff_binary_b))
    return _dedupe_changed_functions(facts)


def _changed_facts_from_diff_rows(
    rows: list[BinaryDiffRow],
    binary_b: str,
) -> list[WindowsChangedFunctionFact]:
    file = Path(binary_b).name
    facts: list[WindowsChangedFunctionFact] = []
    for row in rows:
        if row.status == "same":
            continue
        facts.append(
            WindowsChangedFunctionFact(
                file=file,
                function=row.name,
                status=row.status,
                match_basis=(
                    "hash_based_body_delta"
                    if row.status == "changed"
                    else "name_based_added_removed"
                ),
                security_signals=["binary_diff_delta"],
                functionization_blockers=(
                    ["added_removed_boundary_identity_uncertain"]
                    if row.status in {"added", "removed"}
                    else []
                ),
            )
        )
    return facts


def _load_operation_risk_groups(
    ctx: MemoryContext,
    config: WindowsTriageWorklistConfig,
) -> list[WindowsProjectOperationRiskGroup]:
    groups = list(config.operation_risk_groups)
    if not config.project_path:
        return groups
    if not config.project_binary:
        raise ValueError("project_binary is required when project_path is supplied")
    result = WindowsProjectOperationRiskSummaryTool().run(
        ctx,
        ctx.kb,
        WindowsProjectOperationRiskSummaryArgs(
            project_path=config.project_path,
            binary=config.project_binary,
            binary_path=config.project_binary_path,
            build=config.project_build,
            sinks_path=config.sinks_path,
            gates_path=config.gates_path,
            sources_path=config.sources_path,
            binary_id=config.project_binary_id,
            function_va=config.project_function_va,
            call_symbol=config.project_call_symbol,
            sink_kind=config.project_sink_kind,
            max_groups=config.max_operation_risk_groups,
        ),
    )
    groups.extend(result.groups)
    return groups


def _changed_function_items(
    facts: list[WindowsChangedFunctionFact],
) -> list[WindowsTriageWorkItem]:
    return [
        WindowsTriageWorkItem(
            rank=0,
            kind="changed_function",
            priority=720
            + len(fact.security_signals) * 25
            + len(fact.functionization_blockers) * 20,
            file=fact.file,
            address=fact.function if fact.function.startswith("0x") else None,
            summary=(
                f"{fact.status} function {fact.function} matched by {fact.match_basis}"
            ),
            reason_codes=_dedupe(
                [
                    fact.status,
                    f"match_basis:{fact.match_basis}",
                    *fact.security_signals,
                    *fact.functionization_blockers,
                ]
            ),
            next_tool="windows_patch_diff_review",
            next_args={"file": fact.file, "function": fact.function},
        )
        for fact in facts
    ]


def _operation_risk_items(
    groups: list[WindowsProjectOperationRiskGroup],
) -> list[WindowsTriageWorkItem]:
    items: list[WindowsTriageWorkItem] = []
    for group in groups:
        kind: TriageQueueKind = (
            "gate_source_blocker"
            if group.blockers or group.missing_required_gates
            else "sink_heavy"
        )
        items.append(
            WindowsTriageWorkItem(
                rank=0,
                kind=kind,
                priority=680 + int(group.score) + min(group.packet_count, 100),
                file=group.provenance[0] if group.provenance else "<project>",
                summary=(
                    f"{group.packet_count} {group.sink_kind} calls through "
                    f"{group.sink_symbol}; priority={group.priority}"
                ),
                reason_codes=_dedupe(
                    [
                        group.sink_kind,
                        group.priority,
                        *group.reasons,
                        *group.blockers,
                        *group.missing_required_gates,
                    ]
                ),
                next_tool="windows_sink_to_gate_review",
                next_args={
                    "sink_symbol": group.sink_symbol,
                    "sink_kind": group.sink_kind,
                },
            )
        )
    return items


def _project_fact_items(
    records: list[ProjectFactRecord],
) -> list[WindowsTriageWorkItem]:
    items: list[WindowsTriageWorkItem] = []
    for record in records:
        untyped_gaps = [
            fact
            for fact in record.missing_facts
            if fact in {"function_prototypes", "data_labels", "type_layouts"}
        ]
        if not untyped_gaps:
            continue
        items.append(
            WindowsTriageWorkItem(
                rank=0,
                kind="untyped_global",
                priority=620
                + min(record.counts.data_read_xref_count, 100)
                + len(untyped_gaps) * 20,
                file=record.binary_filename,
                summary=(
                    f"project {record.target_id} lacks typed data/prototype facts: "
                    f"{', '.join(untyped_gaps)}"
                ),
                reason_codes=_dedupe(
                    [
                        "persisted_project_fact_gap",
                        *untyped_gaps,
                        *record.fact_coverage,
                    ]
                ),
                next_tool="windows_project_fact_manifest",
                next_args={
                    "target_id": record.target_id,
                    "binary": record.binary_filename,
                },
            )
        )
    return items


def _precision_items(
    rows: list[WindowsFunctionBoundaryDiffRow],
) -> list[WindowsTriageWorkItem]:
    return [
        WindowsTriageWorkItem(
            rank=0,
            kind="functionization_precision",
            priority=row.extra_entries + min(row.missing_entries, 50),
            file=row.file,
            summary=(
                f"precision gap: {row.extra_entries} Glaurung-only starts, "
                f"{row.missing_entries} Ghidra-only starts"
            ),
            reason_codes=row.cause_buckets,
            next_tool="windows_candidate_start_worklist",
            next_args={"file": row.file, "diagnostic_kind": "extra"},
        )
        for row in rows
        if row.extra_entries
    ]


def _recall_items(
    rows: list[WindowsFunctionBoundaryDiffRow],
) -> list[WindowsTriageWorkItem]:
    return [
        WindowsTriageWorkItem(
            rank=0,
            kind="functionization_recall",
            priority=row.missing_entries + min(row.extra_entries, 50),
            file=row.file,
            summary=(
                f"recall gap: {row.missing_entries} Ghidra-only starts, "
                f"{row.missing_thunks} thunk starts"
            ),
            reason_codes=row.cause_buckets,
            next_tool="windows_function_start_explain",
            next_args={
                "file": row.file,
                "address": row.sample_missing[0].entry if row.sample_missing else "",
            },
        )
        for row in rows
        if row.missing_entries
    ]


def _uncertain_items(rows: list[CandidateStartWorkItem]) -> list[WindowsTriageWorkItem]:
    return [
        WindowsTriageWorkItem(
            rank=0,
            kind="uncertain_start",
            priority=500 + row.score,
            file=row.file,
            address=row.address,
            summary=f"{row.final_state}: {row.recommended_action}",
            reason_codes=row.reason_codes,
            next_tool=row.next_tool,
            next_args={"file": row.file, "address": row.address},
        )
        for row in rows
    ]


def _split_items(rows: list[FunctionBodySplitCandidate]) -> list[WindowsTriageWorkItem]:
    return [
        WindowsTriageWorkItem(
            rank=0,
            kind="body_split",
            priority=450 + row.score,
            file=row.file,
            address=row.address,
            summary=f"body split candidate inside {row.owner_entry}",
            reason_codes=row.reason_codes,
            next_tool="windows_function_start_explain",
            next_args={"file": row.file, "address": row.address},
        )
        for row in rows
    ]


def _thunk_items(rows: list[ImportThunkCatalogRow]) -> list[WindowsTriageWorkItem]:
    return [
        WindowsTriageWorkItem(
            rank=0,
            kind="import_thunk",
            priority=400,
            file=row.file,
            address=row.address,
            summary=f"{row.shape} thunk is {row.current_state}",
            reason_codes=row.reason_codes,
            next_tool="windows_import_thunk_catalog",
            next_args={"file": row.file, "address": row.address},
        )
        for row in rows
    ]


def _evidence_bundle(
    *,
    config: WindowsTriageWorklistConfig,
    build_corpus_resolution: WindowsTriageBuildCorpusResolution | None,
    target_fanout_batches: list[WindowsTriageTargetFanoutBatch],
    queue: list[WindowsTriageWorkItem],
    total_missing: int,
    total_extra: int,
    tool_sequence: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "comparison_path": config.comparison_path,
                "diagnostics_path": config.diagnostics_path,
                "queue_count": len(queue),
                "build_corpus_manifest_path": (
                    build_corpus_resolution.manifest_path
                    if build_corpus_resolution is not None
                    else None
                ),
                "build_corpus_target_count": (
                    build_corpus_resolution.target_count
                    if build_corpus_resolution is not None
                    else 0
                ),
                "resolved_project_path": (
                    build_corpus_resolution.resolved_project_path
                    if build_corpus_resolution is not None
                    else None
                ),
                "resolved_binary_path": (
                    build_corpus_resolution.resolved_binary_path
                    if build_corpus_resolution is not None
                    else None
                ),
                "resolved_diff_binary_a": (
                    build_corpus_resolution.resolved_diff_binary_a
                    if build_corpus_resolution is not None
                    else None
                ),
                "resolved_diff_binary_b": (
                    build_corpus_resolution.resolved_diff_binary_b
                    if build_corpus_resolution is not None
                    else None
                ),
                "selected_build_corpus_target_count": (
                    len(build_corpus_resolution.selected_targets)
                    if build_corpus_resolution is not None
                    else 0
                ),
                "selected_build_corpus_targets": (
                    ",".join(
                        target.target_id
                        for target in build_corpus_resolution.selected_targets
                    )
                    if build_corpus_resolution is not None
                    else ""
                ),
                "target_fanout_batch_count": len(target_fanout_batches),
                "target_fanout_ready_count": sum(
                    1 for batch in target_fanout_batches if batch.status == "ready"
                ),
                "target_fanout_targets": ",".join(
                    batch.target_id for batch in target_fanout_batches
                ),
            },
        ),
        source_tools=[tool.split(":")[0] for tool in tool_sequence],
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_triage_worklist",
                summary=f"rank {item.rank}: {item.kind} {item.file} {item.address or ''}",
                reason_codes=item.reason_codes,
                provenance=[config.comparison_path, config.diagnostics_path],
            )
            for item in queue[:16]
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=tool_sequence,
            ghidra_missing_entries=total_missing,
            ghidra_extra_entries=total_extra,
        ),
        reason_codes=_dedupe([code for item in queue for code in item.reason_codes]),
        next_actions=_dedupe([item.next_tool for item in queue]),
        notes=notes,
    )


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-triage-worklist>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-triage-worklist>")
    return ctx


def _dedupe_changed_functions(
    facts: list[WindowsChangedFunctionFact],
) -> list[WindowsChangedFunctionFact]:
    out: list[WindowsChangedFunctionFact] = []
    seen: set[tuple[str, str, str]] = set()
    for fact in facts:
        key = (fact.file, fact.function, fact.status)
        if key in seen:
            continue
        seen.add(key)
        out.append(fact)
    return out


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
