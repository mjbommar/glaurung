"""Deterministic Windows interactive-analyst workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

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
from ..tools.windows_emit_review_packet import WindowsReviewPacket
from ..tools.windows_emit_vm_validation_plan import WindowsVmValidationPlan
from ..tools.windows_function_boundary_diff import (
    WindowsFunctionBoundaryDiffArgs,
    WindowsFunctionBoundaryDiffTool,
)
from ..tools.windows_function_start_explain import (
    WindowsFunctionStartExplainArgs,
    WindowsFunctionStartExplainTool,
)
from ..tools.windows_pipeline_blocker_task_plan import (
    WindowsPipelineBlockerTask,
    WindowsPipelineBlockerTaskPlanResult,
)
from ..tools.windows_rank_candidate_packets import (
    WindowsRankCandidatePacketsArgs,
    WindowsRankCandidatePacketsTool,
)
from .windows_patch_diff_review import (
    WindowsPatchDiffReviewConfig,
    run_windows_patch_diff_review,
)
from .windows_target_pipeline import WindowsTargetPipelineBlockerWorklist
from .windows_triage_worklist import (
    WindowsTriageWorklistConfig,
    run_windows_triage_worklist,
)


InteractiveIntent = Literal[
    "explain_function",
    "boundary_gap",
    "triage_queue",
    "patch_diff",
    "candidate_handoff",
    "pipeline_blockers",
]


class WindowsInteractiveAnalystSessionState(BaseModel):
    file: str | None = None
    address: str | None = None
    addresses: list[str] = Field(default_factory=list)
    last_intent: InteractiveIntent | None = None
    review_packet_candidate_id: str | None = None


class WindowsInteractiveAnalystConfig(BaseModel):
    intent: InteractiveIntent
    question: str
    comparison_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
    )
    diagnostics_path: str = Field(
        "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
    )
    file: str | None = None
    address: str | None = None
    max_items: int = Field(8, ge=1, le=64)
    binary_a: str | None = None
    binary_b: str | None = None
    seeds_path: str | None = None
    pdb_backed: bool = False
    candidate_packet: WindowsReviewPacket | None = None
    candidate_id: str | None = Field(
        None,
        description=(
            "Optional candidate id to select when loading a candidate packet "
            "from a structured evidence-review export manifest."
        ),
    )
    evidence_export_manifest_path: str | None = Field(
        None,
        description=(
            "Optional evidence-review export manifest. For candidate_handoff, "
            "the analyst loads candidate_packets_path from this manifest when "
            "candidate_packet is not supplied directly."
        ),
    )
    blocker_worklist_path: str | None = Field(
        None,
        description=(
            "Optional target-pipeline blocker worklist JSON artifact for "
            "pipeline_blockers intent."
        ),
    )
    blocker_task_plan_path: str | None = Field(
        None,
        description=(
            "Optional pipeline blocker task-plan JSON artifact for "
            "pipeline_blockers intent."
        ),
    )
    validation_plan: WindowsVmValidationPlan | None = None
    review_packet_output_path: str | None = Field(
        None,
        description="Optional JSON path for persisting candidate handoff packets.",
    )
    session_state: WindowsInteractiveAnalystSessionState | None = None


class WindowsInteractiveAnalystResult(BaseModel):
    claim_level: str = "interactive_analysis_not_finding"
    intent: InteractiveIntent
    answer: str
    addresses: list[str] = Field(default_factory=list)
    project_fact_coverage: list[str] = Field(default_factory=list)
    known_uncertainty: list[str] = Field(default_factory=list)
    next_tools: list[str] = Field(default_factory=list)
    tool_sequence: list[str]
    review_packet_handoff: WindowsReviewPacket | None = None
    review_packet_handoff_path: str | None = None
    session_state: WindowsInteractiveAnalystSessionState
    evidence_bundle: WindowsEvidenceBundle
    notes: list[str] = Field(default_factory=list)


def run_windows_interactive_analyst(
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    config = _with_session_defaults(config)
    config = _with_evidence_export_candidate(config)
    ctx = _ctx()
    if config.intent == "explain_function":
        return _explain_function(ctx, config)
    if config.intent == "boundary_gap":
        return _boundary_gap(ctx, config)
    if config.intent == "triage_queue":
        return _triage_queue(config)
    if config.intent == "patch_diff":
        return _patch_diff(config)
    if config.intent == "pipeline_blockers":
        return _pipeline_blockers(config)
    return _candidate_handoff(ctx, config)


def _explain_function(
    ctx: MemoryContext,
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    if not config.file or not config.address:
        raise ValueError("explain_function requires file and address")
    explanation = WindowsFunctionStartExplainTool().run(
        ctx,
        ctx.kb,
        WindowsFunctionStartExplainArgs(
            comparison_path=config.comparison_path,
            diagnostics_path=config.diagnostics_path,
            file=config.file,
            address=config.address,
            max_refs=config.max_items,
        ),
    )
    uncertainty = [
        f"confidence={explanation.confidence}",
        f"diagnostic_kind={explanation.diagnostic_kind}",
        *explanation.reason_codes[:8],
    ]
    answer = (
        f"{explanation.address} in {explanation.file} is classified as "
        f"{explanation.final_state}; recommended action: "
        f"{explanation.recommended_action}."
    )
    return _result(
        config=config,
        answer=answer,
        addresses=[explanation.address],
        project_fact_coverage=[],
        known_uncertainty=uncertainty,
        next_tools=["windows_function_start_explain"],
        tool_sequence=["windows_function_start_explain"],
        review_packet=None,
        refs=[
            evidence_ref(
                kind="address",
                source="windows_function_start_explain",
                summary=answer,
                address=explanation.va,
                reason_codes=explanation.reason_codes,
                provenance=[explanation.path],
            )
        ],
    )


def _boundary_gap(
    ctx: MemoryContext,
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    diff = WindowsFunctionBoundaryDiffTool().run(
        ctx,
        ctx.kb,
        WindowsFunctionBoundaryDiffArgs(
            comparison_path=config.comparison_path,
            file=config.file,
            sort_by="total_gap",
            max_rows=config.max_items,
        ),
    )
    rows = diff.rows[: config.max_items]
    addresses = [sample.entry for row in rows for sample in row.sample_missing[:2]]
    uncertainty = [
        f"{row.file}: missing={row.missing_entries} extra={row.extra_entries} buckets={','.join(row.cause_buckets[:4])}"
        for row in rows
    ]
    answer = (
        f"Boundary review covers {len(rows)} row(s), with "
        f"{diff.total_missing_entries} Ghidra-only and "
        f"{diff.total_extra_entries} Glaurung-only starts in the dashboard."
    )
    return _result(
        config=config,
        answer=answer,
        addresses=addresses,
        project_fact_coverage=[],
        known_uncertainty=uncertainty,
        next_tools=_dedupe([tool for row in rows for tool in row.next_tools]),
        tool_sequence=["windows_function_boundary_diff"],
        review_packet=None,
        refs=[
            evidence_ref(
                kind="functionization",
                source="windows_function_boundary_diff",
                summary=f"{row.file}: missing={row.missing_entries} extra={row.extra_entries}",
                reason_codes=row.cause_buckets,
                provenance=[diff.comparison_path],
            )
            for row in rows[:8]
        ],
    )


def _triage_queue(
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    triage = run_windows_triage_worklist(
        WindowsTriageWorklistConfig(
            comparison_path=config.comparison_path,
            diagnostics_path=config.diagnostics_path,
            max_items=config.max_items,
            max_tool_rows=max(config.max_items, 4),
        )
    )
    answer = f"Triage queue has {len(triage.queue)} bounded item(s); top item: {triage.queue[0].summary}."
    addresses = [item.address for item in triage.queue if item.address]
    uncertainty = [
        f"{item.kind}:{item.file}:{','.join(item.reason_codes[:4])}"
        for item in triage.queue
    ]
    return _result(
        config=config,
        answer=answer,
        addresses=addresses,
        project_fact_coverage=[],
        known_uncertainty=uncertainty,
        next_tools=_dedupe([item.next_tool for item in triage.queue]),
        tool_sequence=["windows_triage_worklist"],
        review_packet=None,
        refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_triage_worklist",
                summary=f"rank {item.rank}: {item.summary}",
                reason_codes=item.reason_codes,
                provenance=[item.file],
            )
            for item in triage.queue[:8]
        ],
    )


def _patch_diff(
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    if not config.binary_a or not config.binary_b:
        raise ValueError("patch_diff requires binary_a and binary_b")
    patch = run_windows_patch_diff_review(
        WindowsPatchDiffReviewConfig(
            binary_a=config.binary_a,
            binary_b=config.binary_b,
            seeds_path=config.seeds_path,
            pdb_backed=config.pdb_backed,
            max_items=config.max_items,
        )
    )
    answer = (
        f"Patch diff ranked {len(patch.review_items)} item(s); "
        f"changed={patch.binary_diff.changed}, added={patch.binary_diff.added}, "
        f"removed={patch.binary_diff.removed}."
    )
    uncertainty = [
        f"{item.kind}:{item.function or 'unknown'}:{','.join(item.reason_codes[:4])}"
        for item in patch.review_items
    ]
    return _result(
        config=config,
        answer=answer,
        addresses=[],
        project_fact_coverage=[],
        known_uncertainty=uncertainty,
        next_tools=_dedupe([item.next_tool for item in patch.review_items]),
        tool_sequence=["windows_patch_diff_review", *patch.tool_sequence],
        review_packet=None,
        refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_patch_diff_review",
                summary=f"rank {item.rank}: {item.summary}",
                confidence=item.confidence,
                reason_codes=item.reason_codes,
                provenance=[config.binary_a, config.binary_b],
            )
            for item in patch.review_items[:8]
        ],
    )


def _pipeline_blockers(
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    if config.blocker_task_plan_path:
        return _pipeline_blocker_task_plan(config)
    if not config.blocker_worklist_path:
        raise ValueError(
            "pipeline_blockers requires blocker_worklist_path or blocker_task_plan_path"
        )
    path = Path(config.blocker_worklist_path).expanduser()
    raw = json.loads(path.read_text(encoding="utf-8"))
    worklist = WindowsTargetPipelineBlockerWorklist.model_validate(raw)
    items = worklist.work_items[: config.max_items]
    if not items:
        answer = "Pipeline blocker worklist has 0 item(s)."
    else:
        top = items[0]
        answer = (
            f"Pipeline blocker worklist has {worklist.blocker_work_item_count} "
            f"item(s); top blocker is {top.kind} '{top.blocker}' across "
            f"{top.count} observation(s) and {len(top.candidate_ids)} candidate(s)."
        )
    uncertainty = [
        (
            f"{item.kind}:{item.blocker}:count={item.count}:"
            f"candidates={len(item.candidate_ids)}"
        )
        for item in items
    ]
    next_tools = _dedupe([tool for item in items for tool in _blocker_next_tools(item.kind)])
    return _result(
        config=config,
        answer=answer,
        addresses=[],
        project_fact_coverage=[],
        known_uncertainty=uncertainty,
        next_tools=next_tools,
        tool_sequence=["windows_target_pipeline_blocker_worklist"],
        review_packet=None,
        refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_target_pipeline_blocker_worklist",
                summary=f"rank {item.rank}: {item.kind} {item.blocker}",
                reason_codes=item.reason_codes,
                provenance=[str(path), *item.stages],
            )
            for item in items
        ],
    )


def _pipeline_blocker_task_plan(
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    path = Path(config.blocker_task_plan_path or "").expanduser()
    raw = json.loads(path.read_text(encoding="utf-8"))
    task_count, tasks, source_paths = _load_pipeline_blocker_tasks(raw)
    tasks = tasks[: config.max_items]
    if not tasks:
        answer = "Pipeline blocker task plan has 0 task(s)."
    else:
        top = tasks[0]
        answer = (
            f"Pipeline blocker task plan has {task_count} task(s); "
            f"top task is {top.kind} '{top.title}' with priority "
            f"{top.priority} and tool {top.next_tool_name or 'manual review'}."
        )
    uncertainty = [
        (
            f"{task.kind}:priority={task.priority}:"
            f"targets={','.join(task.target_ids) or '-'}:"
            f"blockers={task.blocker_count}"
        )
        for task in tasks
    ]
    next_tools = _dedupe(
        [task.next_tool_name for task in tasks if task.next_tool_name]
    )
    return _result(
        config=config,
        answer=answer,
        addresses=[],
        project_fact_coverage=[],
        known_uncertainty=uncertainty,
        next_tools=next_tools,
        tool_sequence=["windows_pipeline_blocker_task_plan:artifact"],
        review_packet=None,
        refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_pipeline_blocker_task_plan",
                summary=f"rank {task.rank}: {task.kind} {task.title}",
                reason_codes=task.reason_codes,
                provenance=[str(path), *source_paths, *task.stages],
            )
            for task in tasks
        ],
    )


def _load_pipeline_blocker_tasks(
    raw: Any,
) -> tuple[int, list[WindowsPipelineBlockerTask], list[str]]:
    if not isinstance(raw, dict):
        raise ValueError("pipeline blocker task plan artifact must be a JSON object")
    if "evidence_bundle" in raw:
        plan = WindowsPipelineBlockerTaskPlanResult.model_validate(raw)
        return plan.task_count, list(plan.tasks), list(plan.source_paths)
    tasks = [
        WindowsPipelineBlockerTask.model_validate(item)
        for item in raw.get("tasks") or []
    ]
    return (
        int(raw.get("task_count") or len(tasks)),
        tasks,
        [str(path) for path in raw.get("source_paths") or []],
    )


def _blocker_next_tools(kind: str) -> list[str]:
    return {
        "project_cache": ["windows_project_fact_manifest"],
        "source_gate_metadata": [
            "windows_operation_metadata",
            "windows_source_sink_operand_match",
        ],
        "validation_inventory": ["windows_validation_planning"],
        "harness": ["windows_validation_harness_recipe"],
        "runtime_artifact": ["windows_record_validation_artifact_bundle"],
        "functionization": ["windows_function_start_explain"],
        "symbol_similarity": ["windows_patch_function_identity_extract"],
        "packet_grounding": ["windows_emit_review_packet"],
        "unknown": ["windows_target_pipeline"],
    }.get(kind, ["windows_target_pipeline"])


def _candidate_handoff(
    ctx: MemoryContext,
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystResult:
    if config.candidate_packet is None:
        raise ValueError("candidate_handoff requires candidate_packet")
    plans = [config.validation_plan] if config.validation_plan is not None else []
    ranked = WindowsRankCandidatePacketsTool().run(
        ctx,
        ctx.kb,
        WindowsRankCandidatePacketsArgs(
            packets=[config.candidate_packet],
            validation_plans=plans,
            max_results=1,
        ),
    )
    top = ranked.ranked[0]
    packet = top.packet
    coverage = (
        list(packet.project_facts.fact_coverage)
        if packet.project_facts is not None
        else []
    )
    missing = (
        list(packet.project_facts.missing_facts)
        if packet.project_facts is not None
        else list(packet.required_project_facts)
    )
    uncertainty = [
        f"validation_ready={top.validation_ready}",
        *top.validation_blockers,
        *packet.promotion_blockers,
        *(f"missing_fact={fact}" for fact in missing),
    ]
    answer = (
        f"Candidate {packet.candidate_id} is ranked {top.rank} with score "
        f"{top.score:.2f}; validation_ready={top.validation_ready}. "
        "The review packet handoff preserves packet provenance."
    )
    tool_sequence = ["windows_rank_candidate_packets"]
    if config.evidence_export_manifest_path:
        tool_sequence = [
            "evidence_export_manifest_loader",
            "evidence_export_candidate_packet_loader",
            *tool_sequence,
        ]
        uncertainty.append(
            f"evidence_export_manifest={config.evidence_export_manifest_path}"
        )
    return _result(
        config=config,
        answer=answer,
        addresses=[],
        project_fact_coverage=coverage,
        known_uncertainty=uncertainty,
        next_tools=["windows_evidence_review", "windows_validation_planning"],
        tool_sequence=tool_sequence,
        review_packet=packet,
        refs=[
            evidence_ref(
                kind="candidate",
                source="windows_rank_candidate_packets",
                summary=answer,
                confidence=min(1.0, top.score / 100.0),
                reason_codes=top.reasons,
                provenance=packet.provenance,
            )
        ],
    )


def _result(
    *,
    config: WindowsInteractiveAnalystConfig,
    answer: str,
    addresses: list[str],
    project_fact_coverage: list[str],
    known_uncertainty: list[str],
    next_tools: list[str],
    tool_sequence: list[str],
    review_packet: WindowsReviewPacket | None,
    refs,
) -> WindowsInteractiveAnalystResult:
    notes = [
        "Interactive analyst answers are deterministic tool summaries, not vulnerability verdicts.",
        "Use next_tools to continue with bounded evidence collection.",
    ]
    handoff_path = _write_review_packet_handoff(
        config.review_packet_output_path,
        review_packet,
    )
    sequence = list(tool_sequence)
    if handoff_path:
        sequence.append("windows_interactive_analyst:write_review_packet_handoff")
    return WindowsInteractiveAnalystResult(
        intent=config.intent,
        answer=answer,
        addresses=_dedupe(addresses),
        project_fact_coverage=_dedupe(project_fact_coverage),
        known_uncertainty=_dedupe(known_uncertainty),
        next_tools=_dedupe(next_tools),
        tool_sequence=sequence,
        review_packet_handoff=review_packet,
        review_packet_handoff_path=handoff_path,
        session_state=_session_state(config, addresses, review_packet),
        evidence_bundle=make_windows_evidence_bundle(
            claim_level="triage_evidence_bundle_not_finding",
            subject=WindowsEvidenceSubject(
                kind="candidate" if review_packet is not None else "generic",
                file=config.file,
                candidate_id=review_packet.candidate_id if review_packet else None,
                attributes={
                    "intent": config.intent,
                    "question": config.question,
                    "address_count": len(addresses),
                    "uncertainty_count": len(known_uncertainty),
                    "candidate_id": config.candidate_id,
                    "evidence_export_manifest_path": (
                        config.evidence_export_manifest_path
                    ),
                    "blocker_worklist_path": config.blocker_worklist_path,
                    "blocker_task_plan_path": config.blocker_task_plan_path,
                },
            ),
            source_tools=sequence,
            tool_sequence=sequence,
            evidence_refs=refs,
            coverage=WindowsEvidenceCoverage(
                fact_coverage=project_fact_coverage,
                missing_facts=[
                    item.removeprefix("missing_fact=")
                    for item in known_uncertainty
                    if item.startswith("missing_fact=")
                ],
            ),
            reason_codes=known_uncertainty,
            next_actions=next_tools,
            notes=notes,
        ),
        notes=notes,
    )


def _write_review_packet_handoff(
    path_text: str | None,
    review_packet: WindowsReviewPacket | None,
) -> str | None:
    if not path_text or review_packet is None:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(review_packet.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return str(path)


def _with_session_defaults(
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystConfig:
    state = config.session_state
    if state is None:
        return config
    updates: dict[str, str] = {}
    if config.file is None and state.file:
        updates["file"] = state.file
    if config.address is None:
        if state.address:
            updates["address"] = state.address
        elif state.addresses:
            updates["address"] = state.addresses[0]
    if not updates:
        return config
    return config.model_copy(update=updates)


def _with_evidence_export_candidate(
    config: WindowsInteractiveAnalystConfig,
) -> WindowsInteractiveAnalystConfig:
    if (
        config.intent != "candidate_handoff"
        or config.candidate_packet is not None
        or not config.evidence_export_manifest_path
    ):
        return config
    packets = _load_candidate_packets_from_export_manifest(
        Path(config.evidence_export_manifest_path)
    )
    if not packets:
        raise ValueError(
            f"{config.evidence_export_manifest_path}: no candidate packets found"
        )
    selected = _select_candidate_packet(packets, config.candidate_id)
    return config.model_copy(update={"candidate_packet": selected})


def _load_candidate_packets_from_export_manifest(
    manifest_path: Path,
) -> list[WindowsReviewPacket]:
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{manifest_path}: expected evidence export manifest object")
    packets_path_text = raw.get("candidate_packets_path")
    if not isinstance(packets_path_text, str) or not packets_path_text:
        raise ValueError(f"{manifest_path}: missing candidate_packets_path")
    packets_path = Path(packets_path_text).expanduser()
    if not packets_path.is_absolute():
        packets_path = manifest_path.parent / packets_path
    packet_raw = json.loads(packets_path.read_text(encoding="utf-8"))
    return _packets_from_raw(packet_raw, packets_path)


def _packets_from_raw(raw: Any, path: Path) -> list[WindowsReviewPacket]:
    if isinstance(raw, dict):
        for key in ("candidate_packets", "packets", "results"):
            value = raw.get(key)
            if isinstance(value, list):
                return _packets_from_raw_list(value, path)
        if isinstance(raw.get("packet"), dict):
            return [WindowsReviewPacket.model_validate(raw["packet"])]
        return [WindowsReviewPacket.model_validate(raw)]
    if isinstance(raw, list):
        return _packets_from_raw_list(raw, path)
    raise ValueError(f"{path}: expected packet list or object")


def _packets_from_raw_list(raw: list[Any], path: Path) -> list[WindowsReviewPacket]:
    packets: list[WindowsReviewPacket] = []
    for idx, entry in enumerate(raw):
        if isinstance(entry, dict) and isinstance(entry.get("packet"), dict):
            packets.append(WindowsReviewPacket.model_validate(entry["packet"]))
        elif isinstance(entry, dict):
            packets.append(WindowsReviewPacket.model_validate(entry))
        else:
            raise ValueError(f"{path}: packet entry {idx} is not a mapping")
    return packets


def _select_candidate_packet(
    packets: list[WindowsReviewPacket],
    candidate_id: str | None,
) -> WindowsReviewPacket:
    if candidate_id is None:
        return packets[0]
    for packet in packets:
        if packet.candidate_id == candidate_id:
            return packet
    raise ValueError(f"candidate id not found in evidence export: {candidate_id}")


def _session_state(
    config: WindowsInteractiveAnalystConfig,
    addresses: list[str],
    review_packet: WindowsReviewPacket | None,
) -> WindowsInteractiveAnalystSessionState:
    previous = config.session_state
    carried_addresses = previous.addresses if previous is not None else []
    merged_addresses = _dedupe([*addresses, *carried_addresses])
    address = addresses[0] if addresses else config.address
    if address is None and previous is not None:
        address = previous.address
    file = config.file
    if file is None and previous is not None:
        file = previous.file
    if file is None and review_packet is not None:
        file = review_packet.binary
    return WindowsInteractiveAnalystSessionState(
        file=file,
        address=address,
        addresses=merged_addresses[:32],
        last_intent=config.intent,
        review_packet_candidate_id=(
            review_packet.candidate_id if review_packet is not None else None
        ),
    )


def _ctx() -> MemoryContext:
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path="<windows-interactive-analyst>", artifact=artifact)
    import_triage(ctx.kb, artifact, "<windows-interactive-analyst>")
    return ctx


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
