"""Turn Windows pipeline readiness artifacts into concrete follow-up tasks."""

from __future__ import annotations

import glob
import json
from pathlib import Path
import shlex
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)
from .windows_build_corpus import (
    WindowsBuildCorpusArgs,
    WindowsBuildCorpusTarget,
    WindowsBuildCorpusTool,
)
from .windows_high_volume_preflight import WindowsHighVolumePreflightResult
from ..agents.windows_target_pipeline import (
    WindowsTargetPipelineBlockerKind,
    WindowsTargetPipelineBlockerWorkItem,
    WindowsTargetPipelineBlockerWorklist,
)


WindowsPipelineBlockerTaskKind = Literal[
    "project_cache_refresh",
    "corpus_binary_vendor",
    "source_gate_metadata",
    "validation_inventory",
    "harness",
    "runtime_artifact",
    "functionization_rule",
    "symbol_similarity_extract",
    "packet_grounding",
    "unknown",
]
WindowsPipelineBlockerTaskSource = Literal[
    "preflight",
    "target_pipeline",
    "scan_rejection",
]


class WindowsPipelineBlockerTaskPlanArgs(BaseModel):
    blocker_worklist_path: str | None = Field(
        None,
        description="Optional target-pipeline blocker-worklist JSON artifact.",
    )
    preflight_path: str | None = Field(
        None,
        description="Optional high-volume preflight JSON artifact.",
    )
    build_corpus_manifest: str | None = None
    corpus_root: str | None = None
    project_root: str | None = None
    metadata_root: str | None = None
    artifact_dir: str = "artifacts/windows-target-pipeline/high-volume"
    max_tasks: int = Field(32, ge=1, le=256)
    output_path: str | None = Field(
        None,
        description="Optional JSON path to persist the generated task plan.",
    )
    add_to_kb: bool = False


class WindowsPipelineBlockerTask(BaseModel):
    rank: int
    kind: WindowsPipelineBlockerTaskKind
    source_kind: WindowsPipelineBlockerTaskSource
    title: str
    priority: int
    target_ids: list[str] = Field(default_factory=list)
    candidate_ids: list[str] = Field(default_factory=list)
    stages: list[str] = Field(default_factory=list)
    blocker_count: int = 1
    blockers: list[str] = Field(default_factory=list)
    required_artifacts: list[str] = Field(default_factory=list)
    next_tool_name: str | None = None
    next_tool_args: dict[str, Any] = Field(default_factory=dict)
    commands: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)


class WindowsPipelineBlockerTaskPlanResult(BaseModel):
    claim_level: str = "pipeline_blocker_task_plan_not_finding"
    task_count: int
    tasks: list[WindowsPipelineBlockerTask]
    source_paths: list[str] = Field(default_factory=list)
    output_path: str | None = None
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    tool_sequence: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsPipelineBlockerTaskPlanTool(
    MemoryTool[
        WindowsPipelineBlockerTaskPlanArgs,
        WindowsPipelineBlockerTaskPlanResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_pipeline_blocker_task_plan",
                description=(
                    "Convert high-volume preflight and target-pipeline blocker "
                    "artifacts into concrete project-cache, metadata, scanner, "
                    "validation, runtime, and symbol/similarity follow-up tasks."
                ),
                tags=("windows", "pipeline", "blockers", "worklist", "ci"),
            ),
            WindowsPipelineBlockerTaskPlanArgs,
            WindowsPipelineBlockerTaskPlanResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsPipelineBlockerTaskPlanArgs,
    ) -> WindowsPipelineBlockerTaskPlanResult:
        if not args.preflight_path and not args.blocker_worklist_path:
            raise ValueError("provide preflight_path, blocker_worklist_path, or both")

        warnings: list[str] = []
        blockers: list[str] = []
        tool_sequence = ["windows_pipeline_blocker_task_plan"]
        source_paths: list[str] = []
        targets_by_id = _load_targets_by_id(ctx, kb, args, warnings, tool_sequence)
        tasks: list[WindowsPipelineBlockerTask] = []

        if args.preflight_path:
            preflight_path = Path(args.preflight_path).expanduser()
            preflight = WindowsHighVolumePreflightResult.model_validate(
                _load_structured(preflight_path)
            )
            source_paths.append(str(preflight_path))
            tool_sequence.append("windows_high_volume_preflight:artifact")
            tasks.extend(_preflight_tasks(preflight, args, targets_by_id))

        if args.blocker_worklist_path:
            worklist_path = Path(args.blocker_worklist_path).expanduser()
            worklist = WindowsTargetPipelineBlockerWorklist.model_validate(
                _load_structured(worklist_path)
            )
            source_paths.append(str(worklist_path))
            tool_sequence.append("windows_target_pipeline_blocker_worklist:artifact")
            tasks.extend(_worklist_tasks(worklist, args))

        tasks = _rank_tasks(tasks)[: args.max_tasks]
        notes = [
            "Pipeline blocker task plans are remediation worklists, not findings.",
            "Run the listed deterministic tools, then rerun preflight or target-pipeline.",
        ]
        output_path = _write_result(args.output_path, tasks, source_paths, warnings)
        if output_path:
            tool_sequence.append("windows_pipeline_blocker_task_plan:write_output")
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_pipeline_blocker_task_plan",
                    props={
                        "task_count": len(tasks),
                        "source_paths": source_paths,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsPipelineBlockerTaskPlanResult(
            task_count=len(tasks),
            tasks=tasks,
            source_paths=source_paths,
            output_path=output_path,
            blockers=blockers,
            warnings=_dedupe(warnings),
            tool_sequence=_dedupe(tool_sequence),
            evidence_bundle=_evidence_bundle(
                tasks=tasks,
                source_paths=source_paths,
                blockers=blockers,
                warnings=warnings,
                tool_sequence=_dedupe(tool_sequence),
                output_path=output_path,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _load_targets_by_id(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsPipelineBlockerTaskPlanArgs,
    warnings: list[str],
    tool_sequence: list[str],
) -> dict[str, WindowsBuildCorpusTarget]:
    if not args.build_corpus_manifest:
        return {}
    try:
        corpus = WindowsBuildCorpusTool().run(
            ctx,
            kb,
            WindowsBuildCorpusArgs(
                manifest_path=args.build_corpus_manifest,
                corpus_root=args.corpus_root,
                project_root=args.project_root,
                max_matches=4,
            ),
        )
    except Exception as exc:
        warnings.append(f"could not load build corpus manifest: {exc}")
        return {}
    tool_sequence.append("windows_build_corpus")
    return {target.id: target for target in corpus.targets}


def _preflight_tasks(
    preflight: WindowsHighVolumePreflightResult,
    args: WindowsPipelineBlockerTaskPlanArgs,
    targets_by_id: dict[str, WindowsBuildCorpusTarget],
) -> list[WindowsPipelineBlockerTask]:
    tasks: list[WindowsPipelineBlockerTask] = []
    for target in preflight.targets:
        if target.ready:
            continue
        for blocker in target.blockers:
            if "project cache missing" in blocker.lower():
                tasks.append(_project_cache_task(target.target_id, blocker, target, args, targets_by_id))
            elif "corpus binary missing" in blocker.lower():
                tasks.append(_corpus_binary_task(target.target_id, blocker, target))
            else:
                tasks.append(
                    _basic_task(
                        kind="unknown",
                        source_kind="preflight",
                        title=f"Review preflight blocker for {target.target_id}",
                        priority=10,
                        target_ids=[target.target_id],
                        blockers=[blocker],
                        next_tool_name="windows_high_volume_preflight",
                        reason_codes=["preflight_blocker", "unknown_blocker"],
                    )
                )
    return tasks


def _project_cache_task(
    target_id: str,
    blocker: str,
    target,
    args: WindowsPipelineBlockerTaskPlanArgs,
    targets_by_id: dict[str, WindowsBuildCorpusTarget],
) -> WindowsPipelineBlockerTask:
    build_target = targets_by_id.get(target_id)
    pe_path = _first([*target.corpus_paths, *(_target_corpus_paths(build_target) if build_target else [])])
    project_path = _first(
        [
            *target.project_paths,
            *(_expected_project_paths(build_target, args.project_root) if build_target else []),
        ]
    )
    next_args: dict[str, Any] = {"target_id": target_id}
    commands: list[str] = []
    project_facts_output_path = (
        str(Path(args.metadata_root) / "pe-project-facts.yaml")
        if args.metadata_root
        else None
    )
    if pe_path and project_path:
        binary_filename = build_target.filename if build_target else None
        architecture = (
            build_target.architectures[0]
            if build_target and build_target.architectures
            else "x64"
        )
        project_fact_id = f"{target_id}_unknown" if build_target else None
        build_label = "unknown" if build_target else None
        next_args.update(
            {
                "pe_path": pe_path,
                "project_path": project_path,
                "index_callgraph": True,
                "index_data_xrefs": True,
                "index_cfg": True,
                "index_branch_conditions": True,
                "project_facts_output_path": project_facts_output_path,
                "binary_filename": binary_filename,
                "architecture": architecture,
            }
        )
        if build_target:
            next_args["project_fact_id"] = project_fact_id
            next_args["build_label"] = build_label
        cmd_parts = [
            "uv",
            "run",
            "glaurung",
            "windows",
            "bootstrap-project-facts",
            "--pe-path",
            pe_path,
            "--project-path",
            project_path,
            "--target-id",
            target_id,
            "--architecture",
            architecture,
        ]
        if binary_filename:
            cmd_parts.extend(["--binary-filename", binary_filename])
        if project_fact_id:
            cmd_parts.extend(["--project-fact-id", project_fact_id])
        if build_label:
            cmd_parts.extend(["--build-label", build_label])
        if project_facts_output_path:
            cmd_parts.extend(["--project-facts-output-path", project_facts_output_path])
        commands.append(" ".join(shlex.quote(part) for part in cmd_parts))
    return _basic_task(
        kind="project_cache_refresh",
        source_kind="preflight",
        title=f"Build .glaurung project cache for {target_id}",
        priority=100,
        target_ids=[target_id],
        blockers=[blocker],
        required_artifacts=[".glaurung project cache", "project-fact manifest row"],
        next_tool_name="windows_bootstrap_project_facts",
        next_tool_args=next_args,
        commands=commands,
        reason_codes=["preflight_project_cache_missing", "windows_bootstrap_project_facts"],
    )


def _corpus_binary_task(
    target_id: str,
    blocker: str,
    target,
) -> WindowsPipelineBlockerTask:
    return _basic_task(
        kind="corpus_binary_vendor",
        source_kind="preflight",
        title=f"Vendor corpus binary for {target_id}",
        priority=98,
        target_ids=[target_id],
        blockers=[blocker],
        required_artifacts=["Windows PE corpus binary"],
        next_tool_name="windows_build_corpus",
        next_tool_args={"target_id": target_id, "filename": target.filename},
        reason_codes=["preflight_corpus_binary_missing"],
    )


def _worklist_tasks(
    worklist: WindowsTargetPipelineBlockerWorklist,
    args: WindowsPipelineBlockerTaskPlanArgs,
) -> list[WindowsPipelineBlockerTask]:
    return [_task_from_work_item(item, args) for item in worklist.work_items]


def _task_from_work_item(
    item: WindowsTargetPipelineBlockerWorkItem,
    args: WindowsPipelineBlockerTaskPlanArgs,
) -> WindowsPipelineBlockerTask:
    kind = _task_kind(item.kind)
    next_tool, next_args = _next_tool(item, args)
    return _basic_task(
        kind=kind,
        source_kind="target_pipeline",
        title=_task_title(kind, item),
        priority=_task_priority(kind),
        target_ids=list(item.target_ids),
        candidate_ids=list(item.candidate_ids),
        stages=list(item.stages),
        blocker_count=item.count,
        blockers=[item.blocker],
        required_artifacts=([item.required_artifact] if item.required_artifact else []),
        next_tool_name=next_tool,
        next_tool_args=next_args,
        reason_codes=_dedupe([*item.reason_codes, _reason_code_for_task(kind)]),
    )


def _task_kind(kind: WindowsTargetPipelineBlockerKind) -> WindowsPipelineBlockerTaskKind:
    if kind == "project_cache":
        return "project_cache_refresh"
    if kind == "source_gate_metadata":
        return "source_gate_metadata"
    if kind == "validation_inventory":
        return "validation_inventory"
    if kind == "harness":
        return "harness"
    if kind == "runtime_artifact":
        return "runtime_artifact"
    if kind == "functionization":
        return "functionization_rule"
    if kind == "symbol_similarity":
        return "symbol_similarity_extract"
    if kind == "packet_grounding":
        return "packet_grounding"
    return "unknown"


def _next_tool(
    item: WindowsTargetPipelineBlockerWorkItem,
    args: WindowsPipelineBlockerTaskPlanArgs,
) -> tuple[str | None, dict[str, Any]]:
    base_args: dict[str, Any] = {
        "target_ids": list(item.target_ids),
        "candidate_ids": list(item.candidate_ids),
        "blocker": item.blocker,
    }
    if item.kind == "project_cache":
        return "windows_bootstrap_project_facts", base_args
    if item.kind == "source_gate_metadata":
        return "windows_sink_to_gate_review", base_args
    if item.kind == "validation_inventory":
        return "windows_validation_planning_batch", base_args
    if item.kind == "harness":
        return "windows_emit_validation_harness_template", base_args
    if item.kind == "runtime_artifact":
        return "windows_record_validation_artifact_bundle", base_args
    if item.kind == "functionization":
        return "windows_scan_rejection_dashboard", base_args
    if item.kind == "symbol_similarity":
        base_args["artifact_dir"] = args.artifact_dir
        return "windows_symbol_similarity_extraction_plan", base_args
    if item.kind == "packet_grounding":
        return "windows_emit_review_packet", base_args
    return None, base_args


def _task_title(
    kind: WindowsPipelineBlockerTaskKind,
    item: WindowsTargetPipelineBlockerWorkItem,
) -> str:
    target = f" for {', '.join(item.target_ids)}" if item.target_ids else ""
    return {
        "project_cache_refresh": f"Refresh project cache{target}",
        "corpus_binary_vendor": f"Vendor corpus binary{target}",
        "source_gate_metadata": f"Refine source/gate metadata{target}",
        "validation_inventory": f"Update validation inventory{target}",
        "harness": f"Add validation harness/KDNET precondition{target}",
        "runtime_artifact": f"Collect runtime artifact bundle{target}",
        "functionization_rule": f"Review functionization/scanner gate{target}",
        "symbol_similarity_extract": f"Extract symbol/similarity identity{target}",
        "packet_grounding": f"Ground candidate packet{target}",
        "unknown": f"Classify recurring blocker{target}",
    }[kind]


def _task_priority(kind: WindowsPipelineBlockerTaskKind) -> int:
    return {
        "project_cache_refresh": 100,
        "corpus_binary_vendor": 98,
        "source_gate_metadata": 95,
        "validation_inventory": 85,
        "harness": 80,
        "symbol_similarity_extract": 70,
        "functionization_rule": 65,
        "packet_grounding": 60,
        "runtime_artifact": 50,
        "unknown": 10,
    }[kind]


def _reason_code_for_task(kind: WindowsPipelineBlockerTaskKind) -> str:
    return f"task:{kind}"


def _basic_task(
    *,
    kind: WindowsPipelineBlockerTaskKind,
    source_kind: WindowsPipelineBlockerTaskSource,
    title: str,
    priority: int,
    target_ids: list[str] | None = None,
    candidate_ids: list[str] | None = None,
    stages: list[str] | None = None,
    blocker_count: int = 1,
    blockers: list[str] | None = None,
    required_artifacts: list[str] | None = None,
    next_tool_name: str | None = None,
    next_tool_args: dict[str, Any] | None = None,
    commands: list[str] | None = None,
    reason_codes: list[str] | None = None,
) -> WindowsPipelineBlockerTask:
    return WindowsPipelineBlockerTask(
        rank=0,
        kind=kind,
        source_kind=source_kind,
        title=title,
        priority=priority,
        target_ids=_dedupe(target_ids or []),
        candidate_ids=_dedupe(candidate_ids or []),
        stages=_dedupe(stages or []),
        blocker_count=blocker_count,
        blockers=_dedupe(blockers or []),
        required_artifacts=_dedupe(required_artifacts or []),
        next_tool_name=next_tool_name,
        next_tool_args=next_tool_args or {},
        commands=commands or [],
        reason_codes=_dedupe(reason_codes or []),
    )


def _rank_tasks(tasks: list[WindowsPipelineBlockerTask]) -> list[WindowsPipelineBlockerTask]:
    keyed: dict[tuple[str, tuple[str, ...], str], WindowsPipelineBlockerTask] = {}
    for task in tasks:
        key = (task.kind, tuple(task.target_ids), ";".join(task.blockers))
        existing = keyed.get(key)
        if existing is None:
            keyed[key] = task
            continue
        keyed[key] = existing.model_copy(
            update={
                "candidate_ids": _dedupe([*existing.candidate_ids, *task.candidate_ids]),
                "stages": _dedupe([*existing.stages, *task.stages]),
                "blocker_count": existing.blocker_count + task.blocker_count,
                "reason_codes": _dedupe([*existing.reason_codes, *task.reason_codes]),
                "commands": _dedupe([*existing.commands, *task.commands]),
            }
        )
    ranked = sorted(
        keyed.values(),
        key=lambda item: (
            -item.priority,
            -item.blocker_count,
            item.kind,
            ",".join(item.target_ids),
            item.title,
        ),
    )
    return [
        task.model_copy(update={"rank": index})
        for index, task in enumerate(ranked, start=1)
    ]


def _target_corpus_paths(target: WindowsBuildCorpusTarget) -> list[str]:
    return [match.path for match in target.corpus_matches]


def _expected_project_paths(
    target: WindowsBuildCorpusTarget,
    project_root_text: str | None,
) -> list[str]:
    if not project_root_text:
        return []
    root = Path(project_root_text).expanduser()
    out: list[str] = []
    for pattern in target.project_globs:
        if glob.has_magic(pattern):
            continue
        out.append(str(root / pattern))
    return out


def _first(values: list[str]) -> str | None:
    for value in values:
        if value:
            return value
    return None


def _load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


def _write_result(
    path_text: str | None,
    tasks: list[WindowsPipelineBlockerTask],
    source_paths: list[str],
    warnings: list[str],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "claim_level": "pipeline_blocker_task_plan_not_finding",
        "task_count": len(tasks),
        "tasks": [task.model_dump(mode="json") for task in tasks],
        "source_paths": source_paths,
        "warnings": _dedupe(warnings),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _evidence_bundle(
    *,
    tasks: list[WindowsPipelineBlockerTask],
    source_paths: list[str],
    blockers: list[str],
    warnings: list[str],
    tool_sequence: list[str],
    output_path: str | None,
    notes: list[str],
) -> WindowsEvidenceBundle:
    task_kinds = sorted({task.kind for task in tasks})
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "task_count": len(tasks),
                "source_count": len(source_paths),
                "output_path": output_path,
                "warning_count": len(warnings),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_pipeline_blocker_task_plan",
                summary=f"generated {len(tasks)} blocker remediation task(s)",
                reason_codes=[
                    "pipeline_blocker_task_plan_not_finding",
                    *task_kinds,
                ],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=source_paths,
            stale_or_blocking_facts=[
                blocker for task in tasks for blocker in task.blockers
            ],
            validation_ready=len(tasks) == 0,
        ),
        reason_codes=["pipeline_blocker_task_plan_not_finding", *task_kinds],
        blockers=blockers,
        next_actions=[
            f"{task.next_tool_name}: {task.title}"
            for task in tasks
            if task.next_tool_name
        ],
        notes=notes,
    )


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsPipelineBlockerTaskPlanTool:
    return WindowsPipelineBlockerTaskPlanTool()
