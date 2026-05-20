"""Review high-volume Windows runner artifact directories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

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


WindowsRunnerArtifactReviewMode = Literal[
    "auto",
    "target_pipeline",
    "ghidra_parity",
]
WindowsRunnerArtifactKind = Literal[
    "preflight",
    "preflight_task_plan",
    "target_pipeline",
    "blocker_worklist",
    "blocker_task_plan",
    "pipeline_export",
    "evidence_export",
    "corpus_guard",
    "ghidra_parity_json",
    "ghidra_parity_markdown",
    "unknown",
]


class WindowsRunnerArtifactReviewArgs(BaseModel):
    artifact_dir: str = Field(..., description="Directory uploaded by a runner job.")
    mode: WindowsRunnerArtifactReviewMode = "auto"
    output_path: str | None = Field(
        None,
        description="Optional JSON path to persist this review.",
    )
    add_to_kb: bool = False


class WindowsRunnerArtifactEntry(BaseModel):
    name: str
    path: str
    kind: WindowsRunnerArtifactKind
    exists: bool
    valid_json: bool | None = None
    size_bytes: int | None = None
    summary: str | None = None
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class WindowsRunnerArtifactReviewResult(BaseModel):
    claim_level: str = "windows_runner_artifact_review_not_finding"
    mode: WindowsRunnerArtifactReviewMode
    artifact_dir: str
    review_ready: bool
    promotion_ready: bool
    preflight_ready: bool | None = None
    candidate_count: int = 0
    planned_count: int = 0
    blocker_work_item_count: int = 0
    task_count: int = 0
    artifact_count_present: int = 0
    artifacts: list[WindowsRunnerArtifactEntry]
    promotable_artifacts: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    output_path: str | None = None
    tool_sequence: list[str] = Field(default_factory=list)
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsRunnerArtifactReviewTool(
    MemoryTool[WindowsRunnerArtifactReviewArgs, WindowsRunnerArtifactReviewResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_runner_artifact_review",
                description=(
                    "Review high-volume Windows target-pipeline or Ghidra parity "
                    "runner artifacts and decide whether outputs are blocked, "
                    "need follow-up tasks, or are ready to promote as baselines."
                ),
                tags=("windows", "runner", "artifacts", "ci", "review"),
            ),
            WindowsRunnerArtifactReviewArgs,
            WindowsRunnerArtifactReviewResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRunnerArtifactReviewArgs,
    ) -> WindowsRunnerArtifactReviewResult:
        artifact_dir = Path(args.artifact_dir).expanduser()
        if not artifact_dir.exists():
            raise ValueError(f"{artifact_dir}: artifact directory does not exist")
        mode = _resolve_mode(args.mode, artifact_dir)
        parsed: dict[str, Any] = {}
        artifacts = _artifact_entries(mode, artifact_dir, parsed)
        blockers, warnings = _review_blockers(mode, parsed, artifacts)
        preflight_ready = _get_bool(parsed.get("preflight"), "ready")
        candidate_count = _get_int(parsed.get("target_pipeline"), "candidate_count")
        planned_count = _get_int(parsed.get("target_pipeline"), "planned_count")
        blocker_work_item_count = max(
            _get_int(parsed.get("target_pipeline"), "blocker_work_item_count"),
            _get_int(parsed.get("blocker_worklist"), "blocker_work_item_count"),
        )
        task_count = (
            _get_int(parsed.get("blocker_task_plan"), "task_count")
            + _get_int(parsed.get("preflight_task_plan"), "task_count")
        )
        review_ready = any(entry.exists for entry in artifacts) and not any(
            entry.blockers for entry in artifacts
        )
        promotion_ready = review_ready and not blockers and task_count == 0
        promotable_artifacts = _promotable_artifacts(mode, parsed, artifacts, promotion_ready)
        next_actions = _next_actions(parsed)
        output_path = _write_result(
            args.output_path,
            mode=mode,
            artifact_dir=str(artifact_dir),
            promotion_ready=promotion_ready,
            artifacts=artifacts,
            blockers=blockers,
            warnings=warnings,
            next_actions=next_actions,
        )
        tool_sequence = ["windows_runner_artifact_review"]
        if output_path:
            tool_sequence.append("windows_runner_artifact_review:write_output")
        notes = [
            "Runner artifact review is a promotion/readiness review, not finding evidence.",
            "Promotion means artifact-baseline promotion only, not vulnerability promotion.",
        ]
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_runner_artifact_review",
                    props={
                        "artifact_dir": str(artifact_dir),
                        "mode": mode,
                        "promotion_ready": promotion_ready,
                        "blocker_count": len(blockers),
                        "task_count": task_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
        return WindowsRunnerArtifactReviewResult(
            mode=mode,
            artifact_dir=str(artifact_dir),
            review_ready=review_ready,
            promotion_ready=promotion_ready,
            preflight_ready=preflight_ready,
            candidate_count=candidate_count,
            planned_count=planned_count,
            blocker_work_item_count=blocker_work_item_count,
            task_count=task_count,
            artifact_count_present=sum(1 for entry in artifacts if entry.exists),
            artifacts=artifacts,
            promotable_artifacts=promotable_artifacts,
            blockers=blockers,
            warnings=warnings,
            next_actions=next_actions,
            output_path=output_path,
            tool_sequence=tool_sequence,
            evidence_bundle=_evidence_bundle(
                mode=mode,
                artifact_dir=str(artifact_dir),
                promotion_ready=promotion_ready,
                artifacts=artifacts,
                blockers=blockers,
                warnings=warnings,
                next_actions=next_actions,
                tool_sequence=tool_sequence,
                notes=notes,
            ),
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _resolve_mode(
    mode: WindowsRunnerArtifactReviewMode,
    artifact_dir: Path,
) -> WindowsRunnerArtifactReviewMode:
    if mode != "auto":
        return mode
    if (artifact_dir / "target-pipeline.json").exists() or (
        artifact_dir / "preflight.json"
    ).exists():
        return "target_pipeline"
    if (artifact_dir / "corpus-guard.json").exists():
        return "ghidra_parity"
    return "target_pipeline"


def _artifact_entries(
    mode: WindowsRunnerArtifactReviewMode,
    artifact_dir: Path,
    parsed: dict[str, Any],
) -> list[WindowsRunnerArtifactEntry]:
    names = _expected_names(mode, artifact_dir)
    out: list[WindowsRunnerArtifactEntry] = []
    for kind, name in names:
        path = artifact_dir / name
        payload, entry = _artifact_entry(path, kind)
        if payload is not None:
            parsed[kind] = payload
        out.append(entry)
    return out


def _expected_names(
    mode: WindowsRunnerArtifactReviewMode,
    artifact_dir: Path,
) -> list[tuple[WindowsRunnerArtifactKind, str]]:
    if mode == "ghidra_parity":
        return [
            ("corpus_guard", "corpus-guard.json"),
            (
                "ghidra_parity_json",
                _first_existing_name(
                    artifact_dir,
                    [
                        "glaurung_vs_ghidra_vendor_windows_30_refresh.json",
                        "glaurung_vs_ghidra_vendor_windows_30.json",
                    ],
                ),
            ),
            (
                "ghidra_parity_markdown",
                _first_existing_name(
                    artifact_dir,
                    [
                        "glaurung_vs_ghidra_vendor_windows_30_refresh.md",
                        "glaurung_vs_ghidra_vendor_windows_30.md",
                    ],
                ),
            ),
        ]
    return [
        ("preflight", "preflight.json"),
        ("preflight_task_plan", "preflight-task-plan.json"),
        ("target_pipeline", "target-pipeline.json"),
        ("blocker_worklist", "blocker-worklist.json"),
        ("blocker_task_plan", "blocker-task-plan.json"),
        ("pipeline_export", "pipeline-export.json"),
        ("evidence_export", "evidence-export.json"),
    ]


def _first_existing_name(artifact_dir: Path, names: list[str]) -> str:
    for name in names:
        if (artifact_dir / name).exists():
            return name
    return names[0]


def _artifact_entry(
    path: Path,
    kind: WindowsRunnerArtifactKind,
) -> tuple[Any | None, WindowsRunnerArtifactEntry]:
    if not path.exists():
        return None, WindowsRunnerArtifactEntry(
            name=path.name,
            path=str(path),
            kind=kind,
            exists=False,
            summary="missing",
        )
    size = path.stat().st_size
    if path.suffix.lower() != ".json":
        return None, WindowsRunnerArtifactEntry(
            name=path.name,
            path=str(path),
            kind=kind,
            exists=True,
            size_bytes=size,
            summary="present",
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, WindowsRunnerArtifactEntry(
            name=path.name,
            path=str(path),
            kind=kind,
            exists=True,
            valid_json=False,
            size_bytes=size,
            summary="invalid json",
            blockers=[f"{path.name}: invalid JSON: {exc}"],
        )
    return payload, WindowsRunnerArtifactEntry(
        name=path.name,
        path=str(path),
        kind=kind,
        exists=True,
        valid_json=True,
        size_bytes=size,
        summary=_summary(kind, payload),
    )


def _summary(kind: WindowsRunnerArtifactKind, payload: Any) -> str:
    if not isinstance(payload, dict):
        return "json payload is not an object"
    if kind == "preflight":
        return f"ready={payload.get('ready')} targets={payload.get('target_count')}"
    if kind == "target_pipeline":
        return (
            f"candidates={payload.get('candidate_count')} "
            f"blocker_items={payload.get('blocker_work_item_count')}"
        )
    if kind in {"blocker_task_plan", "preflight_task_plan"}:
        return f"tasks={payload.get('task_count')}"
    if kind == "blocker_worklist":
        return f"blocker_items={payload.get('blocker_work_item_count')}"
    if kind == "corpus_guard":
        return f"drift_guard_passed={payload.get('drift_guard_passed')}"
    return str(payload.get("claim_level") or "present")


def _review_blockers(
    mode: WindowsRunnerArtifactReviewMode,
    parsed: dict[str, Any],
    artifacts: list[WindowsRunnerArtifactEntry],
) -> tuple[list[str], list[str]]:
    blockers = [blocker for entry in artifacts for blocker in entry.blockers]
    warnings: list[str] = []
    if mode == "ghidra_parity":
        corpus_guard = parsed.get("corpus_guard")
        if isinstance(corpus_guard, dict) and not corpus_guard.get("drift_guard_passed", False):
            blockers.append("corpus guard did not pass")
        for kind in ("ghidra_parity_json", "ghidra_parity_markdown"):
            if not _entry_exists(artifacts, kind):
                blockers.append(f"{kind} artifact missing")
        return _dedupe(blockers), _dedupe(warnings)

    preflight = parsed.get("preflight")
    if isinstance(preflight, dict):
        if not preflight.get("ready", False):
            for blocker in preflight.get("blockers") or ["preflight not ready"]:
                blockers.append(f"preflight blocked: {blocker}")
    elif not _entry_exists(artifacts, "preflight"):
        blockers.append("preflight.json missing")

    target_pipeline_missing = not _entry_exists(artifacts, "target_pipeline")
    if target_pipeline_missing:
        if isinstance(preflight, dict) and not preflight.get("ready", False):
            warnings.append("target-pipeline.json missing after blocked preflight")
        else:
            blockers.append("target-pipeline.json missing")
    target_pipeline = parsed.get("target_pipeline")
    if isinstance(target_pipeline, dict):
        blockers.extend(str(item) for item in target_pipeline.get("blockers") or [])
        if _get_int(target_pipeline, "blocker_work_item_count") > 0:
            blockers.append("target pipeline produced blocker work items")
    for key in ("blocker_task_plan", "preflight_task_plan"):
        payload = parsed.get(key)
        if isinstance(payload, dict) and _get_int(payload, "task_count") > 0:
            blockers.append(f"{key} has {payload.get('task_count')} task(s)")
    return _dedupe(blockers), _dedupe(warnings)


def _promotable_artifacts(
    mode: WindowsRunnerArtifactReviewMode,
    parsed: dict[str, Any],
    artifacts: list[WindowsRunnerArtifactEntry],
    promotion_ready: bool,
) -> list[str]:
    if not promotion_ready:
        return []
    if mode == "ghidra_parity":
        return [
            entry.name
            for entry in artifacts
            if entry.exists and entry.kind in {"ghidra_parity_json", "ghidra_parity_markdown"}
        ]
    names = []
    for key in ("pipeline_export", "evidence_export", "target_pipeline"):
        entry = _entry_by_kind(artifacts, key)
        if entry and entry.exists:
            names.append(entry.name)
    export = parsed.get("pipeline_export")
    if isinstance(export, dict):
        names.extend(str(item) for item in export.get("generated_artifacts") or [])
    return _dedupe(names)


def _next_actions(parsed: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    for key in ("preflight_task_plan", "blocker_task_plan"):
        payload = parsed.get(key)
        if not isinstance(payload, dict):
            continue
        for task in payload.get("tasks") or []:
            if not isinstance(task, dict):
                continue
            tool = task.get("next_tool_name")
            title = task.get("title") or task.get("kind") or "follow-up task"
            if tool:
                actions.append(f"Run {tool}: {title}")
            else:
                actions.append(str(title))
    return _dedupe(actions)


def _entry_exists(
    artifacts: list[WindowsRunnerArtifactEntry],
    kind: str,
) -> bool:
    entry = _entry_by_kind(artifacts, kind)
    return bool(entry and entry.exists)


def _entry_by_kind(
    artifacts: list[WindowsRunnerArtifactEntry],
    kind: str,
) -> WindowsRunnerArtifactEntry | None:
    for entry in artifacts:
        if entry.kind == kind:
            return entry
    return None


def _get_bool(payload: Any, key: str) -> bool | None:
    if isinstance(payload, dict) and isinstance(payload.get(key), bool):
        return payload[key]
    return None


def _get_int(payload: Any, key: str) -> int:
    if isinstance(payload, dict) and isinstance(payload.get(key), int):
        return int(payload[key])
    return 0


def _write_result(
    path_text: str | None,
    *,
    mode: WindowsRunnerArtifactReviewMode,
    artifact_dir: str,
    promotion_ready: bool,
    artifacts: list[WindowsRunnerArtifactEntry],
    blockers: list[str],
    warnings: list[str],
    next_actions: list[str],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "claim_level": "windows_runner_artifact_review_not_finding",
        "mode": mode,
        "artifact_dir": artifact_dir,
        "promotion_ready": promotion_ready,
        "artifacts": [entry.model_dump(mode="json") for entry in artifacts],
        "blockers": blockers,
        "warnings": warnings,
        "next_actions": next_actions,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _evidence_bundle(
    *,
    mode: WindowsRunnerArtifactReviewMode,
    artifact_dir: str,
    promotion_ready: bool,
    artifacts: list[WindowsRunnerArtifactEntry],
    blockers: list[str],
    warnings: list[str],
    next_actions: list[str],
    tool_sequence: list[str],
    notes: list[str],
) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            attributes={
                "mode": mode,
                "artifact_dir": artifact_dir,
                "promotion_ready": promotion_ready,
                "artifact_count_present": sum(1 for entry in artifacts if entry.exists),
                "warning_count": len(warnings),
            },
        ),
        source_tools=tool_sequence,
        tool_sequence=tool_sequence,
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_runner_artifact_review",
                summary=(
                    f"reviewed {sum(1 for entry in artifacts if entry.exists)} "
                    f"runner artifact(s), promotion_ready={promotion_ready}"
                ),
                reason_codes=["windows_runner_artifact_review_not_finding", mode],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=[entry.path for entry in artifacts if entry.exists],
            missing_facts=[entry.name for entry in artifacts if not entry.exists],
            stale_or_blocking_facts=blockers,
            validation_ready=promotion_ready,
        ),
        reason_codes=["windows_runner_artifact_review_not_finding", mode],
        blockers=blockers,
        next_actions=next_actions,
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


def build_tool() -> WindowsRunnerArtifactReviewTool:
    return WindowsRunnerArtifactReviewTool()
