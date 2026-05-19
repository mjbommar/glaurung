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


class WindowsOperationReturnValueSnapshotsArgs(BaseModel):
    snapshots_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-operation-return-value-snapshots.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(None, description="Optional target id filter.")
    component: str | None = Field(None, description="Optional component filename filter.")
    backlog_id: str | None = Field(None, description="Optional backlog entry id filter.")
    symbol: str | None = Field(None, description="Optional exact backlog symbol filter.")
    use_kind: str | None = Field(
        None,
        description="Optional return-use kind filter, e.g. null_or_status_check.",
    )
    min_sampled_callsite_count: int = Field(
        0,
        ge=0,
        description="Only return groups with at least this many sampled callsites.",
    )
    max_snapshots: int = Field(
        16,
        ge=0,
        le=256,
        description="Maximum snapshots to return.",
    )
    max_samples_per_group: int = Field(
        8,
        ge=0,
        le=128,
        description="Maximum representative samples to return per group.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact return-value snapshot evidence node to the KB.",
    )


class WindowsOperationReturnUseFact(BaseModel):
    use_kind: str
    instruction_va: str
    instruction_text: str
    branch_va: str | None = None
    branch_text: str | None = None
    expression: str | None = None


class WindowsOperationReturnUseSample(BaseModel):
    callsite_va: str
    caller_name: str
    first_use_kind: str
    coverage: list[str] = Field(default_factory=list)
    uses: list[WindowsOperationReturnUseFact] = Field(default_factory=list)


class WindowsOperationReturnValueGroup(BaseModel):
    backlog_id: str
    symbol: str
    triage_category: str
    candidate_operation_kinds: list[str]
    likely_security_relevance: str
    required_capabilities: list[str]
    metadata_observed_callsite_count: int
    project_callsite_count: int
    sampled_callsite_count: int
    project_caller_function_count: int
    sample_callers: list[str] = Field(default_factory=list)
    use_kind_counts: dict[str, int] = Field(default_factory=dict)
    checked_callsite_count: int
    branch_related_callsite_count: int
    clobbered_callsite_count: int
    ignored_callsite_count: int
    sample_return_uses: list[WindowsOperationReturnUseSample] = Field(default_factory=list)
    recommended_next_actions: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsOperationReturnValueSnapshot(BaseModel):
    id: str
    target_id: str
    component: str
    build_label: str
    binary_id: int
    binary_path: str
    binary_sha256: str
    project_path: str
    backlog_path: str
    sinks_path: str
    source_backlog_snapshot_id: str
    tool: str
    tool_commit: str
    generated_on: str
    scanned_callsite_count: int
    backlog_entry_count_total: int
    matched_backlog_entry_count: int
    matched_project_callsite_count: int
    sampled_callsite_count: int
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    groups: list[WindowsOperationReturnValueGroup] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WindowsOperationReturnValueSnapshotsResult(BaseModel):
    snapshots_path: str
    snapshot_count_total: int
    snapshots: list[WindowsOperationReturnValueSnapshot]
    returned_snapshot_count: int
    returned_group_count: int
    returned_sample_count: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsOperationReturnValueSnapshotsTool(
    MemoryTool[
        WindowsOperationReturnValueSnapshotsArgs,
        WindowsOperationReturnValueSnapshotsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_operation_return_value_snapshots",
                description=(
                    "Load ASB precomputed local return-value-use snapshots "
                    "for Windows operation backlog entries."
                ),
                tags=("windows", "pe", "metadata", "operations", "return-values"),
            ),
            WindowsOperationReturnValueSnapshotsArgs,
            WindowsOperationReturnValueSnapshotsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsOperationReturnValueSnapshotsArgs,
    ) -> WindowsOperationReturnValueSnapshotsResult:
        snapshots_path = _resolve_metadata_path(
            args.snapshots_path,
            "data/kg/pe-operation-return-value-snapshots.yaml",
        )
        snapshots = [
            _snapshot(entry, args) for entry in _load_yaml_list(snapshots_path)
        ]
        total = len(snapshots)
        snapshots = [snapshot for snapshot in snapshots if _snapshot_matches(snapshot, args)]
        snapshots = snapshots[: args.max_snapshots]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_operation_return_value_snapshots",
                    props={
                        "target_id": args.target_id,
                        "component": args.component,
                        "backlog_id": args.backlog_id,
                        "symbol": args.symbol,
                        "use_kind": args.use_kind,
                        "snapshot_matches": len(snapshots),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        returned_group_count = sum(len(snapshot.groups) for snapshot in snapshots)
        returned_sample_count = sum(
            len(group.sample_return_uses)
            for snapshot in snapshots
            for group in snapshot.groups
        )
        return WindowsOperationReturnValueSnapshotsResult(
            snapshots_path=str(snapshots_path),
            snapshot_count_total=total,
            snapshots=snapshots,
            returned_snapshot_count=len(snapshots),
            returned_group_count=returned_group_count,
            returned_sample_count=returned_sample_count,
            evidence_node_id=evidence_node_id,
            notes=[
                "return-value snapshots are bounded local post-call samples; "
                "they are not interprocedural return-flow proof or findings"
            ],
        )


def _snapshot(
    entry: dict[str, Any],
    args: WindowsOperationReturnValueSnapshotsArgs,
) -> WindowsOperationReturnValueSnapshot:
    groups = [_group(group, args) for group in entry.get("groups") or []]
    groups = [group for group in groups if _group_matches(group, args)]
    return WindowsOperationReturnValueSnapshot(
        id=_required_str(entry, "id"),
        target_id=_required_str(entry, "target_id"),
        component=_required_str(entry, "component"),
        build_label=_required_str(entry, "build_label"),
        binary_id=int(entry.get("binary_id") or 0),
        binary_path=_required_str(entry, "binary_path"),
        binary_sha256=_required_str(entry, "binary_sha256"),
        project_path=_required_str(entry, "project_path"),
        backlog_path=_required_str(entry, "backlog_path"),
        sinks_path=_required_str(entry, "sinks_path"),
        source_backlog_snapshot_id=_required_str(entry, "source_backlog_snapshot_id"),
        tool=_required_str(entry, "tool"),
        tool_commit=_required_str(entry, "tool_commit"),
        generated_on=str(entry.get("generated_on") or ""),
        scanned_callsite_count=int(entry.get("scanned_callsite_count") or 0),
        backlog_entry_count_total=int(entry.get("backlog_entry_count_total") or 0),
        matched_backlog_entry_count=int(entry.get("matched_backlog_entry_count") or 0),
        matched_project_callsite_count=int(entry.get("matched_project_callsite_count") or 0),
        sampled_callsite_count=int(entry.get("sampled_callsite_count") or 0),
        coverage=[str(value) for value in entry.get("coverage") or []],
        missing_capabilities=[
            str(value) for value in entry.get("missing_capabilities") or []
        ],
        groups=groups,
        notes=[str(value) for value in entry.get("notes") or []],
    )


def _group(
    entry: dict[str, Any],
    args: WindowsOperationReturnValueSnapshotsArgs,
) -> WindowsOperationReturnValueGroup:
    samples = [_sample(sample) for sample in entry.get("sample_return_uses") or []]
    if args.use_kind:
        samples = [
            sample
            for sample in samples
            if sample.first_use_kind == args.use_kind
            or any(use.use_kind == args.use_kind for use in sample.uses)
        ]
    return WindowsOperationReturnValueGroup(
        backlog_id=_required_str(entry, "backlog_id"),
        symbol=_required_str(entry, "symbol"),
        triage_category=_required_str(entry, "triage_category"),
        candidate_operation_kinds=[
            str(value) for value in entry.get("candidate_operation_kinds") or []
        ],
        likely_security_relevance=_required_str(entry, "likely_security_relevance"),
        required_capabilities=[
            str(value) for value in entry.get("required_capabilities") or []
        ],
        metadata_observed_callsite_count=int(
            entry.get("metadata_observed_callsite_count") or 0
        ),
        project_callsite_count=int(entry.get("project_callsite_count") or 0),
        sampled_callsite_count=int(entry.get("sampled_callsite_count") or 0),
        project_caller_function_count=int(
            entry.get("project_caller_function_count") or 0
        ),
        sample_callers=[str(value) for value in entry.get("sample_callers") or []],
        use_kind_counts={
            str(key): int(value)
            for key, value in (entry.get("use_kind_counts") or {}).items()
        },
        checked_callsite_count=int(entry.get("checked_callsite_count") or 0),
        branch_related_callsite_count=int(
            entry.get("branch_related_callsite_count") or 0
        ),
        clobbered_callsite_count=int(entry.get("clobbered_callsite_count") or 0),
        ignored_callsite_count=int(entry.get("ignored_callsite_count") or 0),
        sample_return_uses=samples[: args.max_samples_per_group],
        recommended_next_actions=[
            str(value) for value in entry.get("recommended_next_actions") or []
        ],
        notes=entry.get("notes"),
    )


def _sample(entry: dict[str, Any]) -> WindowsOperationReturnUseSample:
    return WindowsOperationReturnUseSample(
        callsite_va=_required_str(entry, "callsite_va"),
        caller_name=_required_str(entry, "caller_name"),
        first_use_kind=_required_str(entry, "first_use_kind"),
        coverage=[str(value) for value in entry.get("coverage") or []],
        uses=[_use(use) for use in entry.get("uses") or []],
    )


def _use(entry: dict[str, Any]) -> WindowsOperationReturnUseFact:
    return WindowsOperationReturnUseFact(
        use_kind=_required_str(entry, "use_kind"),
        instruction_va=_required_str(entry, "instruction_va"),
        instruction_text=_required_str(entry, "instruction_text"),
        branch_va=_optional_str(entry.get("branch_va")),
        branch_text=_optional_str(entry.get("branch_text")),
        expression=_optional_str(entry.get("expression")),
    )


def _snapshot_matches(
    snapshot: WindowsOperationReturnValueSnapshot,
    args: WindowsOperationReturnValueSnapshotsArgs,
) -> bool:
    if args.target_id and snapshot.target_id != args.target_id:
        return False
    if args.component and snapshot.component.lower() != args.component.lower():
        return False
    return bool(snapshot.groups)


def _group_matches(
    group: WindowsOperationReturnValueGroup,
    args: WindowsOperationReturnValueSnapshotsArgs,
) -> bool:
    if args.backlog_id and group.backlog_id != args.backlog_id:
        return False
    if args.symbol and group.symbol != args.symbol:
        return False
    if group.sampled_callsite_count < args.min_sampled_callsite_count:
        return False
    if args.use_kind and args.use_kind not in group.use_kind_counts:
        return False
    return True


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: snapshot entry {idx} is not a mapping")
        out.append(entry)
    return out


def _required_str(entry: dict[str, Any], key: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"snapshot entry missing required string field {key!r}")
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def build_tool() -> WindowsOperationReturnValueSnapshotsTool:
    return WindowsOperationReturnValueSnapshotsTool()
