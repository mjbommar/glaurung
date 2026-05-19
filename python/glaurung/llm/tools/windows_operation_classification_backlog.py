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


SecurityRelevance = Literal["low", "medium", "high"]


class WindowsOperationBacklogEntry(BaseModel):
    id: str
    target_id: str
    component: str
    build_label: str
    source_snapshot_id: str
    symbol: str
    observed_callsite_count: int
    caller_function_count: int
    resolution_kind_counts: dict[str, int]
    sample_callers: list[str]
    triage_category: str
    candidate_operation_kinds: list[str]
    likely_security_relevance: SecurityRelevance
    required_capabilities: list[str]
    recommended_next_actions: list[str]
    notes: str | None = None


class WindowsOperationClassificationBacklogArgs(BaseModel):
    backlog_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-operation-classification-backlog.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    target_id: str | None = Field(None, description="Optional target id filter.")
    component: str | None = Field(
        None,
        description="Optional Windows component filename filter, e.g. cldflt.sys.",
    )
    symbol: str | None = Field(None, description="Optional exact callee symbol filter.")
    triage_category: str | None = Field(
        None,
        description="Optional backlog triage-category filter.",
    )
    required_capability: str | None = Field(
        None,
        description="Optional required Glaurung/ASB capability filter.",
    )
    likely_security_relevance: SecurityRelevance | None = Field(
        None,
        description="Optional security-relevance filter.",
    )
    min_callsite_count: int = Field(
        0,
        description="Only return entries with at least this many observed callsites.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact backlog evidence node to the KB.",
    )


class WindowsOperationClassificationBacklogResult(BaseModel):
    backlog_path: str
    entries: list[WindowsOperationBacklogEntry]
    entry_count_total: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsOperationClassificationBacklogTool(
    MemoryTool[
        WindowsOperationClassificationBacklogArgs,
        WindowsOperationClassificationBacklogResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_operation_classification_backlog",
                description=(
                    "Load ASB Windows operation-classification backlog entries "
                    "for actionable unmatched project call groups."
                ),
                tags=("windows", "pe", "metadata", "operations", "backlog"),
            ),
            WindowsOperationClassificationBacklogArgs,
            WindowsOperationClassificationBacklogResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsOperationClassificationBacklogArgs,
    ) -> WindowsOperationClassificationBacklogResult:
        backlog_path = _resolve_metadata_path(
            args.backlog_path,
            "data/kg/pe-operation-classification-backlog.yaml",
        )
        entries = [
            _backlog_entry(entry, backlog_path) for entry in _load_yaml_list(backlog_path)
        ]
        entry_count_total = len(entries)
        entries = _filter_entries(entries, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_operation_classification_backlog",
                    props={
                        "target_id": args.target_id,
                        "component": args.component,
                        "symbol": args.symbol,
                        "triage_category": args.triage_category,
                        "required_capability": args.required_capability,
                        "likely_security_relevance": args.likely_security_relevance,
                        "entry_matches": len(entries),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsOperationClassificationBacklogResult(
            backlog_path=str(backlog_path),
            entries=entries,
            entry_count_total=entry_count_total,
            evidence_node_id=evidence_node_id,
            notes=[
                "backlog entries are classifier work items, not sink claims or findings"
            ],
        )


def _filter_entries(
    entries: list[WindowsOperationBacklogEntry],
    args: WindowsOperationClassificationBacklogArgs,
) -> list[WindowsOperationBacklogEntry]:
    out = entries
    if args.target_id:
        out = [entry for entry in out if entry.target_id == args.target_id]
    if args.component:
        component = args.component.lower()
        out = [entry for entry in out if entry.component.lower() == component]
    if args.symbol:
        out = [entry for entry in out if entry.symbol == args.symbol]
    if args.triage_category:
        out = [entry for entry in out if entry.triage_category == args.triage_category]
    if args.required_capability:
        out = [
            entry
            for entry in out
            if args.required_capability in entry.required_capabilities
        ]
    if args.likely_security_relevance:
        out = [
            entry
            for entry in out
            if entry.likely_security_relevance == args.likely_security_relevance
        ]
    if args.min_callsite_count > 0:
        out = [
            entry
            for entry in out
            if entry.observed_callsite_count >= args.min_callsite_count
        ]
    return sorted(out, key=lambda entry: entry.observed_callsite_count, reverse=True)


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: operation backlog entry {idx} is not a mapping")
        out.append(entry)
    return out


def _backlog_entry(entry: dict[str, Any], path: Path) -> WindowsOperationBacklogEntry:
    callsite_count = int(entry.get("observed_callsite_count") or 0)
    caller_count = int(entry.get("caller_function_count") or 0)
    if callsite_count <= 0 or caller_count <= 0:
        raise ValueError(f"{path}: backlog {entry.get('id')!r} has bad call counts")
    relevance = _required_str(entry, "likely_security_relevance", path)
    if relevance not in {"low", "medium", "high"}:
        raise ValueError(f"{path}: backlog {entry.get('id')!r} has bad relevance")
    return WindowsOperationBacklogEntry(
        id=_required_str(entry, "id", path),
        target_id=_required_str(entry, "target_id", path),
        component=_required_str(entry, "component", path),
        build_label=_required_str(entry, "build_label", path),
        source_snapshot_id=_required_str(entry, "source_snapshot_id", path),
        symbol=_required_str(entry, "symbol", path),
        observed_callsite_count=callsite_count,
        caller_function_count=caller_count,
        resolution_kind_counts=_required_str_int_dict(
            entry,
            "resolution_kind_counts",
            path,
        ),
        sample_callers=_required_str_list(entry, "sample_callers", path),
        triage_category=_required_str(entry, "triage_category", path),
        candidate_operation_kinds=_required_str_list(
            entry,
            "candidate_operation_kinds",
            path,
        ),
        likely_security_relevance=relevance,  # type: ignore[arg-type]
        required_capabilities=_required_str_list(entry, "required_capabilities", path),
        recommended_next_actions=_required_str_list(
            entry,
            "recommended_next_actions",
            path,
        ),
        notes=entry.get("notes"),
    )


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty list field {key!r}")
    return [str(value) for value in values if str(value)]


def _required_str_int_dict(
    entry: dict[str, Any],
    key: str,
    path: Path,
) -> dict[str, int]:
    values = entry.get(key)
    if not isinstance(values, dict) or not values:
        raise ValueError(f"{path}: missing non-empty mapping field {key!r}")
    out: dict[str, int] = {}
    for raw_key, raw_value in values.items():
        name = str(raw_key)
        count = int(raw_value)
        if not name or count <= 0:
            raise ValueError(f"{path}: bad {key!r} entry")
        out[name] = count
    return out


def build_tool() -> MemoryTool[
    WindowsOperationClassificationBacklogArgs,
    WindowsOperationClassificationBacklogResult,
]:
    return WindowsOperationClassificationBacklogTool()
