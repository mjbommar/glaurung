from __future__ import annotations

from collections import Counter, defaultdict
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_project_callsite_facts import (
    ProjectCallsiteFact,
    WindowsProjectCallsiteFactsArgs,
    WindowsProjectCallsiteFactsTool,
)
from .windows_surface_metadata import _resolve_metadata_path


class WindowsProjectOperationCoverageSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    non_sinks_path: str | None = Field(
        None,
        description=(
            "Optional path to ASB data/kg/pe-non-sink-operations.yaml. "
            "When supplied, known tracing/debug/compiler support calls are "
            "classified separately from actionable unmatched backlog."
        ),
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter callsites.",
    )
    max_calls: int = Field(
        4096,
        ge=0,
        le=65536,
        description="Maximum project callsites to scan before summarizing coverage.",
    )
    max_unmatched: int = Field(
        32,
        ge=0,
        le=512,
        description="Maximum unmatched callee groups to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-coverage evidence node.",
    )


class WindowsProjectUnmatchedCallGroup(BaseModel):
    symbol: str
    count: int
    caller_function_count: int
    sample_callsites: list[int] = Field(default_factory=list)
    sample_callers: list[str] = Field(default_factory=list)
    resolution_kind_counts: dict[str, int] = Field(default_factory=dict)
    non_sink_category: str | None = None
    non_sink_disposition: str | None = None
    recommended_next_action: str


class NonSinkOperationRecord(BaseModel):
    id: str
    symbols: list[str]
    category: str
    disposition: str
    notes: str | None = None


class WindowsProjectOperationCoverageSummaryResult(BaseModel):
    project_path: str
    sinks_path: str
    non_sinks_path: str | None = None
    binary_id: int | None = None
    scanned_callsite_count: int
    returned_callsite_count: int
    operation_callsite_count: int
    unmatched_named_callsite_count: int
    unmatched_unnamed_callsite_count: int
    known_non_sink_callsite_count: int
    actionable_unmatched_named_callsite_count: int
    alias_or_thunk_match_count: int
    operation_match_rate: float
    resolution_kind_counts: dict[str, int] = Field(default_factory=dict)
    operation_kind_counts: dict[str, int] = Field(default_factory=dict)
    non_sink_category_counts: dict[str, int] = Field(default_factory=dict)
    unmatched_groups: list[WindowsProjectUnmatchedCallGroup] = Field(default_factory=list)
    known_non_sink_groups: list[WindowsProjectUnmatchedCallGroup] = Field(
        default_factory=list
    )
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOperationCoverageSummaryTool(
    MemoryTool[
        WindowsProjectOperationCoverageSummaryArgs,
        WindowsProjectOperationCoverageSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_operation_coverage_summary",
                description=(
                    "Summarize how many project callsites are already classified "
                    "as ASB operations, matched through alias/thunk normalization, "
                    "or still need sink metadata / target resolution."
                ),
                tags=("windows", "pe", "project", "operations", "coverage", "summary"),
            ),
            WindowsProjectOperationCoverageSummaryArgs,
            WindowsProjectOperationCoverageSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOperationCoverageSummaryArgs,
    ) -> WindowsProjectOperationCoverageSummaryResult:
        non_sink_records, non_sinks_path = _load_non_sink_records(args.non_sinks_path)
        callsites = WindowsProjectCallsiteFactsTool().run(
            ctx,
            kb,
            WindowsProjectCallsiteFactsArgs(
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                function_va=args.function_va,
                operation_only=False,
                max_calls=args.max_calls,
                add_to_kb=False,
            ),
        )

        facts = callsites.callsites
        operation_sites = [site for site in facts if site.operation is not None]
        unmatched_named = [
            site for site in facts if site.operation is None and _display_symbol(site)
        ]
        unmatched_unnamed = [
            site for site in facts if site.operation is None and not _display_symbol(site)
        ]
        non_sink_by_site = {
            site.callsite_va: record
            for site in unmatched_named
            if (record := _first_non_sink_match(site, non_sink_records)) is not None
        }
        known_non_sink_sites = [
            site for site in unmatched_named if site.callsite_va in non_sink_by_site
        ]
        actionable_unmatched_named = [
            site for site in unmatched_named if site.callsite_va not in non_sink_by_site
        ]
        alias_or_thunk_matches = [
            site
            for site in operation_sites
            if site.callee_aliases or site.callee_resolution_kind != "direct_name"
        ]

        operation_kind_counts = Counter(
            site.operation.sink_kind
            for site in operation_sites
            if site.operation is not None
        )
        resolution_kind_counts = Counter(site.callee_resolution_kind for site in facts)
        unmatched_groups = _unmatched_groups(
            actionable_unmatched_named,
            args.max_unmatched,
            non_sink_by_site,
        )
        known_non_sink_groups = _unmatched_groups(
            known_non_sink_sites,
            args.max_unmatched,
            non_sink_by_site,
        )
        non_sink_category_counts = Counter(
            non_sink_by_site[site.callsite_va].category for site in known_non_sink_sites
        )
        operation_match_rate = (
            round(len(operation_sites) / len(facts), 4) if facts else 0.0
        )
        coverage = _coverage(
            facts,
            operation_sites,
            alias_or_thunk_matches,
            unmatched_groups,
            known_non_sink_groups,
        )
        missing = _missing_capabilities(actionable_unmatched_named, unmatched_unnamed)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_operation_coverage_summary",
                    props={
                        "project_path": str(Path(args.project_path)),
                        "scanned_callsite_count": callsites.scanned_call_count,
                        "returned_callsite_count": len(facts),
                        "operation_callsite_count": len(operation_sites),
                        "unmatched_named_callsite_count": len(unmatched_named),
                        "unmatched_unnamed_callsite_count": len(unmatched_unnamed),
                        "known_non_sink_callsite_count": len(known_non_sink_sites),
                        "actionable_unmatched_named_callsite_count": len(
                            actionable_unmatched_named
                        ),
                        "alias_or_thunk_match_count": len(alias_or_thunk_matches),
                        "operation_match_rate": operation_match_rate,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOperationCoverageSummaryResult(
            project_path=str(Path(args.project_path)),
            sinks_path=callsites.sinks_path,
            non_sinks_path=str(non_sinks_path) if non_sinks_path else None,
            binary_id=callsites.binary_id,
            scanned_callsite_count=callsites.scanned_call_count,
            returned_callsite_count=len(facts),
            operation_callsite_count=len(operation_sites),
            unmatched_named_callsite_count=len(unmatched_named),
            unmatched_unnamed_callsite_count=len(unmatched_unnamed),
            known_non_sink_callsite_count=len(known_non_sink_sites),
            actionable_unmatched_named_callsite_count=len(actionable_unmatched_named),
            alias_or_thunk_match_count=len(alias_or_thunk_matches),
            operation_match_rate=operation_match_rate,
            resolution_kind_counts=dict(sorted(resolution_kind_counts.items())),
            operation_kind_counts=dict(sorted(operation_kind_counts.items())),
            non_sink_category_counts=dict(sorted(non_sink_category_counts.items())),
            unmatched_groups=unmatched_groups,
            known_non_sink_groups=known_non_sink_groups,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "operation coverage summaries measure static metadata coverage; "
                "unmatched calls are triage backlog, not findings"
            ],
        )


def _unmatched_groups(
    callsites: list[ProjectCallsiteFact],
    max_unmatched: int,
    non_sink_by_site: dict[int, NonSinkOperationRecord],
) -> list[WindowsProjectUnmatchedCallGroup]:
    by_symbol: dict[str, list[ProjectCallsiteFact]] = defaultdict(list)
    for site in callsites:
        symbol = _display_symbol(site)
        if symbol:
            by_symbol[symbol].append(site)

    out: list[WindowsProjectUnmatchedCallGroup] = []
    for symbol, sites in sorted(
        by_symbol.items(),
        key=lambda item: (-len(item[1]), item[0].lower()),
    )[:max_unmatched]:
        callers = _sample_callers(sites)
        non_sink = _group_non_sink_record(sites, non_sink_by_site)
        out.append(
            WindowsProjectUnmatchedCallGroup(
                symbol=symbol,
                count=len(sites),
                caller_function_count=len(
                    {site.caller_va for site in sites if site.caller_va is not None}
                ),
                sample_callsites=[site.callsite_va for site in sites[:5]],
                sample_callers=callers,
                resolution_kind_counts=dict(
                    sorted(Counter(site.callee_resolution_kind for site in sites).items())
                ),
                non_sink_category=non_sink.category if non_sink else None,
                non_sink_disposition=non_sink.disposition if non_sink else None,
                recommended_next_action=_recommended_next_action(sites, non_sink),
            )
        )
    return out


def _display_symbol(site: ProjectCallsiteFact) -> str | None:
    for value in (
        site.callee_demangled,
        site.callee_name,
        *site.callee_aliases,
        *site.callee_normalized_names,
    ):
        if value:
            return value
    return None


def _sample_callers(sites: list[ProjectCallsiteFact]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for site in sites:
        caller = site.caller_name or site.caller_demangled
        if not caller and site.caller_va is not None:
            caller = f"0x{site.caller_va:x}"
        if not caller or caller in seen:
            continue
        seen.add(caller)
        out.append(caller)
        if len(out) >= 5:
            break
    return out


def _group_non_sink_record(
    sites: list[ProjectCallsiteFact],
    non_sink_by_site: dict[int, NonSinkOperationRecord],
) -> NonSinkOperationRecord | None:
    records_by_id = {
        record.id: record
        for site in sites
        if (record := non_sink_by_site.get(site.callsite_va)) is not None
    }
    if not records_by_id:
        return None
    top_id = Counter(
        non_sink_by_site[site.callsite_va].id
        for site in sites
        if site.callsite_va in non_sink_by_site
    ).most_common(1)[0][0]
    return records_by_id[top_id]


def _recommended_next_action(
    sites: list[ProjectCallsiteFact],
    non_sink: NonSinkOperationRecord | None,
) -> str:
    if non_sink is not None:
        return (
            f"treat as {non_sink.category} non-sink unless local context shows "
            "security-relevant side effects"
        )
    if any(site.callee_aliases or site.callee_resolution_kind != "direct_name" for site in sites):
        return "review alias/import-thunk spelling and add ASB sink metadata if security-relevant"
    return "classify callee semantics and add ASB sink metadata if security-relevant"


def _coverage(
    facts: list[ProjectCallsiteFact],
    operation_sites: list[ProjectCallsiteFact],
    alias_or_thunk_matches: list[ProjectCallsiteFact],
    unmatched_groups: list[WindowsProjectUnmatchedCallGroup],
    known_non_sink_groups: list[WindowsProjectUnmatchedCallGroup],
) -> list[str]:
    coverage = []
    if facts:
        coverage.extend(["project_operation_coverage_summary", "operation_match_rate"])
    if operation_sites:
        coverage.append("operation_callsite_classification_counts")
    if alias_or_thunk_matches:
        coverage.append("alias_or_import_thunk_operation_match_counts")
    if unmatched_groups:
        coverage.append("unmatched_project_callsite_summary")
    if known_non_sink_groups:
        coverage.append("known_non_sink_operation_filter")
    return coverage


def _missing_capabilities(
    unmatched_named: list[ProjectCallsiteFact],
    unmatched_unnamed: list[ProjectCallsiteFact],
) -> list[str]:
    missing = []
    if unmatched_named:
        missing.append("asb_sink_metadata_for_unmatched_symbols")
    if unmatched_unnamed:
        missing.append("indirect_call_target_resolution")
    missing.extend(
        [
            "local_instruction_pattern_sinks",
            "type_aware_operation_classification",
            "runtime_validation_artifacts",
        ]
    )
    return list(dict.fromkeys(missing))


def _load_non_sink_records(
    non_sinks_path: str | None,
) -> tuple[list[NonSinkOperationRecord], Path | None]:
    if non_sinks_path is None:
        return [], None
    path = _resolve_metadata_path(non_sinks_path, "data/kg/pe-non-sink-operations.yaml")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    records = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: non-sink entry {idx} is not a mapping")
        records.append(
            NonSinkOperationRecord(
                id=_required_str(entry, "id", path),
                symbols=_required_str_list(entry, "symbols", path),
                category=_required_str(entry, "category", path),
                disposition=_required_str(entry, "disposition", path),
                notes=str(entry["notes"]) if entry.get("notes") is not None else None,
            )
        )
    return records, path


def _first_non_sink_match(
    site: ProjectCallsiteFact,
    records: list[NonSinkOperationRecord],
) -> NonSinkOperationRecord | None:
    names = [
        name
        for name in (
            site.callee_demangled,
            site.callee_name,
            *site.callee_aliases,
            *site.callee_normalized_names,
        )
        if name
    ]
    for record in records:
        if any(_record_matches_name(record, name) for name in names):
            return record
    return None


def _record_matches_name(record: NonSinkOperationRecord, name: str) -> bool:
    suffix = name.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
    candidates = {name, suffix}
    for pattern in record.symbols:
        pattern_suffix = pattern.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
        if any(
            fnmatchcase(candidate, pattern)
            or fnmatchcase(candidate, pattern_suffix)
            or candidate.lower() == pattern.lower()
            or candidate.lower() == pattern_suffix.lower()
            for candidate in candidates
        ):
            return True
    return False


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: non-sink entry missing string {key}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: non-sink entry missing list {key}")
    out = [str(value) for value in values if str(value)]
    if not out:
        raise ValueError(f"{path}: non-sink entry {key} is empty")
    return out


def build_tool() -> WindowsProjectOperationCoverageSummaryTool:
    return WindowsProjectOperationCoverageSummaryTool()
