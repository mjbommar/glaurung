from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_operation_classification_backlog import (
    WindowsOperationBacklogEntry,
    WindowsOperationClassificationBacklogArgs,
    WindowsOperationClassificationBacklogTool,
)
from .windows_project_callsite_facts import (
    ProjectCallsiteFact,
    WindowsProjectCallsiteFactsArgs,
    WindowsProjectCallsiteFactsTool,
)


class WindowsProjectOperationBacklogSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    backlog_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-operation-classification-backlog.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    target_id: str | None = Field(None, description="Optional target id filter.")
    component: str | None = Field(None, description="Optional component filename filter.")
    required_capability: str | None = Field(
        None,
        description="Optional required Glaurung/ASB capability filter.",
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter callsites.",
    )
    max_calls: int = Field(
        16384,
        ge=0,
        le=65536,
        description="Maximum project callsites to scan before joining backlog metadata.",
    )
    max_entries: int = Field(
        32,
        ge=0,
        le=512,
        description="Maximum matched backlog entries to return.",
    )
    include_unmatched_backlog: bool = Field(
        False,
        description="If true, include backlog entries that had no matching project callsites.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact project-backlog evidence node to the KB.",
    )


class WindowsProjectOperationBacklogGroup(BaseModel):
    backlog_id: str
    symbol: str
    target_id: str
    component: str
    build_label: str
    triage_category: str
    candidate_operation_kinds: list[str]
    likely_security_relevance: str
    required_capabilities: list[str]
    recommended_next_actions: list[str]
    metadata_observed_callsite_count: int
    project_callsite_count: int
    project_caller_function_count: int
    sample_callsites: list[int] = Field(default_factory=list)
    sample_callers: list[str] = Field(default_factory=list)
    resolution_kind_counts: dict[str, int] = Field(default_factory=dict)
    notes: str | None = None


class WindowsProjectOperationBacklogSummaryResult(BaseModel):
    project_path: str
    backlog_path: str
    sinks_path: str
    binary_id: int | None = None
    scanned_callsite_count: int
    backlog_entry_count_total: int
    matched_backlog_entry_count: int
    unmatched_backlog_entry_count: int
    matched_project_callsite_count: int
    groups: list[WindowsProjectOperationBacklogGroup]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOperationBacklogSummaryTool(
    MemoryTool[
        WindowsProjectOperationBacklogSummaryArgs,
        WindowsProjectOperationBacklogSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_operation_backlog_summary",
                description=(
                    "Join ASB operation-classification backlog entries to exact "
                    "project callsites so agents can prioritize classifier work."
                ),
                tags=("windows", "pe", "project", "operations", "backlog", "summary"),
            ),
            WindowsProjectOperationBacklogSummaryArgs,
            WindowsProjectOperationBacklogSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOperationBacklogSummaryArgs,
    ) -> WindowsProjectOperationBacklogSummaryResult:
        backlog_result = WindowsOperationClassificationBacklogTool().run(
            ctx,
            kb,
            WindowsOperationClassificationBacklogArgs(
                backlog_path=args.backlog_path,
                target_id=args.target_id,
                component=args.component,
                required_capability=args.required_capability,
                add_to_kb=False,
            ),
        )
        callsite_result = WindowsProjectCallsiteFactsTool().run(
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

        matched_sites = _match_backlog_entries(backlog_result.entries, callsite_result.callsites)
        groups = _groups(
            backlog_result.entries,
            matched_sites,
            include_unmatched=args.include_unmatched_backlog,
        )[: args.max_entries]
        matched_entry_count = sum(1 for entry in backlog_result.entries if entry.id in matched_sites)
        matched_callsite_count = sum(len(sites) for sites in matched_sites.values())
        unmatched_entry_count = len(backlog_result.entries) - matched_entry_count

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_operation_backlog_summary",
                    props={
                        "project_path": str(Path(args.project_path)),
                        "target_id": args.target_id,
                        "component": args.component,
                        "required_capability": args.required_capability,
                        "backlog_entry_count_total": backlog_result.entry_count_total,
                        "matched_backlog_entry_count": matched_entry_count,
                        "matched_project_callsite_count": matched_callsite_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOperationBacklogSummaryResult(
            project_path=str(Path(args.project_path)),
            backlog_path=backlog_result.backlog_path,
            sinks_path=callsite_result.sinks_path,
            binary_id=callsite_result.binary_id,
            scanned_callsite_count=callsite_result.scanned_call_count,
            backlog_entry_count_total=backlog_result.entry_count_total,
            matched_backlog_entry_count=matched_entry_count,
            unmatched_backlog_entry_count=unmatched_entry_count,
            matched_project_callsite_count=matched_callsite_count,
            groups=groups,
            coverage=_coverage(groups, matched_callsite_count),
            missing_capabilities=_missing_capabilities(groups),
            evidence_node_id=evidence_node_id,
            notes=[
                "project backlog summaries join metadata to static callsite facts; "
                "matched groups are classifier work items, not findings"
            ],
        )


def _match_backlog_entries(
    entries: list[WindowsOperationBacklogEntry],
    callsites: list[ProjectCallsiteFact],
) -> dict[str, list[ProjectCallsiteFact]]:
    out: dict[str, list[ProjectCallsiteFact]] = defaultdict(list)
    for site in callsites:
        names = _callsite_names(site)
        if not names:
            continue
        for entry in entries:
            if any(_symbol_matches(name, entry.symbol) for name in names):
                out[entry.id].append(site)
    return dict(out)


def _groups(
    entries: list[WindowsOperationBacklogEntry],
    matched_sites: dict[str, list[ProjectCallsiteFact]],
    *,
    include_unmatched: bool,
) -> list[WindowsProjectOperationBacklogGroup]:
    out: list[WindowsProjectOperationBacklogGroup] = []
    for entry in entries:
        sites = matched_sites.get(entry.id, [])
        if not sites and not include_unmatched:
            continue
        out.append(_group(entry, sites))
    return sorted(
        out,
        key=lambda group: (
            -group.project_callsite_count,
            -group.metadata_observed_callsite_count,
            group.symbol.lower(),
        ),
    )


def _group(
    entry: WindowsOperationBacklogEntry,
    sites: list[ProjectCallsiteFact],
) -> WindowsProjectOperationBacklogGroup:
    return WindowsProjectOperationBacklogGroup(
        backlog_id=entry.id,
        symbol=entry.symbol,
        target_id=entry.target_id,
        component=entry.component,
        build_label=entry.build_label,
        triage_category=entry.triage_category,
        candidate_operation_kinds=entry.candidate_operation_kinds,
        likely_security_relevance=entry.likely_security_relevance,
        required_capabilities=entry.required_capabilities,
        recommended_next_actions=entry.recommended_next_actions,
        metadata_observed_callsite_count=entry.observed_callsite_count,
        project_callsite_count=len(sites),
        project_caller_function_count=len(
            {site.caller_va for site in sites if site.caller_va is not None}
        ),
        sample_callsites=[site.callsite_va for site in sites[:5]],
        sample_callers=_sample_callers(sites),
        resolution_kind_counts=dict(
            sorted(Counter(site.callee_resolution_kind for site in sites).items())
        ),
        notes=entry.notes,
    )


def _callsite_names(site: ProjectCallsiteFact) -> list[str]:
    values = [
        site.callee_demangled,
        site.callee_name,
        *site.callee_aliases,
        *site.callee_normalized_names,
    ]
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _symbol_matches(name: str, symbol: str) -> bool:
    name_suffix = name.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
    symbol_suffix = symbol.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
    return name.lower() == symbol.lower() or name_suffix.lower() == symbol_suffix.lower()


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


def _coverage(
    groups: list[WindowsProjectOperationBacklogGroup],
    matched_callsite_count: int,
) -> list[str]:
    coverage = ["operation_classification_backlog_metadata"]
    if groups:
        coverage.append("project_operation_backlog_join")
    if matched_callsite_count:
        coverage.append("project_backlog_callsite_evidence")
    if any(group.required_capabilities for group in groups):
        coverage.append("backlog_required_capability_metadata")
    return coverage


def _missing_capabilities(groups: list[WindowsProjectOperationBacklogGroup]) -> list[str]:
    missing = [
        "classifier_semantic_confirmation",
        "type_aware_operation_classification",
        "runtime_validation_artifacts",
    ]
    for group in groups:
        for capability in group.required_capabilities:
            missing.append(capability)
    return list(dict.fromkeys(missing))


def build_tool() -> WindowsProjectOperationBacklogSummaryTool:
    return WindowsProjectOperationBacklogSummaryTool()
