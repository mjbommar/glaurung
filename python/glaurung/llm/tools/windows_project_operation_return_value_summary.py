from __future__ import annotations

from collections import Counter
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
from .windows_project_operation_backlog_summary import (
    _match_backlog_entries,
    _sample_callers,
)
from .windows_project_return_value_use_snapshot import (
    ProjectReturnValueUseFact,
    WindowsProjectReturnValueUseSnapshotArgs,
    WindowsProjectReturnValueUseSnapshotTool,
)


class WindowsProjectOperationReturnValueSummaryArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary backing the project.")
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
    symbol: str | None = Field(None, description="Optional exact backlog symbol filter.")
    required_capability: str = Field(
        "return_value_flow",
        description="Backlog required-capability filter; defaults to return_value_flow.",
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter project callsites.",
    )
    max_calls: int = Field(
        16384,
        ge=0,
        le=65536,
        description="Maximum project callsites to scan before joining backlog metadata.",
    )
    max_entries: int = Field(
        16,
        ge=0,
        le=256,
        description="Maximum matched backlog entries to summarize.",
    )
    max_callsites_per_entry: int = Field(
        16,
        ge=0,
        le=512,
        description="Maximum project callsites per backlog entry to sample for return uses.",
    )
    max_after_instructions: int = Field(
        16,
        ge=1,
        le=128,
        description="Maximum post-call instructions to inspect per sampled callsite.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact operation-return evidence node to the KB.",
    )


class ProjectReturnValueSample(BaseModel):
    callsite_va: int
    caller_va: int | None = None
    caller_name: str | None = None
    callee_va: int | None = None
    callee_name: str | None = None
    callsite_text: str | None = None
    first_use_kind: str | None = None
    uses: list[ProjectReturnValueUseFact] = Field(default_factory=list)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOperationReturnValueGroup(BaseModel):
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
    sampled_callsite_count: int
    project_caller_function_count: int
    sample_callers: list[str] = Field(default_factory=list)
    use_kind_counts: dict[str, int] = Field(default_factory=dict)
    checked_callsite_count: int = 0
    branch_related_callsite_count: int = 0
    clobbered_callsite_count: int = 0
    ignored_callsite_count: int = 0
    samples: list[ProjectReturnValueSample] = Field(default_factory=list)
    notes: str | None = None


class WindowsProjectOperationReturnValueSummaryResult(BaseModel):
    binary_path: str
    project_path: str
    backlog_path: str
    sinks_path: str
    binary_id: int | None = None
    scanned_callsite_count: int
    backlog_entry_count_total: int
    matched_backlog_entry_count: int
    matched_project_callsite_count: int
    sampled_callsite_count: int
    groups: list[WindowsProjectOperationReturnValueGroup]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectOperationReturnValueSummaryTool(
    MemoryTool[
        WindowsProjectOperationReturnValueSummaryArgs,
        WindowsProjectOperationReturnValueSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_operation_return_value_summary",
                description=(
                    "Join operation-classification backlog entries to exact project "
                    "callsites and summarize local post-call return-value uses."
                ),
                tags=(
                    "windows",
                    "pe",
                    "project",
                    "operations",
                    "backlog",
                    "return-values",
                ),
            ),
            WindowsProjectOperationReturnValueSummaryArgs,
            WindowsProjectOperationReturnValueSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectOperationReturnValueSummaryArgs,
    ) -> WindowsProjectOperationReturnValueSummaryResult:
        binary_path = Path(args.binary_path)
        if not binary_path.exists():
            raise ValueError(f"{binary_path}: PE binary does not exist")

        backlog_result = WindowsOperationClassificationBacklogTool().run(
            ctx,
            kb,
            WindowsOperationClassificationBacklogArgs(
                backlog_path=args.backlog_path,
                target_id=args.target_id,
                component=args.component,
                symbol=args.symbol,
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
        groups = _groups(ctx, kb, args, backlog_result.entries, matched_sites)
        matched_entry_count = sum(1 for entry in backlog_result.entries if entry.id in matched_sites)
        matched_callsite_count = sum(len(sites) for sites in matched_sites.values())
        sampled_callsite_count = sum(group.sampled_callsite_count for group in groups)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_operation_return_value_summary",
                    props={
                        "binary_path": str(binary_path),
                        "project_path": str(Path(args.project_path)),
                        "target_id": args.target_id,
                        "component": args.component,
                        "symbol": args.symbol,
                        "required_capability": args.required_capability,
                        "matched_backlog_entry_count": matched_entry_count,
                        "matched_project_callsite_count": matched_callsite_count,
                        "sampled_callsite_count": sampled_callsite_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectOperationReturnValueSummaryResult(
            binary_path=str(binary_path),
            project_path=str(Path(args.project_path)),
            backlog_path=backlog_result.backlog_path,
            sinks_path=callsite_result.sinks_path,
            binary_id=callsite_result.binary_id,
            scanned_callsite_count=callsite_result.scanned_call_count,
            backlog_entry_count_total=backlog_result.entry_count_total,
            matched_backlog_entry_count=matched_entry_count,
            matched_project_callsite_count=matched_callsite_count,
            sampled_callsite_count=sampled_callsite_count,
            groups=groups,
            coverage=_coverage(groups),
            missing_capabilities=_missing_capabilities(groups),
            evidence_node_id=evidence_node_id,
            notes=[
                "operation return-value summaries sample local post-call uses; "
                "they are classifier evidence, not interprocedural return-flow proof"
            ],
        )


def _groups(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOperationReturnValueSummaryArgs,
    entries: list[WindowsOperationBacklogEntry],
    matched_sites: dict[str, list[ProjectCallsiteFact]],
) -> list[WindowsProjectOperationReturnValueGroup]:
    out: list[WindowsProjectOperationReturnValueGroup] = []
    for entry in entries:
        sites = matched_sites.get(entry.id, [])
        if not sites:
            continue
        out.append(_group(ctx, kb, args, entry, sites))
    return sorted(
        out,
        key=lambda group: (
            -group.sampled_callsite_count,
            -group.project_callsite_count,
            group.symbol.lower(),
        ),
    )[: args.max_entries]


def _group(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOperationReturnValueSummaryArgs,
    entry: WindowsOperationBacklogEntry,
    sites: list[ProjectCallsiteFact],
) -> WindowsProjectOperationReturnValueGroup:
    samples = [
        _sample_return_value_use(ctx, kb, args, site)
        for site in sites[: args.max_callsites_per_entry]
    ]
    use_counts = Counter(
        use.use_kind for sample in samples for use in sample.uses if use.use_kind
    )
    return WindowsProjectOperationReturnValueGroup(
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
        sampled_callsite_count=len(samples),
        project_caller_function_count=len(
            {site.caller_va for site in sites if site.caller_va is not None}
        ),
        sample_callers=_sample_callers(sites),
        use_kind_counts=dict(sorted(use_counts.items())),
        checked_callsite_count=sum(
            1
            for sample in samples
            if sample.first_use_kind in {"comparison_gate", "null_or_status_check"}
        ),
        branch_related_callsite_count=sum(
            1
            for sample in samples
            if any(use.branch_va is not None for use in sample.uses)
        ),
        clobbered_callsite_count=sum(
            1
            for sample in samples
            if any(use.use_kind.startswith("clobbered") for use in sample.uses)
        ),
        ignored_callsite_count=sum(
            1 for sample in samples if sample.first_use_kind == "ignored_in_window"
        ),
        samples=samples,
        notes=entry.notes,
    )


def _sample_return_value_use(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectOperationReturnValueSummaryArgs,
    site: ProjectCallsiteFact,
) -> ProjectReturnValueSample:
    result = WindowsProjectReturnValueUseSnapshotTool().run(
        ctx,
        kb,
        WindowsProjectReturnValueUseSnapshotArgs(
            binary_path=args.binary_path,
            project_path=args.project_path,
            callsite_va=site.callsite_va,
            binary_id=args.binary_id,
            max_after_instructions=args.max_after_instructions,
            add_to_kb=False,
        ),
    )
    return ProjectReturnValueSample(
        callsite_va=site.callsite_va,
        caller_va=result.caller_va,
        caller_name=result.caller_name,
        callee_va=result.callee_va,
        callee_name=result.callee_name,
        callsite_text=result.callsite_text,
        first_use_kind=result.first_use_kind,
        uses=result.uses,
        coverage=result.coverage,
        missing_capabilities=result.missing_capabilities,
        notes=result.notes,
    )


def _coverage(groups: list[WindowsProjectOperationReturnValueGroup]) -> list[str]:
    coverage: list[str] = []
    if groups:
        coverage.append("project_backlog_callsite_evidence")
        coverage.append("local_return_value_use_snapshots")
    if any(group.checked_callsite_count for group in groups):
        coverage.append("return_value_check_summary")
    if any(group.branch_related_callsite_count for group in groups):
        coverage.append("return_value_branch_summary")
    if any(group.clobbered_callsite_count for group in groups):
        coverage.append("return_value_clobber_summary")
    if any(group.ignored_callsite_count for group in groups):
        coverage.append("return_value_ignored_summary")
    return coverage


def _missing_capabilities(groups: list[WindowsProjectOperationReturnValueGroup]) -> list[str]:
    missing = {
        "interprocedural_return_value_flow",
        "path_sensitive_return_value_flow",
        "non_adjacent_return_flag_flow",
        "full_alias_tracking",
        "helper_side_effect_summaries",
    }
    if not groups:
        missing.add("project_backlog_callsite_evidence")
    if any(group.ignored_callsite_count for group in groups):
        missing.add("larger_post_call_window")
    return sorted(missing)


def build_tool() -> WindowsProjectOperationReturnValueSummaryTool:
    return WindowsProjectOperationReturnValueSummaryTool()
