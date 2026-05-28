from __future__ import annotations

from collections import defaultdict
from pathlib import Path

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


class WindowsProjectSinkOperationSummaryArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter sink callsites.",
    )
    call_symbol: str | None = Field(
        None,
        description="Optional callee symbol filter, e.g. RtlCopyMemory.",
    )
    sink_kind: str | None = Field(
        None,
        description="Optional ASB sink kind filter, e.g. copy, free, completion.",
    )
    max_calls: int = Field(
        1024,
        ge=0,
        le=16384,
        description="Maximum project callsites to scan before aggregation.",
    )
    max_groups: int = Field(
        128,
        ge=0,
        le=2048,
        description="Maximum operation summary groups to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact sink-operation-summary evidence node.",
    )


class WindowsProjectSinkOperationSample(BaseModel):
    callsite_va: int
    caller_va: int | None = None
    caller_name: str | None = None
    callee_va: int
    callee_name: str | None = None
    callee_resolution_kind: str = "direct_name"


class WindowsProjectSinkOperationGroup(BaseModel):
    operation_id: str
    sink_kind: str
    callsite_count: int
    caller_function_count: int
    observed_symbols: list[str] = Field(default_factory=list)
    sink_effects: list[str] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    arg_roles: dict[int, str] = Field(default_factory=dict)
    sample_callsites: list[WindowsProjectSinkOperationSample] = Field(
        default_factory=list
    )
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: list[str] = Field(default_factory=list)


class WindowsProjectSinkOperationSummaryResult(BaseModel):
    project_path: str
    sinks_path: str
    binary_id: int | None = None
    scanned_callsite_count: int
    operation_callsite_count: int
    operation_group_count: int
    groups: list[WindowsProjectSinkOperationGroup]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectSinkOperationSummaryTool(
    MemoryTool[
        WindowsProjectSinkOperationSummaryArgs,
        WindowsProjectSinkOperationSummaryResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_sink_operation_summary",
                description=(
                    "Aggregate project-backed ASB sink callsites into operation "
                    "groups with call counts, effects, argument roles, and "
                    "required gates."
                ),
                tags=("windows", "pe", "project", "sinks", "operations", "summary"),
            ),
            WindowsProjectSinkOperationSummaryArgs,
            WindowsProjectSinkOperationSummaryResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectSinkOperationSummaryArgs,
    ) -> WindowsProjectSinkOperationSummaryResult:
        project_path = Path(args.project_path)
        callsite_tool = WindowsProjectCallsiteFactsTool()
        callsites = callsite_tool.run(
            ctx,
            kb,
            WindowsProjectCallsiteFactsArgs(
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                function_va=args.function_va,
                call_symbol=args.call_symbol,
                operation_only=True,
                max_calls=args.max_calls,
                add_to_kb=False,
            ),
        )

        operation_sites = [
            site
            for site in callsites.callsites
            if site.operation is not None
            and (args.sink_kind is None or site.operation.sink_kind == args.sink_kind)
        ]
        groups = _groups(operation_sites, args.max_groups)
        coverage = _coverage(callsites.coverage, groups)
        missing = _missing_capabilities(callsites.missing_capabilities, groups)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_sink_operation_summary",
                    props={
                        "project_path": str(project_path),
                        "scanned_callsite_count": callsites.scanned_call_count,
                        "operation_callsite_count": len(operation_sites),
                        "operation_group_count": len(groups),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectSinkOperationSummaryResult(
            project_path=str(project_path),
            sinks_path=callsites.sinks_path,
            binary_id=callsites.binary_id,
            scanned_callsite_count=callsites.scanned_call_count,
            operation_callsite_count=len(operation_sites),
            operation_group_count=len(groups),
            groups=groups,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "sink operation summaries classify project callsites by ASB sink "
                "metadata; argument value flow, source reachability, and gate "
                "dominance require separate project facts"
            ],
        )


def _groups(
    callsites: list[ProjectCallsiteFact],
    max_groups: int,
) -> list[WindowsProjectSinkOperationGroup]:
    grouped: dict[str, list[ProjectCallsiteFact]] = defaultdict(list)
    for site in callsites:
        if site.operation is None:
            continue
        grouped[site.operation.id].append(site)

    out: list[WindowsProjectSinkOperationGroup] = []
    for operation_id, sites in grouped.items():
        operation = sites[0].operation
        if operation is None:
            continue
        out.append(
            WindowsProjectSinkOperationGroup(
                operation_id=operation_id,
                sink_kind=operation.sink_kind,
                callsite_count=len(sites),
                caller_function_count=len(
                    {site.caller_va for site in sites if site.caller_va is not None}
                ),
                observed_symbols=_uniq(
                    name
                    for site in sites
                    for name in (
                        site.callee_name,
                        site.callee_demangled,
                        *site.callee_aliases,
                        *site.callee_normalized_names,
                    )
                    if name
                ),
                sink_effects=operation.effects,
                required_gates=operation.required_gates,
                arg_roles={role.index: role.role for role in operation.arg_roles},
                sample_callsites=[
                    WindowsProjectSinkOperationSample(
                        callsite_va=site.callsite_va,
                        caller_va=site.caller_va,
                        caller_name=site.caller_name,
                        callee_va=site.callee_va,
                        callee_name=site.callee_name,
                        callee_resolution_kind=site.callee_resolution_kind,
                    )
                    for site in sites[:5]
                ],
                confidence=round(min(site.confidence for site in sites), 2),
                provenance=_group_provenance(sites),
            )
        )
        if len(out) >= max_groups:
            break
    return out


def _coverage(
    callsite_coverage: list[str],
    groups: list[WindowsProjectSinkOperationGroup],
) -> list[str]:
    coverage = list(dict.fromkeys(callsite_coverage))
    if groups:
        coverage.extend(
            [
                "project_sink_operation_summary",
                "sink_effect_metadata",
                "sink_required_gate_metadata",
                "sink_argument_role_metadata",
            ]
        )
    return list(dict.fromkeys(coverage))


def _missing_capabilities(
    callsite_missing: list[str],
    groups: list[WindowsProjectSinkOperationGroup],
) -> list[str]:
    missing = list(dict.fromkeys(callsite_missing))
    if not groups:
        missing.append("project_sink_operation_summary")
    missing.extend(
        [
            "source_reachability",
            "gate_dominance_per_sink",
            "argument_value_flow",
        ]
    )
    return list(dict.fromkeys(missing))


def _uniq(values) -> list[str]:
    out = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _group_provenance(sites: list[ProjectCallsiteFact]) -> list[str]:
    provenance = [
        "windows_project_callsite_facts",
        "glaurung_project_xrefs",
        "glaurung_function_names",
    ]
    if any(site.callee_resolution_kind != "direct_name" for site in sites):
        provenance.append("glaurung_import_thunk_symbol_normalization")
    provenance.extend(["asb_pe_sink_metadata", "project_sink_operation_summary"])
    return provenance


def build_tool() -> WindowsProjectSinkOperationSummaryTool:
    return WindowsProjectSinkOperationSummaryTool()
