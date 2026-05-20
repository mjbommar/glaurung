from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb import windows_sysinfo
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class ProjectSysinfoDispatchFact(BaseModel):
    information_class: int
    information_class_name: str
    syscall_name: str
    dispatcher_va: int | None = None
    dispatcher_name: str | None = None
    callsite_va: int | None = None
    helper_va: int
    helper_name: str
    selector_source: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: dict = Field(default_factory=dict)


class WindowsProjectSysinfoDispatchFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    information_class: int | None = Field(
        None,
        description="Optional SystemInformationClass integer filter.",
    )
    helper_name: str | None = Field(
        None,
        description="Optional helper-name substring filter.",
    )
    max_rows: int = Field(64, ge=0, description="Maximum dispatch facts to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact sysinfo-dispatch evidence node to the KB.",
    )


class WindowsProjectSysinfoDispatchFactsResult(BaseModel):
    project_path: str
    dispatch_count: int
    dispatches: list[ProjectSysinfoDispatchFact]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectSysinfoDispatchFactsTool(
    MemoryTool[
        WindowsProjectSysinfoDispatchFactsArgs,
        WindowsProjectSysinfoDispatchFactsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_sysinfo_dispatch_facts",
                description=(
                    "Query first-class NtQuerySystemInformation/SystemInformationClass "
                    "dispatch facts from a .glaurung project."
                ),
                tags=("windows", "pe", "project", "sysinfo", "dispatch"),
            ),
            WindowsProjectSysinfoDispatchFactsArgs,
            WindowsProjectSysinfoDispatchFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectSysinfoDispatchFactsArgs,
    ) -> WindowsProjectSysinfoDispatchFactsResult:
        project_path = Path(args.project_path)
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        project = PersistentKnowledgeBase.open(project_path)
        try:
            rows = windows_sysinfo.list_sysinfo_dispatch_facts(
                project,
                information_class=args.information_class,
                helper_name=args.helper_name,
                limit=args.max_rows,
            )
        finally:
            project.close()

        dispatches = [
            ProjectSysinfoDispatchFact(
                information_class=row.information_class,
                information_class_name=row.information_class_name,
                syscall_name=row.syscall_name,
                dispatcher_va=row.dispatcher_va,
                dispatcher_name=row.dispatcher_name,
                callsite_va=row.callsite_va,
                helper_va=row.helper_va,
                helper_name=row.helper_name,
                selector_source=row.selector_source,
                confidence=row.confidence,
                evidence=row.evidence,
            )
            for row in rows
        ]
        coverage = ["sysinfo_dispatch"] if dispatches else []
        missing = [] if dispatches else ["sysinfo_dispatch"]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_sysinfo_dispatch_facts",
                    props={
                        "project_path": str(project_path),
                        "information_class": args.information_class,
                        "helper_name": args.helper_name,
                        "dispatch_count": len(dispatches),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectSysinfoDispatchFactsResult(
            project_path=str(project_path),
            dispatch_count=len(dispatches),
            dispatches=dispatches,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "sysinfo dispatch facts are deterministic Windows dispatch metadata; "
                "they identify high-risk helper paths but do not prove vulnerability"
            ],
        )


def build_tool() -> WindowsProjectSysinfoDispatchFactsTool:
    return WindowsProjectSysinfoDispatchFactsTool()
