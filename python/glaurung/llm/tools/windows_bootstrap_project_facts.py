from __future__ import annotations

from pathlib import Path
from time import perf_counter
from typing import Callable

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb import cfg_db, pe_direct_calls, type_db, xref_db
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_import_pdb_facts import PdbFactImportCounts


class WindowsBootstrapProjectFactsArgs(BaseModel):
    pe_path: str = Field(..., description="Path to the Windows PE binary to index.")
    project_path: str = Field(..., description="Path to create or update as a .glaurung project.")
    pdb_cache_dir: str | None = Field(
        None,
        description="Optional Microsoft-style PDB cache directory for PDB fact import.",
    )
    struct_names: list[str] = Field(
        default_factory=list,
        description="Optional PDB struct/class/union names to import as type layouts.",
    )
    index_callgraph: bool = Field(
        True,
        description="If true, persist call xrefs and analyzer function names.",
    )
    index_data_xrefs: bool = Field(
        True,
        description="If true, persist direct code-to-data xrefs.",
    )
    index_cfg: bool = Field(
        True,
        description="If true, persist native PE basic blocks and CFG edges.",
    )
    index_cfg_dominance: bool = Field(
        True,
        description="If true, precompute dominance summaries for persisted CFGs.",
    )
    index_branch_conditions: bool = Field(
        True,
        description="If true, persist conditional branch and compare operand facts.",
    )
    import_pdb_facts: bool = Field(
        True,
        description="If true and pdb_cache_dir is set, import matching PDB facts.",
    )
    max_pdb_prototypes: int = Field(
        512,
        ge=0,
        description="Maximum PDB function-prototype type records to persist.",
    )
    force_reindex: bool = Field(
        False,
        description="If true, rebuild callgraph/data-xref indexes even when present.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact bootstrap evidence node to the active KB.",
    )


class ProjectBootstrapStep(BaseModel):
    name: str
    ran: bool
    ok: bool
    count: int = 0
    elapsed_ms: float = 0.0
    error: str | None = None


class WindowsBootstrapProjectFactsResult(BaseModel):
    pe_path: str
    project_path: str
    steps: list[ProjectBootstrapStep]
    pdb_counts: PdbFactImportCounts | None = None
    fact_coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsBootstrapProjectFactsTool(
    MemoryTool[WindowsBootstrapProjectFactsArgs, WindowsBootstrapProjectFactsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_bootstrap_project_facts",
                description=(
                    "Create or update a .glaurung Windows PE project with "
                    "call xrefs, data xrefs, CFG facts, and optional "
                    "PDB-backed facts."
                ),
                tags=("windows", "pe", "project", "xrefs", "cfg", "pdb"),
            ),
            WindowsBootstrapProjectFactsArgs,
            WindowsBootstrapProjectFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsBootstrapProjectFactsArgs,
    ) -> WindowsBootstrapProjectFactsResult:
        pe_path = Path(args.pe_path)
        project_path = Path(args.project_path)
        if not pe_path.exists():
            raise ValueError(f"{pe_path}: PE binary does not exist")

        project = PersistentKnowledgeBase.open(project_path, binary_path=pe_path)
        steps: list[ProjectBootstrapStep] = []
        pdb_counts: PdbFactImportCounts | None = None
        try:
            if args.index_callgraph:
                steps.append(
                    _run_count_step(
                        "index_callgraph",
                        lambda: xref_db.index_callgraph(
                            project,
                            str(pe_path),
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(ProjectBootstrapStep(name="index_callgraph", ran=False, ok=True))

            if args.index_data_xrefs:
                steps.append(
                    _run_count_step(
                        "index_data_xrefs",
                        lambda: xref_db.index_data_xrefs(
                            project,
                            str(pe_path),
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(ProjectBootstrapStep(name="index_data_xrefs", ran=False, ok=True))

            if args.index_cfg:
                steps.append(
                    _run_count_step(
                        "index_cfg",
                        lambda: cfg_db.index_cfg(
                            project,
                            str(pe_path),
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(ProjectBootstrapStep(name="index_cfg", ran=False, ok=True))

            if args.index_cfg_dominance:
                steps.append(
                    _run_count_step(
                        "index_cfg_dominance",
                        lambda: cfg_db.index_cfg_dominance(
                            project,
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(
                    ProjectBootstrapStep(name="index_cfg_dominance", ran=False, ok=True)
                )

            if args.index_branch_conditions:
                steps.append(
                    _run_count_step(
                        "index_branch_conditions",
                        lambda: cfg_db.index_cfg_branch_facts(
                            project,
                            str(pe_path),
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(
                    ProjectBootstrapStep(
                        name="index_branch_conditions",
                        ran=False,
                        ok=True,
                    )
                )

            if args.import_pdb_facts and args.pdb_cache_dir:
                step, pdb_counts = _run_pdb_import_step(project, pe_path, args)
                steps.append(step)
            else:
                steps.append(ProjectBootstrapStep(name="import_pdb_facts", ran=False, ok=True))

            if args.index_callgraph and not _has_call_xref_facts(steps):
                steps.append(
                    _run_count_step(
                        "index_pe_direct_calls",
                        lambda: pe_direct_calls.index_pe_direct_calls(project, pe_path),
                    )
                )
        finally:
            project.close()

        coverage = _fact_coverage(steps, pdb_counts)
        missing = _missing_capabilities(steps, pdb_counts, args)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_bootstrap_project_facts",
                    props={
                        "pe_path": str(pe_path),
                        "project_path": str(project_path),
                        "coverage": coverage,
                        "missing_capabilities": missing,
                        "steps": [step.model_dump() for step in steps],
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsBootstrapProjectFactsResult(
            pe_path=str(pe_path),
            project_path=str(project_path),
            steps=steps,
            pdb_counts=pdb_counts,
            fact_coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "bootstrap prepares project facts only; source reachability and vulnerability truth are not implied"
            ],
        )


def _run_count_step(name: str, fn: Callable[[], int]) -> ProjectBootstrapStep:
    start = perf_counter()
    try:
        count = int(fn())
    except Exception as exc:  # pragma: no cover - native analyzer errors vary.
        return ProjectBootstrapStep(
            name=name,
            ran=True,
            ok=False,
            elapsed_ms=round((perf_counter() - start) * 1000, 1),
            error=str(exc),
        )
    return ProjectBootstrapStep(
        name=name,
        ran=True,
        ok=True,
        count=count,
        elapsed_ms=round((perf_counter() - start) * 1000, 1),
    )


def _run_pdb_import_step(
    project: PersistentKnowledgeBase,
    pe_path: Path,
    args: WindowsBootstrapProjectFactsArgs,
) -> tuple[ProjectBootstrapStep, PdbFactImportCounts]:
    start = perf_counter()
    try:
        raw = type_db.import_pe_pdb_types(
            project,
            str(pe_path),
            str(args.pdb_cache_dir),
            args.struct_names,
            max_prototypes=args.max_pdb_prototypes,
        )
        counts = _pdb_counts(raw)
    except Exception as exc:  # pragma: no cover - native PDB errors vary.
        return (
            ProjectBootstrapStep(
                name="import_pdb_facts",
                ran=True,
                ok=False,
                elapsed_ms=round((perf_counter() - start) * 1000, 1),
                error=str(exc),
            ),
            PdbFactImportCounts(),
        )
    total = (
        counts.imported_struct
        + counts.imported_union
        + counts.imported_function_proto
        + counts.imported_function_name
    )
    return (
        ProjectBootstrapStep(
            name="import_pdb_facts",
            ran=True,
            ok=True,
            count=total,
            elapsed_ms=round((perf_counter() - start) * 1000, 1),
        ),
        counts,
    )


def _pdb_counts(raw: dict) -> PdbFactImportCounts:
    return PdbFactImportCounts(
        cache_hit=bool(raw.get("cache_hit")),
        imported_struct=int(raw.get("imported_struct") or 0),
        imported_union=int(raw.get("imported_union") or 0),
        imported_function_proto=int(raw.get("imported_function_proto") or 0),
        imported_function_name=int(raw.get("imported_function_name") or 0),
        public_symbols=int(raw.get("public_symbols") or 0),
        skipped_manual_function_name=int(raw.get("skipped_manual_function_name") or 0),
        missing_layouts=[str(name) for name in raw.get("missing_layouts") or []],
    )


def _fact_coverage(
    steps: list[ProjectBootstrapStep],
    pdb_counts: PdbFactImportCounts | None,
) -> list[str]:
    coverage: list[str] = []
    by_name = {step.name: step for step in steps}
    if _step_has_facts(by_name.get("index_callgraph")) or _step_has_facts(
        by_name.get("index_pe_direct_calls")
    ):
        coverage.append("call_xrefs")
    if _step_has_facts(by_name.get("index_data_xrefs")):
        coverage.append("data_xrefs")
    if _step_has_facts(by_name.get("index_cfg")):
        coverage.append("persisted_cfg")
    if _step_has_facts(by_name.get("index_cfg_dominance")):
        coverage.append("cfg_dominance")
    if _step_has_facts(by_name.get("index_branch_conditions")):
        coverage.append("branch_conditions")
    if pdb_counts:
        if pdb_counts.cache_hit:
            coverage.append("cached_pdb")
        if pdb_counts.imported_function_name:
            coverage.extend(["pdb_public_symbols", "pdb_function_names"])
        if pdb_counts.imported_struct or pdb_counts.imported_union:
            coverage.append("pdb_type_layouts")
        if pdb_counts.imported_function_proto:
            coverage.append("pdb_function_prototypes")
    return coverage


def _missing_capabilities(
    steps: list[ProjectBootstrapStep],
    pdb_counts: PdbFactImportCounts | None,
    args: WindowsBootstrapProjectFactsArgs,
) -> list[str]:
    missing: list[str] = []
    by_name = {step.name: step for step in steps}
    if args.index_callgraph and not (
        _step_has_facts(by_name.get("index_callgraph"))
        or _step_has_facts(by_name.get("index_pe_direct_calls"))
    ):
        missing.append("call_xrefs")
    if args.index_data_xrefs and not _step_has_facts(by_name.get("index_data_xrefs")):
        missing.append("data_xrefs")
    if args.index_cfg and not _step_has_facts(by_name.get("index_cfg")):
        missing.append("persisted_cfg")
    if args.index_cfg_dominance and not _step_has_facts(
        by_name.get("index_cfg_dominance")
    ):
        missing.append("cfg_dominance")
    if args.index_branch_conditions and not _step_has_facts(
        by_name.get("index_branch_conditions")
    ):
        missing.append("branch_conditions")
    if args.import_pdb_facts and not pdb_counts:
        missing.append("pdb_import")
    if pdb_counts:
        if not pdb_counts.cache_hit:
            missing.append("cached_pdb")
        if not pdb_counts.imported_function_name:
            missing.append("pdb_function_names")
        if args.struct_names and pdb_counts.missing_layouts:
            missing.append("requested_type_layouts")
        if not (pdb_counts.imported_struct or pdb_counts.imported_union):
            missing.append("pdb_type_layouts")
        if not pdb_counts.imported_function_proto:
            missing.append("pdb_function_prototypes")
    return missing


def _step_has_facts(step: ProjectBootstrapStep | None) -> bool:
    return bool(step and step.ran and step.ok and step.count > 0)


def _has_call_xref_facts(steps: list[ProjectBootstrapStep]) -> bool:
    return any(
        step.name in {"index_callgraph", "index_pe_direct_calls"}
        and _step_has_facts(step)
        for step in steps
    )


def build_tool() -> MemoryTool[
    WindowsBootstrapProjectFactsArgs, WindowsBootstrapProjectFactsResult
]:
    return WindowsBootstrapProjectFactsTool()
