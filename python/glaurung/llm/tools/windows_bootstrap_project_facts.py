from __future__ import annotations

import hashlib
import re
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb import (
    cfg_db,
    pe_direct_calls,
    type_db,
    windows_boundaries,
    windows_callsite_facts,
    windows_sysinfo,
    xref_db,
)
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from glaurung.windows_config import WindowsAnalysisConfig, load_windows_analysis_config
from .base import MemoryTool, ToolMeta
from .windows_import_pdb_facts import PdbFactImportCounts
from .windows_project_fact_summary import (
    WindowsProjectFactSummaryArgs,
    WindowsProjectFactSummaryResult,
    WindowsProjectFactSummaryTool,
)


class WindowsBootstrapProjectFactsArgs(BaseModel):
    pe_path: str = Field(..., description="Path to the Windows PE binary to index.")
    project_path: str = Field(
        ..., description="Path to create or update as a .glaurung project."
    )
    pdb_cache_dir: str | None = Field(
        None,
        description="Optional Microsoft-style PDB cache directory for PDB fact import.",
    )
    struct_names: list[str] = Field(
        default_factory=list,
        description="Optional PDB struct/class/union names to import as type layouts.",
    )
    analysis_config_path: str | None = Field(
        None,
        description=(
            "Optional Windows analysis config YAML/JSON. Defaults to "
            ".glaurung/windows-analysis.yaml or $GLAURUNG_WINDOWS_ANALYSIS_CONFIG."
        ),
    )
    max_read_bytes: int | None = Field(
        None,
        ge=1,
        description="Override maximum bytes read from the PE during analysis.",
    )
    max_file_size: int | None = Field(
        None,
        ge=1,
        description="Override maximum allowed PE file size during analysis.",
    )
    max_functions: int | None = Field(
        None,
        ge=0,
        description="Override maximum functions; 0 means unlimited.",
    )
    max_blocks: int | None = Field(
        None,
        ge=1,
        description="Override maximum CFG basic blocks.",
    )
    max_instructions: int | None = Field(
        None,
        ge=1,
        description="Override maximum decoded/lifted instructions.",
    )
    timeout_ms: int | None = Field(
        None,
        ge=1,
        description="Override per-analysis timeout in milliseconds.",
    )
    index_callgraph: bool = Field(
        True,
        description="If true, persist call xrefs and analyzer function names.",
    )
    index_pe_direct_calls: bool = Field(
        True,
        description=(
            "If true, scan executable PE sections for rel32 calls to known "
            "function-name targets. This runs without full CFG dependence."
        ),
    )
    index_function_boundaries: bool = Field(
        True,
        description=(
            "If true, persist confidence-ranked function-boundary candidates "
            "from PDB/public names, .pdata, and call-target facts."
        ),
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
    index_sysinfo_dispatch: bool = Field(
        True,
        description=(
            "If true, persist first-class NtQuerySystemInformation class-to-helper "
            "dispatch facts."
        ),
    )
    index_callsite_path_conditions: bool = Field(
        True,
        description=(
            "If true, attach nearby persisted branch-condition facts to callsites."
        ),
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
    project_facts_output_path: str | None = Field(
        None,
        description=(
            "Optional ASB pe-project-facts.yaml path to update with a manifest "
            "record for the generated .glaurung project."
        ),
    )
    project_fact_id: str | None = Field(
        None,
        description=(
            "Optional stable manifest record id. Defaults to "
            "<target_id>_<build_label>_<binary-stem>."
        ),
    )
    target_id: str | None = Field(
        None,
        description="Optional build-corpus target id for the manifest row.",
    )
    build_label: str | None = Field(
        None,
        description="Optional build label for the manifest row.",
    )
    build_number: str | None = Field(
        None,
        description="Optional Windows build number for the manifest row.",
    )
    architecture: str = Field(
        "x64",
        description="Architecture string for the manifest row.",
    )
    binary_filename: str | None = Field(
        None,
        description="Optional PE filename override for the manifest row.",
    )
    manifest_note: str | None = Field(
        None,
        description="Optional note to store on the generated manifest row.",
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
    project_facts_output_path: str | None = None
    project_fact_record_id: str | None = None
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

        config = _analysis_config(args)
        project = PersistentKnowledgeBase.open(project_path, binary_path=pe_path)
        steps: list[ProjectBootstrapStep] = []
        pdb_counts: PdbFactImportCounts | None = None
        try:
            if args.import_pdb_facts and args.pdb_cache_dir:
                step, pdb_counts = _run_pdb_import_step(project, pe_path, args)
                steps.append(step)
            else:
                steps.append(
                    ProjectBootstrapStep(name="import_pdb_facts", ran=False, ok=True)
                )

            if args.index_pe_direct_calls:
                steps.append(
                    _run_count_step(
                        "index_pe_direct_calls",
                        lambda: pe_direct_calls.index_pe_direct_calls(project, pe_path),
                    )
                )
            else:
                steps.append(
                    ProjectBootstrapStep(
                        name="index_pe_direct_calls", ran=False, ok=True
                    )
                )

            if args.index_function_boundaries:
                steps.append(
                    _run_count_step(
                        "index_function_boundaries",
                        lambda: windows_boundaries.index_function_boundaries(
                            project,
                            pe_path,
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(
                    ProjectBootstrapStep(
                        name="index_function_boundaries",
                        ran=False,
                        ok=True,
                    )
                )

            if args.index_callgraph:
                steps.append(
                    _run_count_step(
                        "index_callgraph",
                        lambda: xref_db.index_callgraph(
                            project,
                            str(pe_path),
                            force=args.force_reindex,
                            max_read_bytes=config.max_read_bytes,
                            max_file_size=config.max_file_size,
                            max_functions=config.max_functions,
                            max_blocks=config.max_blocks,
                            max_instructions=config.max_instructions,
                            timeout_ms=config.timeout_ms,
                        ),
                    )
                )
            else:
                steps.append(
                    ProjectBootstrapStep(name="index_callgraph", ran=False, ok=True)
                )

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
                steps.append(
                    ProjectBootstrapStep(name="index_data_xrefs", ran=False, ok=True)
                )

            if args.index_cfg:
                steps.append(
                    _run_count_step(
                        "index_cfg",
                        lambda: cfg_db.index_cfg(
                            project,
                            str(pe_path),
                            force=args.force_reindex,
                            max_read_bytes=config.max_read_bytes,
                            max_file_size=config.max_file_size,
                            max_functions=config.max_functions,
                            max_blocks=config.max_blocks,
                            max_instructions=config.max_instructions,
                            timeout_ms=config.timeout_ms,
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
                            timeout_ms=config.timeout_ms,
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

            if args.index_sysinfo_dispatch:
                steps.append(
                    _run_count_step(
                        "index_sysinfo_dispatch",
                        lambda: windows_sysinfo.index_sysinfo_dispatch_facts(
                            project,
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(
                    ProjectBootstrapStep(
                        name="index_sysinfo_dispatch",
                        ran=False,
                        ok=True,
                    )
                )

            if args.index_callsite_path_conditions:
                steps.append(
                    _run_count_step(
                        "index_callsite_path_conditions",
                        lambda: windows_callsite_facts.index_callsite_path_conditions(
                            project,
                            force=args.force_reindex,
                        ),
                    )
                )
            else:
                steps.append(
                    ProjectBootstrapStep(
                        name="index_callsite_path_conditions",
                        ran=False,
                        ok=True,
                    )
                )

        finally:
            project.close()

        coverage = _fact_coverage(steps, pdb_counts)
        missing = _missing_capabilities(steps, pdb_counts, args)
        project_summary = WindowsProjectFactSummaryTool().run(
            ctx,
            kb,
            WindowsProjectFactSummaryArgs(project_path=str(project_path)),
        )
        manifest_path, record_id = _write_project_fact_manifest_record(
            args=args,
            pe_path=pe_path,
            project_path=project_path,
            summary=project_summary,
        )
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
                        "project_facts_output_path": manifest_path,
                        "project_fact_record_id": record_id,
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
            project_facts_output_path=manifest_path,
            project_fact_record_id=record_id,
            evidence_node_id=evidence_node_id,
            notes=[
                "bootstrap prepares project facts only; source reachability and vulnerability truth are not implied"
            ],
        )


def _run_count_step(name: str, fn: Callable[[], int]) -> ProjectBootstrapStep:
    start = perf_counter()
    try:
        count = int(fn())
    except BaseException as exc:  # pragma: no cover - native analyzer errors vary.
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
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


def _analysis_config(args: WindowsBootstrapProjectFactsArgs) -> WindowsAnalysisConfig:
    return load_windows_analysis_config(args.analysis_config_path).with_overrides(
        max_read_bytes=args.max_read_bytes,
        max_file_size=args.max_file_size,
        max_functions=args.max_functions,
        max_blocks=args.max_blocks,
        max_instructions=args.max_instructions,
        timeout_ms=args.timeout_ms,
        pdb_cache_dir=args.pdb_cache_dir,
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
    if _step_has_facts(by_name.get("index_function_boundaries")):
        coverage.append("function_boundaries")
    if _step_has_facts(by_name.get("index_cfg_dominance")):
        coverage.append("cfg_dominance")
    if _step_has_facts(by_name.get("index_branch_conditions")):
        coverage.append("branch_conditions")
    if _step_has_facts(by_name.get("index_sysinfo_dispatch")):
        coverage.append("sysinfo_dispatch")
    if _step_has_facts(by_name.get("index_callsite_path_conditions")):
        coverage.append("callsite_path_conditions")
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
    if (args.index_callgraph or args.index_pe_direct_calls) and not (
        _step_has_facts(by_name.get("index_callgraph"))
        or _step_has_facts(by_name.get("index_pe_direct_calls"))
    ):
        missing.append("call_xrefs")
    if args.index_data_xrefs and not _step_has_facts(by_name.get("index_data_xrefs")):
        missing.append("data_xrefs")
    if args.index_cfg and not _step_has_facts(by_name.get("index_cfg")):
        missing.append("persisted_cfg")
    if args.index_function_boundaries and not _step_has_facts(
        by_name.get("index_function_boundaries")
    ):
        missing.append("function_boundaries")
    if args.index_cfg_dominance and not _step_has_facts(
        by_name.get("index_cfg_dominance")
    ):
        missing.append("cfg_dominance")
    if args.index_branch_conditions and not _step_has_facts(
        by_name.get("index_branch_conditions")
    ):
        missing.append("branch_conditions")
    if args.index_sysinfo_dispatch and not _step_has_facts(
        by_name.get("index_sysinfo_dispatch")
    ):
        missing.append("sysinfo_dispatch")
    if args.index_callsite_path_conditions and not _step_has_facts(
        by_name.get("index_callsite_path_conditions")
    ):
        missing.append("callsite_path_conditions")
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


def _write_project_fact_manifest_record(
    *,
    args: WindowsBootstrapProjectFactsArgs,
    pe_path: Path,
    project_path: Path,
    summary: WindowsProjectFactSummaryResult,
) -> tuple[str | None, str | None]:
    if not args.project_facts_output_path:
        return None, None
    path = Path(args.project_facts_output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    record = _project_fact_record(args, pe_path, project_path, summary)
    existing = _load_manifest_records(path)
    key = str(record["id"])
    updated: list[dict[str, Any]] = []
    replaced = False
    for item in existing:
        if str(item.get("id") or "") == key:
            updated.append(record)
            replaced = True
        else:
            updated.append(item)
    if not replaced:
        updated.append(record)
    path.write_text(
        yaml.safe_dump(updated, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )
    return str(path), key


def _project_fact_record(
    args: WindowsBootstrapProjectFactsArgs,
    pe_path: Path,
    project_path: Path,
    summary: WindowsProjectFactSummaryResult,
) -> dict[str, Any]:
    binary_filename = args.binary_filename or pe_path.name
    target_id = args.target_id or Path(binary_filename).stem
    build_label = args.build_label or "unknown"
    record_id = args.project_fact_id or _slug(
        f"{target_id}_{build_label}_{Path(binary_filename).stem}"
    )
    return {
        "id": record_id,
        "target_id": target_id,
        "build_label": build_label,
        "build_number": args.build_number or "unknown",
        "architecture": args.architecture,
        "binary_filename": binary_filename,
        "project_path": str(project_path),
        "project_sha256": _sha256_file(project_path),
        "project_size_bytes": project_path.stat().st_size,
        "fact_sources": _fact_sources(args, summary),
        "fact_coverage": list(summary.coverage),
        "missing_facts": list(summary.missing_capabilities),
        "counts": _manifest_counts(summary),
        "notes": args.manifest_note or "generated by windows_bootstrap_project_facts",
    }


def _load_manifest_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: manifest entry {idx} is not a mapping")
        out.append(dict(item))
    return out


def _fact_sources(
    args: WindowsBootstrapProjectFactsArgs,
    summary: WindowsProjectFactSummaryResult,
) -> list[str]:
    sources = ["windows_bootstrap_project_facts"]
    if args.import_pdb_facts and args.pdb_cache_dir:
        sources.append("pdb_cache")
    if summary.counts.call_xref_count:
        sources.append("xref_db")
    if summary.counts.basic_block_count or summary.counts.cfg_edge_count:
        sources.append("cfg_db")
    if summary.counts.cfg_branch_fact_count:
        sources.append("cfg_branch_facts")
    if summary.counts.function_boundary_count:
        sources.append("function_boundaries")
    if summary.counts.sysinfo_dispatch_count:
        sources.append("windows_sysinfo_dispatch")
    if summary.counts.callsite_path_condition_count:
        sources.append("callsite_path_conditions")
    return _dedupe(sources)


def _manifest_counts(summary: WindowsProjectFactSummaryResult) -> dict[str, int]:
    counts = summary.counts
    return {
        "function_name_count": counts.function_name_count,
        "xref_count": counts.xref_count,
        "call_xref_count": counts.call_xref_count,
        "data_read_xref_count": counts.data_read_xref_count,
        "data_write_xref_count": counts.data_write_xref_count,
        "data_label_count": counts.data_label_count,
        "function_prototype_count": counts.function_prototype_count,
        "basic_block_count": counts.basic_block_count,
        "cfg_edge_count": counts.cfg_edge_count,
        "cfg_dominance_count": counts.cfg_dominance_count,
        "cfg_branch_fact_count": counts.cfg_branch_fact_count,
        "function_boundary_count": counts.function_boundary_count,
        "sysinfo_dispatch_count": counts.sysinfo_dispatch_count,
        "callsite_argument_fact_count": counts.callsite_argument_fact_count,
        "callsite_path_condition_count": counts.callsite_path_condition_count,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_").lower() or "project"


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


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
