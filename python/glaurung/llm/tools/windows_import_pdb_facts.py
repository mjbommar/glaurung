from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from ..kb import type_db
from .base import MemoryTool, ToolMeta


class WindowsImportPdbFactsArgs(BaseModel):
    project_path: str = Field(..., description="Path to the .glaurung SQLite project.")
    pe_path: str = Field(..., description="Path to the PE binary whose PDB should be imported.")
    pdb_cache_dir: str = Field(
        ...,
        description="Microsoft-style PDB cache directory containing <pdb>/<GUIDAGE>/<pdb>.",
    )
    struct_names: list[str] = Field(
        default_factory=list,
        description="Optional PDB struct/class/union names to import as type layouts.",
    )
    import_types: bool = Field(
        True,
        description=(
            "If true, import requested type layouts and PDB procedure records; "
            "if false, import only public function names."
        ),
    )
    max_prototypes: int = Field(
        512,
        ge=0,
        description="Maximum PDB function-prototype type records to persist.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact PDB import evidence node to the active KB.",
    )


class PdbFactImportCounts(BaseModel):
    cache_hit: bool = False
    imported_struct: int = 0
    imported_union: int = 0
    imported_function_proto: int = 0
    imported_function_name: int = 0
    public_symbols: int = 0
    skipped_manual_function_name: int = 0
    missing_layouts: list[str] = Field(default_factory=list)


class WindowsImportPdbFactsResult(BaseModel):
    project_path: str
    pe_path: str
    pdb_cache_dir: str
    counts: PdbFactImportCounts
    fact_coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsImportPdbFactsTool(
    MemoryTool[WindowsImportPdbFactsArgs, WindowsImportPdbFactsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_import_pdb_facts",
                description=(
                    "Import matching PE/PDB public names, requested type layouts, "
                    "and PDB prototype type records into a .glaurung project."
                ),
                tags=("windows", "pe", "pdb", "types", "project"),
            ),
            WindowsImportPdbFactsArgs,
            WindowsImportPdbFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsImportPdbFactsArgs,
    ) -> WindowsImportPdbFactsResult:
        project_path = Path(args.project_path)
        pe_path = Path(args.pe_path)
        pdb_cache_dir = Path(args.pdb_cache_dir)
        if not pe_path.exists():
            raise ValueError(f"{pe_path}: PE binary does not exist")
        if not pdb_cache_dir.exists():
            raise ValueError(f"{pdb_cache_dir}: PDB cache directory does not exist")

        project = PersistentKnowledgeBase.open(project_path, binary_path=pe_path)
        try:
            if args.import_types:
                raw_counts = type_db.import_pe_pdb_types(
                    project,
                    str(pe_path),
                    str(pdb_cache_dir),
                    args.struct_names,
                    max_prototypes=args.max_prototypes,
                )
            else:
                raw_counts = type_db.import_pe_pdb_public_names(
                    project,
                    str(pe_path),
                    str(pdb_cache_dir),
                )
        finally:
            project.close()

        counts = _counts(raw_counts)
        coverage = _fact_coverage(counts)
        missing = _missing_capabilities(counts, requested_structs=args.struct_names)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_import_pdb_facts",
                    props={
                        "project_path": str(project_path),
                        "pe_path": str(pe_path),
                        "cache_hit": counts.cache_hit,
                        "imported_function_name": counts.imported_function_name,
                        "imported_function_proto": counts.imported_function_proto,
                        "imported_struct": counts.imported_struct,
                        "imported_union": counts.imported_union,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsImportPdbFactsResult(
            project_path=str(project_path),
            pe_path=str(pe_path),
            pdb_cache_dir=str(pdb_cache_dir),
            counts=counts,
            fact_coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "PDB facts were persisted to the .glaurung project; source reachability and vulnerability truth are not implied"
            ],
        )


def _counts(raw: dict) -> PdbFactImportCounts:
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


def _fact_coverage(counts: PdbFactImportCounts) -> list[str]:
    coverage: list[str] = []
    if counts.cache_hit:
        coverage.append("cached_pdb")
    if counts.public_symbols:
        coverage.append("pdb_public_symbols")
    if counts.imported_function_name:
        coverage.append("pdb_function_names")
    if counts.imported_struct or counts.imported_union:
        coverage.append("pdb_type_layouts")
    if counts.imported_function_proto:
        coverage.append("pdb_function_prototypes")
    return coverage


def _missing_capabilities(
    counts: PdbFactImportCounts,
    *,
    requested_structs: list[str],
) -> list[str]:
    missing: list[str] = []
    if not counts.cache_hit:
        missing.append("cached_pdb")
    if not counts.public_symbols:
        missing.append("pdb_public_symbols")
    if not counts.imported_function_name:
        missing.append("pdb_function_names")
    if requested_structs and counts.missing_layouts:
        missing.append("requested_type_layouts")
    if not (counts.imported_struct or counts.imported_union):
        missing.append("pdb_type_layouts")
    if not counts.imported_function_proto:
        missing.append("pdb_function_prototypes")
    return missing


def build_tool() -> MemoryTool[WindowsImportPdbFactsArgs, WindowsImportPdbFactsResult]:
    return WindowsImportPdbFactsTool()
