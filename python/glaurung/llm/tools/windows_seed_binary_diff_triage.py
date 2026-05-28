from __future__ import annotations

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.binary_diff import diff_binaries
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_vulnerability_seed_catalog import (
    WindowsVulnerabilitySeedCatalogArgs,
    _filter_seeds,
    _load_surfaces,
    _load_targets,
    _load_yaml_list,
    _optional_metadata_path,
    _seed_record,
)


class WindowsSeedBinaryDiffTriageArgs(BaseModel):
    binary_a: str = Field(..., description="Pre-change binary path.")
    binary_b: str = Field(..., description="Post-change binary path.")
    seeds_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-vulnerability-seeds.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    manifest_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-build-corpus.yaml.",
    )
    surfaces_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-surfaces.yaml.",
    )
    seed_id: str | None = Field(None, description="Optional seed id filter.")
    public_id: str | None = Field(None, description="Optional CVE/advisory id filter.")
    target_id: str | None = Field(None, description="Optional seed target id filter.")
    component: str | None = Field(None, description="Optional component filename filter.")
    skip_anonymous: bool = Field(
        True,
        description="Drop sub_<hex> placeholder names that often shift between builds.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact seed-diff evidence node to the KB.",
    )


class SeedFunctionDiffStatus(BaseModel):
    function: str
    status: str
    a_size: int | None = None
    b_size: int | None = None
    a_hash: str | None = None
    b_hash: str | None = None


class SeedBinaryDiffTriageRecord(BaseModel):
    seed_id: str
    public_ids: list[str]
    title: str
    target_id: str
    component: str
    primitive: str
    invariant_family: str
    functions: list[SeedFunctionDiffStatus]
    changed_functions: list[str]
    missing_functions: list[str]
    diff_signals: list[str]
    validation_requirements: list[str]


class WindowsSeedBinaryDiffTriageResult(BaseModel):
    binary_a: str
    binary_b: str
    seed_count_total: int
    matched_seed_count: int
    changed: int
    added: int
    removed: int
    same: int
    records: list[SeedBinaryDiffTriageRecord]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSeedBinaryDiffTriageTool(
    MemoryTool[
        WindowsSeedBinaryDiffTriageArgs,
        WindowsSeedBinaryDiffTriageResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_seed_binary_diff_triage",
                description=(
                    "Join ASB public vulnerability seeds to Glaurung "
                    "function-level binary diff rows for patch-regression triage."
                ),
                tags=("windows", "pe", "diff", "vulnerability", "patch"),
            ),
            WindowsSeedBinaryDiffTriageArgs,
            WindowsSeedBinaryDiffTriageResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSeedBinaryDiffTriageArgs,
    ) -> WindowsSeedBinaryDiffTriageResult:
        seeds_path = _optional_metadata_path(
            args.seeds_path,
            "data/kg/pe-vulnerability-seeds.yaml",
        )
        if seeds_path is None:
            raise FileNotFoundError("could not resolve pe-vulnerability-seeds.yaml")
        manifest_path = _optional_metadata_path(
            args.manifest_path,
            "data/kg/pe-build-corpus.yaml",
        )
        surfaces_path = _optional_metadata_path(
            args.surfaces_path,
            "data/kg/pe-surfaces.yaml",
        )
        targets = _load_targets(manifest_path) if manifest_path is not None else {}
        surfaces = _load_surfaces(surfaces_path) if surfaces_path is not None else {}
        all_seeds = [
            _seed_record(entry, targets, surfaces, seeds_path)
            for entry in _load_yaml_list(seeds_path)
        ]
        seed_count_total = len(all_seeds)
        filter_args = WindowsVulnerabilitySeedCatalogArgs(
            seed_id=args.seed_id,
            public_id=args.public_id,
            target_id=args.target_id,
            component=args.component,
        )
        seeds = _filter_seeds(all_seeds, filter_args)
        diff = diff_binaries(
            args.binary_a,
            args.binary_b,
            skip_anonymous=args.skip_anonymous,
        )
        rows_by_name = {row.name: row for row in diff.rows}
        records = [_triage_seed(seed, rows_by_name) for seed in seeds]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_seed_binary_diff_triage",
                    props={
                        "binary_a": args.binary_a,
                        "binary_b": args.binary_b,
                        "seed_id": args.seed_id,
                        "public_id": args.public_id,
                        "target_id": args.target_id,
                        "component": args.component,
                        "matched_seed_count": len(records),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSeedBinaryDiffTriageResult(
            binary_a=diff.binary_a,
            binary_b=diff.binary_b,
            seed_count_total=seed_count_total,
            matched_seed_count=len(records),
            changed=diff.changed,
            added=diff.added,
            removed=diff.removed,
            same=diff.same,
            records=records,
            evidence_node_id=evidence_node_id,
            notes=[
                "seed binary diff triage only shows changed seed functions; it does not prove a fix or bug"
            ],
        )


def _triage_seed(seed, rows_by_name: dict[str, object]) -> SeedBinaryDiffTriageRecord:
    functions: list[SeedFunctionDiffStatus] = []
    changed: list[str] = []
    missing: list[str] = []
    for function in seed.functions:
        row = rows_by_name.get(function)
        if row is None:
            functions.append(SeedFunctionDiffStatus(function=function, status="not_in_diff"))
            missing.append(function)
            continue
        status = str(row.status)
        if status == "changed":
            changed.append(function)
        functions.append(
            SeedFunctionDiffStatus(
                function=function,
                status=status,
                a_size=row.a.size if row.a is not None else None,
                b_size=row.b.size if row.b is not None else None,
                a_hash=row.a.body_hash if row.a is not None else None,
                b_hash=row.b.body_hash if row.b is not None else None,
            )
        )
    return SeedBinaryDiffTriageRecord(
        seed_id=seed.id,
        public_ids=seed.public_ids,
        title=seed.title,
        target_id=seed.target_id,
        component=seed.component,
        primitive=seed.primitive,
        invariant_family=seed.invariant_family,
        functions=functions,
        changed_functions=changed,
        missing_functions=missing,
        diff_signals=seed.diff_signals,
        validation_requirements=seed.validation_requirements,
    )


def build_tool() -> WindowsSeedBinaryDiffTriageTool:
    return WindowsSeedBinaryDiffTriageTool()
