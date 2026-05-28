from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_project_data_table_facts import (
    DataTableQueryKind,
    ProjectDataTableFact,
    WindowsProjectDataTableFactsArgs,
    WindowsProjectDataTableFactsResult,
    WindowsProjectDataTableFactsTool,
)


DataTableDeltaStatus = Literal["added", "removed", "changed", "unchanged"]


class ProjectDataTableDelta(BaseModel):
    table_key: str
    status: DataTableDeltaStatus
    table_kind: str
    name: str | None = None
    before: ProjectDataTableFact | None = None
    after: ProjectDataTableFact | None = None
    changed_fields: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)
    review_priority: int = Field(ge=0)


class WindowsProjectDataTableDiffArgs(BaseModel):
    before_project_path: str = Field(..., description="Pre-change .glaurung project.")
    after_project_path: str = Field(..., description="Post-change .glaurung project.")
    before_binary_id: int | None = None
    after_binary_id: int | None = None
    before_binary_path: str | None = Field(
        None,
        description="Optional pre-change PE path for native code-pointer tables.",
    )
    after_binary_path: str | None = Field(
        None,
        description="Optional post-change PE path for native code-pointer tables.",
    )
    table_kind: DataTableQueryKind = "all"
    name_contains: str | None = None
    include_unchanged: bool = False
    min_entries: int = Field(2, ge=1, le=4096)
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    include_native_code_pointers: bool = True
    max_rows: int = Field(128, ge=0, le=4096)
    max_entries_per_table: int = Field(32, ge=0, le=512)
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact data-table-diff evidence node.",
    )


class WindowsProjectDataTableDiffResult(BaseModel):
    before_project_path: str
    after_project_path: str
    before_table_count: int
    after_table_count: int
    added_count: int
    removed_count: int
    changed_count: int
    unchanged_count: int
    returned_count: int
    deltas: list[ProjectDataTableDelta]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectDataTableDiffTool(
    MemoryTool[WindowsProjectDataTableDiffArgs, WindowsProjectDataTableDiffResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_data_table_diff",
                description=(
                    "Compare recovered Windows project data/table candidates "
                    "across two .glaurung projects and report dispatch, callback, "
                    "vtable, jump-table, selector, import-thunk, and code-pointer "
                    "table deltas."
                ),
                tags=("windows", "pe", "project", "patch", "diff", "tables"),
            ),
            WindowsProjectDataTableDiffArgs,
            WindowsProjectDataTableDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectDataTableDiffArgs,
    ) -> WindowsProjectDataTableDiffResult:
        before_path = Path(args.before_project_path).expanduser()
        after_path = Path(args.after_project_path).expanduser()
        if not before_path.exists():
            raise ValueError(f"{before_path}: before .glaurung project does not exist")
        if not after_path.exists():
            raise ValueError(f"{after_path}: after .glaurung project does not exist")

        before = _table_facts(
            ctx,
            kb,
            project_path=str(before_path),
            binary_id=args.before_binary_id,
            binary_path=args.before_binary_path,
            args=args,
        )
        after = _table_facts(
            ctx,
            kb,
            project_path=str(after_path),
            binary_id=args.after_binary_id,
            binary_path=args.after_binary_path,
            args=args,
        )
        deltas_all = _deltas(
            before.tables,
            after.tables,
            include_unchanged=args.include_unchanged,
            name_contains=args.name_contains,
        )
        counts = _counts(deltas_all)
        deltas = deltas_all[: args.max_rows] if args.max_rows else []

        result = WindowsProjectDataTableDiffResult(
            before_project_path=str(before_path),
            after_project_path=str(after_path),
            before_table_count=len(before.tables),
            after_table_count=len(after.tables),
            added_count=counts["added"],
            removed_count=counts["removed"],
            changed_count=counts["changed"],
            unchanged_count=counts["unchanged"],
            returned_count=len(deltas),
            deltas=deltas,
            coverage=_coverage(before.coverage, after.coverage, deltas_all),
            missing_capabilities=_missing(
                before.missing_capabilities, after.missing_capabilities, deltas_all
            ),
            notes=[
                "project data-table diff is patch-triage metadata, not vulnerability evidence",
                "table deltas should route to data-table, source/gate, and decompile review before promotion",
            ],
        )

        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_data_table_diff",
                    props={
                        "before_project_path": result.before_project_path,
                        "after_project_path": result.after_project_path,
                        "changed_count": result.changed_count,
                        "added_count": result.added_count,
                        "removed_count": result.removed_count,
                    },
                )
            )
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": node.id})

        return result


def _table_facts(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    *,
    project_path: str,
    binary_id: int | None,
    binary_path: str | None,
    args: WindowsProjectDataTableDiffArgs,
) -> WindowsProjectDataTableFactsResult:
    return WindowsProjectDataTableFactsTool().run(
        ctx,
        kb,
        WindowsProjectDataTableFactsArgs(
            project_path=project_path,
            binary_id=binary_id,
            binary_path=binary_path,
            table_kind=args.table_kind,
            name_contains=args.name_contains,
            min_entries=args.min_entries,
            min_confidence=args.min_confidence,
            include_native_code_pointers=args.include_native_code_pointers,
            max_tables=4096,
            max_entries_per_table=args.max_entries_per_table,
            add_to_kb=False,
        ),
    )


def _deltas(
    before: list[ProjectDataTableFact],
    after: list[ProjectDataTableFact],
    *,
    include_unchanged: bool,
    name_contains: str | None,
) -> list[ProjectDataTableDelta]:
    before_by_key = {_table_key(table): table for table in before}
    after_by_key = {_table_key(table): table for table in after}
    needle = name_contains.lower() if name_contains else None
    out: list[ProjectDataTableDelta] = []
    for key in sorted(set(before_by_key) | set(after_by_key)):
        old = before_by_key.get(key)
        new = after_by_key.get(key)
        status, changed = _status_and_changes(old, new)
        if status == "unchanged" and not include_unchanged:
            continue
        item = new or old
        if item is None:
            continue
        if needle and not _matches(item, needle):
            continue
        relevance = _security_relevance(status, changed, old, new)
        out.append(
            ProjectDataTableDelta(
                table_key=key,
                status=status,
                table_kind=item.table_kind,
                name=item.name,
                before=old,
                after=new,
                changed_fields=changed,
                reason_codes=_reason_codes(status, changed, relevance),
                security_relevance=relevance,
                review_priority=_priority(status, changed, relevance),
            )
        )
    return sorted(out, key=_sort_key)


def _status_and_changes(
    before: ProjectDataTableFact | None,
    after: ProjectDataTableFact | None,
) -> tuple[DataTableDeltaStatus, list[str]]:
    if before is None and after is not None:
        return "added", ["table"]
    if before is not None and after is None:
        return "removed", ["table"]
    if before is None or after is None:
        return "unchanged", []
    changed: list[str] = []
    for field in (
        "table_kind",
        "name",
        "c_type",
        "section",
        "size_bytes",
        "slot_size",
        "entry_count",
        "entry_count_source",
        "source",
        "read_xref_count",
        "write_xref_count",
        "source_function_names",
        "security_relevance",
    ):
        if getattr(before, field) != getattr(after, field):
            changed.append(field)
    if _entry_targets(before) != _entry_targets(after):
        changed.append("entry_targets")
    if abs(before.confidence - after.confidence) >= 0.01:
        changed.append("confidence")
    return ("changed" if changed else "unchanged"), changed


def _entry_targets(table: ProjectDataTableFact) -> list[str]:
    out = []
    for entry in table.entries:
        out.append(
            "|".join(
                str(value or "")
                for value in (
                    entry.index,
                    entry.target_name,
                    entry.target,
                    entry.slot,
                    entry.xref_kind,
                )
            )
        )
    return sorted(out)


def _security_relevance(
    status: DataTableDeltaStatus,
    changed: list[str],
    before: ProjectDataTableFact | None,
    after: ProjectDataTableFact | None,
) -> list[str]:
    table = after or before
    relevance = list(table.security_relevance if table is not None else [])
    if status in {"added", "removed"}:
        relevance.append(f"table_{status}")
    if "entry_count" in changed:
        relevance.append("table_entry_count_delta")
    if "entry_targets" in changed:
        relevance.append("table_target_delta")
    if "source_function_names" in changed:
        relevance.append("table_source_function_delta")
    if {"c_type", "size_bytes", "slot_size"} & set(changed):
        relevance.append("table_layout_delta")
    if "read_xref_count" in changed or "write_xref_count" in changed:
        relevance.append("table_xref_count_delta")
    return _dedupe(relevance)


def _reason_codes(
    status: DataTableDeltaStatus,
    changed: list[str],
    relevance: list[str],
) -> list[str]:
    return _dedupe(
        [
            f"table_{status}",
            *(f"changed_{field}" for field in changed if field != "table"),
            *relevance,
        ]
    )


def _priority(
    status: DataTableDeltaStatus,
    changed: list[str],
    relevance: list[str],
) -> int:
    priority = 46
    if status == "changed":
        priority += 12
    if status in {"added", "removed"}:
        priority += 8
    if any(
        item
        in {
            "dispatch_table",
            "callback_table",
            "virtual_dispatch_table",
            "selector_indexed_control_flow",
            "import_thunk_table",
        }
        for item in relevance
    ):
        priority += 18
    if "table_target_delta" in relevance:
        priority += 10
    if {"entry_count", "entry_targets", "c_type", "size_bytes"} & set(changed):
        priority += 6
    return priority


def _table_key(table: ProjectDataTableFact) -> str:
    if table.name:
        return f"name:{table.name.lower()}"
    if table.source == "native_pe_code_pointer_scan" and table.section is not None:
        return f"native:{table.table_kind}:{table.section}:{table.entry_count}"
    return f"va:{table.table_kind}:{table.table or table.table_va or 'unknown'}"


def _matches(table: ProjectDataTableFact, needle: str) -> bool:
    haystack = " ".join(
        value
        for value in (
            table.name,
            table.c_type,
            table.table_kind,
            table.source,
            table.section,
        )
        if value
    ).lower()
    return needle in haystack


def _counts(deltas: list[ProjectDataTableDelta]) -> dict[str, int]:
    return {
        status: sum(1 for delta in deltas if delta.status == status)
        for status in ("added", "removed", "changed", "unchanged")
    }


def _coverage(
    before: list[str],
    after: list[str],
    deltas: list[ProjectDataTableDelta],
) -> list[str]:
    coverage = _dedupe([*before, *after])
    if deltas:
        coverage.append("data_table_deltas")
    if any("dispatch_table" in delta.security_relevance for delta in deltas):
        coverage.append("dispatch_table_deltas")
    if any("callback_table" in delta.security_relevance for delta in deltas):
        coverage.append("callback_table_deltas")
    if any("table_target_delta" in delta.security_relevance for delta in deltas):
        coverage.append("table_target_deltas")
    return coverage


def _missing(
    before: list[str],
    after: list[str],
    deltas: list[ProjectDataTableDelta],
) -> list[str]:
    missing = _dedupe(
        [f"before:{item}" for item in before] + [f"after:{item}" for item in after]
    )
    if not deltas:
        missing.append("data_table_deltas")
    return missing


def _sort_key(delta: ProjectDataTableDelta) -> tuple[int, str, str]:
    return (-delta.review_priority, delta.table_kind, delta.table_key)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsProjectDataTableDiffTool:
    return WindowsProjectDataTableDiffTool()
