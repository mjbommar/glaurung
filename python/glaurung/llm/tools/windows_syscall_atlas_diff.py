from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_syscall_stub_atlas import (
    ServiceTableKind,
    WindowsSyscallStubAtlasArgs,
    WindowsSyscallStubAtlasTool,
    WindowsSyscallStubFact,
)


SyscallDiffStatus = Literal["same", "changed", "added", "removed"]
SyscallDiffChange = Literal[
    "syscall_number",
    "service_table",
    "rva",
    "va",
    "file_offset",
    "byte_pattern",
    "dispatch_kind",
    "stub_shape",
]


class WindowsSyscallAtlasDiffArgs(BaseModel):
    binary_a: str | None = Field(None, description="Optional baseline PE path.")
    binary_b: str | None = Field(None, description="Optional candidate PE path.")
    pseudocode_a: str = Field(
        "",
        description="Optional baseline lifted/text syscall stubs.",
    )
    pseudocode_b: str = Field(
        "",
        description="Optional candidate lifted/text syscall stubs.",
    )
    raw_bytes_hex_a: str | None = Field(
        None,
        description="Optional baseline raw x64 syscall-stub bytes as hex.",
    )
    raw_bytes_hex_b: str | None = Field(
        None,
        description="Optional candidate raw x64 syscall-stub bytes as hex.",
    )
    user_stub_module_a: str | None = Field(
        None,
        description="Optional baseline module name.",
    )
    user_stub_module_b: str | None = Field(
        None,
        description="Optional candidate module name.",
    )
    service_table: ServiceTableKind = Field(
        "unknown",
        description="Expected service-table kind for emitted rows.",
    )
    status: SyscallDiffStatus | None = Field(
        None,
        description="Optional status filter.",
    )
    symbol: str | None = Field(None, description="Optional exact syscall stub symbol.")
    symbol_contains: str | None = Field(
        None,
        description="Optional case-sensitive symbol substring filter.",
    )
    include_same: bool = Field(
        False,
        description="If true, include unchanged rows in the returned row list.",
    )
    compare_locations: bool = Field(
        False,
        description=(
            "If true, treat RVA, VA, and file-offset changes as row changes. "
            "Defaults false because normal build-to-build layout drift is noisy."
        ),
    )
    compare_byte_patterns: bool = Field(
        True,
        description="If true, treat changed syscall stub bytes as row changes.",
    )
    compare_stub_shapes: bool = Field(
        True,
        description=(
            "If true, treat dispatch mechanism or normalized stub-shape changes "
            "as row changes."
        ),
    )
    max_stubs: int = Field(
        4096,
        ge=1,
        description="Maximum atlas rows to extract from each side.",
    )
    max_rows: int = Field(
        64,
        ge=0,
        description="Maximum diff rows to return after filtering. Use 0 for summary only.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact syscall-atlas-diff evidence node to the KB.",
    )


class SyscallAtlasDiffRow(BaseModel):
    symbol: str
    status: SyscallDiffStatus
    changes: list[SyscallDiffChange] = Field(default_factory=list)
    a: WindowsSyscallStubFact | None = None
    b: WindowsSyscallStubFact | None = None


class WindowsSyscallAtlasDiffResult(BaseModel):
    binary_a: str | None = None
    binary_b: str | None = None
    syscall_count_a: int
    syscall_count_b: int
    same: int
    changed: int
    added: int
    removed: int
    renumbered: int
    moved: int
    byte_pattern_changed: int
    dispatch_changed: int
    stub_shape_changed: int
    filtered_row_count: int
    rows: list[SyscallAtlasDiffRow]
    coverage: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsSyscallAtlasDiffTool(
    MemoryTool[WindowsSyscallAtlasDiffArgs, WindowsSyscallAtlasDiffResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_syscall_atlas_diff",
                description=(
                    "Diff two Windows syscall stub atlases from PE binaries, "
                    "lifted text, or raw stub bytes, reporting added, removed, "
                    "renumbered, moved, and byte-pattern-changed syscall rows."
                ),
                tags=("windows", "pe", "syscall", "ssdt", "diff"),
            ),
            WindowsSyscallAtlasDiffArgs,
            WindowsSyscallAtlasDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsSyscallAtlasDiffArgs,
    ) -> WindowsSyscallAtlasDiffResult:
        atlas_a = _build_atlas(
            ctx,
            kb,
            binary_path=args.binary_a,
            pseudocode=args.pseudocode_a,
            raw_bytes_hex=args.raw_bytes_hex_a,
            module=args.user_stub_module_a,
            service_table=args.service_table,
            max_stubs=args.max_stubs,
        )
        atlas_b = _build_atlas(
            ctx,
            kb,
            binary_path=args.binary_b,
            pseudocode=args.pseudocode_b,
            raw_bytes_hex=args.raw_bytes_hex_b,
            module=args.user_stub_module_b,
            service_table=args.service_table,
            max_stubs=args.max_stubs,
        )
        all_rows = _diff_atlases(
            atlas_a.stubs,
            atlas_b.stubs,
            include_same=True,
            compare_locations=args.compare_locations,
            compare_byte_patterns=args.compare_byte_patterns,
            compare_stub_shapes=args.compare_stub_shapes,
        )
        rows = (
            all_rows
            if args.include_same
            else [row for row in all_rows if row.status != "same"]
        )
        same_count = sum(1 for row in all_rows if row.status == "same")
        changed_rows = [row for row in all_rows if row.status == "changed"]
        added_count = sum(1 for row in all_rows if row.status == "added")
        removed_count = sum(1 for row in all_rows if row.status == "removed")

        filtered = _filter_rows(rows, args)
        filtered_row_count = len(filtered)
        result_rows = filtered[: args.max_rows] if args.max_rows else []
        coverage = sorted(
            set(atlas_a.coverage + atlas_b.coverage + ["syscall_atlas_diff"])
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_syscall_atlas_diff",
                    props={
                        "binary_a": args.binary_a,
                        "binary_b": args.binary_b,
                        "syscall_count_a": atlas_a.syscall_count,
                        "syscall_count_b": atlas_b.syscall_count,
                        "filtered_row_count": filtered_row_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsSyscallAtlasDiffResult(
            binary_a=args.binary_a,
            binary_b=args.binary_b,
            syscall_count_a=atlas_a.syscall_count,
            syscall_count_b=atlas_b.syscall_count,
            same=same_count,
            changed=len(changed_rows),
            added=added_count,
            removed=removed_count,
            renumbered=sum(
                1 for row in changed_rows if "syscall_number" in row.changes
            ),
            moved=sum(
                1
                for row in changed_rows
                if any(change in row.changes for change in ("rva", "va", "file_offset"))
            ),
            byte_pattern_changed=sum(
                1 for row in changed_rows if "byte_pattern" in row.changes
            ),
            dispatch_changed=sum(
                1 for row in changed_rows if "dispatch_kind" in row.changes
            ),
            stub_shape_changed=sum(
                1 for row in changed_rows if "stub_shape" in row.changes
            ),
            filtered_row_count=filtered_row_count,
            rows=result_rows,
            coverage=coverage,
            evidence_node_id=evidence_node_id,
            notes=[
                "syscall atlas diff identifies service-table drift; "
                "kernel handler correlation and live SSDT comparison are separate steps"
            ],
        )


def _build_atlas(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    *,
    binary_path: str | None,
    pseudocode: str,
    raw_bytes_hex: str | None,
    module: str | None,
    service_table: ServiceTableKind,
    max_stubs: int,
):
    if module is None and binary_path:
        module = Path(binary_path).name
    tool = WindowsSyscallStubAtlasTool()
    return tool.run(
        ctx,
        kb,
        WindowsSyscallStubAtlasArgs(
            binary_path=binary_path,
            pseudocode=pseudocode,
            raw_bytes_hex=raw_bytes_hex,
            user_stub_module=module,
            service_table=service_table,
            max_stubs=max_stubs,
        ),
    )


def _diff_atlases(
    a_stubs: list[WindowsSyscallStubFact],
    b_stubs: list[WindowsSyscallStubFact],
    *,
    include_same: bool,
    compare_locations: bool,
    compare_byte_patterns: bool,
    compare_stub_shapes: bool,
) -> list[SyscallAtlasDiffRow]:
    by_symbol_a = {stub.user_stub_symbol: stub for stub in a_stubs}
    by_symbol_b = {stub.user_stub_symbol: stub for stub in b_stubs}
    rows: list[SyscallAtlasDiffRow] = []
    for symbol in sorted(set(by_symbol_a) | set(by_symbol_b)):
        a = by_symbol_a.get(symbol)
        b = by_symbol_b.get(symbol)
        if a is None and b is not None:
            rows.append(SyscallAtlasDiffRow(symbol=symbol, status="added", b=b))
            continue
        if b is None and a is not None:
            rows.append(SyscallAtlasDiffRow(symbol=symbol, status="removed", a=a))
            continue
        if a is None or b is None:
            continue
        changes = _changes(
            a,
            b,
            compare_locations=compare_locations,
            compare_byte_patterns=compare_byte_patterns,
            compare_stub_shapes=compare_stub_shapes,
        )
        if changes:
            rows.append(
                SyscallAtlasDiffRow(
                    symbol=symbol,
                    status="changed",
                    changes=changes,
                    a=a,
                    b=b,
                )
            )
        elif include_same:
            rows.append(SyscallAtlasDiffRow(symbol=symbol, status="same", a=a, b=b))
    return rows


def _changes(
    a: WindowsSyscallStubFact,
    b: WindowsSyscallStubFact,
    *,
    compare_locations: bool,
    compare_byte_patterns: bool,
    compare_stub_shapes: bool,
) -> list[SyscallDiffChange]:
    changes: list[SyscallDiffChange] = []
    if a.syscall_number != b.syscall_number:
        changes.append("syscall_number")
    if a.service_table != b.service_table:
        changes.append("service_table")
    if compare_locations:
        if a.rva is not None and b.rva is not None and a.rva != b.rva:
            changes.append("rva")
        if a.va is not None and b.va is not None and a.va != b.va:
            changes.append("va")
        if (
            a.file_offset is not None
            and b.file_offset is not None
            and a.file_offset != b.file_offset
        ):
            changes.append("file_offset")
    if (
        compare_byte_patterns
        and a.byte_pattern
        and b.byte_pattern
        and a.byte_pattern != b.byte_pattern
    ):
        changes.append("byte_pattern")
    if compare_stub_shapes:
        if a.dispatch_kind != b.dispatch_kind:
            changes.append("dispatch_kind")
        if a.stub_shape != b.stub_shape:
            changes.append("stub_shape")
    return changes


def _filter_rows(
    rows: list[SyscallAtlasDiffRow],
    args: WindowsSyscallAtlasDiffArgs,
) -> list[SyscallAtlasDiffRow]:
    filtered = rows
    if args.status:
        filtered = [row for row in filtered if row.status == args.status]
    if args.symbol:
        filtered = [row for row in filtered if row.symbol == args.symbol]
    if args.symbol_contains:
        filtered = [row for row in filtered if args.symbol_contains in row.symbol]
    return filtered


def build_tool() -> WindowsSyscallAtlasDiffTool:
    return WindowsSyscallAtlasDiffTool()
