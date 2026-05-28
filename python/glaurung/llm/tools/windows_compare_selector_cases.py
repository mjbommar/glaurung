from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_check_gate_to_sink import (
    CallSite,
    GateSite,
    SinkSite,
    WindowsCheckGateToSinkArgs,
    _extract_calls,
    _gate_record,
    _gate_sites,
    _load_yaml_list,
    _operation_record,
    _sink_sites,
)
from .windows_surface_metadata import _resolve_metadata_path


CaseDifferenceKind = Literal[
    "operation_missing_in_cases",
    "gate_missing_in_cases",
    "sink_without_gate",
]


class SelectorCaseSummary(BaseModel):
    label: str
    line_start: int
    line_end: int
    gates: list[GateSite]
    sinks: list[SinkSite]
    operation_ids: list[str]
    gate_ids: list[str]


class SelectorCaseDifference(BaseModel):
    kind: CaseDifferenceKind
    item_id: str
    item_kind: str
    present_cases: list[str]
    missing_cases: list[str]
    reason: str


class WindowsCompareSelectorCasesArgs(BaseModel):
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    pseudocode: str | None = Field(
        None,
        description="Optional pseudocode or source-like text to scan.",
    )
    function_va: int | None = Field(
        None,
        description="Optional function VA. Used only when pseudocode is omitted.",
    )
    selector: str | None = Field(
        None,
        description="Optional selector expression filter, e.g. infoClass.",
    )
    gate_kind: str | None = Field(None, description="Optional gate kind filter.")
    sink_kind: str | None = Field(None, description="Optional sink kind filter.")
    max_cases: int = Field(64, description="Maximum cases to compare.")
    timeout_ms: int = Field(500, description="Decompile timeout when function_va is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact selector-case evidence node to the KB.",
    )


class WindowsCompareSelectorCasesResult(BaseModel):
    selector_expression: str | None
    cases: list[SelectorCaseSummary]
    differences: list[SelectorCaseDifference]
    scanned_call_count: int
    pseudocode_source: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsCompareSelectorCasesTool(
    MemoryTool[WindowsCompareSelectorCasesArgs, WindowsCompareSelectorCasesResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_compare_selector_cases",
                description=(
                    "Compare Windows switch/selector cases for case-specific "
                    "operation sinks and validation gates using ASB metadata."
                ),
                tags=("windows", "pe", "selector", "cases", "pseudocode"),
            ),
            WindowsCompareSelectorCasesArgs,
            WindowsCompareSelectorCasesResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsCompareSelectorCasesArgs,
    ) -> WindowsCompareSelectorCasesResult:
        gates_path = _resolve_metadata_path(args.gates_path, "data/kg/pe-gates.yaml")
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        gates = [_gate_record(entry, gates_path) for entry in _load_yaml_list(gates_path)]
        operations = [
            _operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)
        ]
        text, source, notes = _scan_text(ctx, args)
        selector, case_blocks = _case_blocks(text, args.selector, max_cases=args.max_cases)
        if not case_blocks:
            notes.append("no switch/case blocks found")
        tool_args = WindowsCheckGateToSinkArgs(
            gates_path=str(gates_path),
            sinks_path=str(sinks_path),
            gate_kind=args.gate_kind,
            sink_kind=args.sink_kind,
        )
        cases = [
            _case_summary(block, gates, operations, tool_args) for block in case_blocks
        ]
        differences = _differences(cases)
        scanned_call_count = sum(len(case.gates) + len(case.sinks) for case in cases)
        notes.append(
            "selector comparison uses pseudocode case blocks; it is not CFG path proof"
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_compare_selector_cases",
                    props={
                        "selector": selector,
                        "case_count": len(cases),
                        "difference_count": len(differences),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsCompareSelectorCasesResult(
            selector_expression=selector,
            cases=cases,
            differences=differences,
            scanned_call_count=scanned_call_count,
            pseudocode_source=source,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


class _CaseBlock(BaseModel):
    label: str
    body: str
    line_start: int
    line_end: int


def _scan_text(
    ctx: MemoryContext,
    args: WindowsCompareSelectorCasesArgs,
) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if args.pseudocode:
        return args.pseudocode, "supplied_pseudocode", notes
    if args.function_va is None:
        notes.append("no pseudocode or function_va supplied")
        return "", "none", notes
    try:
        text = g.ir.decompile_at(
            str(ctx.file_path),
            int(args.function_va),
            timeout_ms=max(200, int(args.timeout_ms)),
            style="c",
            pdb_cache=args.pdb_cache,
        )
        return text, "glaurung_decompiler", notes
    except Exception as exc:
        notes.append(f"decompile failed: {exc}")
        return "", "glaurung_decompiler_failed", notes


def _case_blocks(
    text: str,
    selector_filter: str | None,
    *,
    max_cases: int,
) -> tuple[str | None, list[_CaseBlock]]:
    switch = _switch_body(text, selector_filter)
    if switch is None:
        return None, []
    selector, body, body_start_line = switch
    labels = list(
        re.finditer(
            r"(?m)^\s*(?P<label>case\s+[^:]+|default)\s*:",
            body,
        )
    )
    blocks: list[_CaseBlock] = []
    for idx, match in enumerate(labels[:max_cases]):
        label = match.group("label").strip()
        start = match.end()
        end = labels[idx + 1].start() if idx + 1 < len(labels) else len(body)
        block_body = body[start:end]
        line_start = body_start_line + body[: match.start()].count("\n")
        line_end = body_start_line + body[:end].count("\n")
        blocks.append(
            _CaseBlock(
                label=label,
                body=block_body,
                line_start=line_start,
                line_end=line_end,
            )
        )
    return selector, blocks


def _switch_body(
    text: str,
    selector_filter: str | None,
) -> tuple[str, str, int] | None:
    for match in re.finditer(r"\bswitch\s*\((?P<selector>[^)]*)\)", text):
        selector = match.group("selector").strip()
        if selector_filter and selector_filter not in selector:
            continue
        brace_start = text.find("{", match.end())
        if brace_start < 0:
            continue
        brace_end = _matching_brace(text, brace_start)
        if brace_end is None:
            continue
        body_start_line = text[: brace_start + 1].count("\n") + 1
        return selector, text[brace_start + 1 : brace_end], body_start_line
    return None


def _matching_brace(text: str, start: int) -> int | None:
    depth = 0
    for idx in range(start, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return idx
    return None


def _case_summary(
    block: _CaseBlock,
    gates,
    operations,
    tool_args: WindowsCheckGateToSinkArgs,
) -> SelectorCaseSummary:
    calls = _shift_calls(_extract_calls(block.body), block.line_start)
    gate_sites = _gate_sites(calls, gates, tool_args)
    sink_sites = _sink_sites(calls, operations, tool_args)
    return SelectorCaseSummary(
        label=block.label,
        line_start=block.line_start,
        line_end=block.line_end,
        gates=gate_sites,
        sinks=sink_sites,
        operation_ids=sorted({sink.operation.id for sink in sink_sites}),
        gate_ids=sorted({gate.gate.id for gate in gate_sites}),
    )


def _shift_calls(calls: list[CallSite], line_start: int) -> list[CallSite]:
    return [
        CallSite(
            symbol=call.symbol,
            line=line_start + call.line - 1,
            snippet=call.snippet,
        )
        for call in calls
    ]


def _differences(cases: list[SelectorCaseSummary]) -> list[SelectorCaseDifference]:
    out: list[SelectorCaseDifference] = []
    labels = [case.label for case in cases]
    out.extend(_missing_differences(cases, labels, "operation"))
    out.extend(_missing_differences(cases, labels, "gate"))
    for case in cases:
        if case.sinks and not case.gates:
            for sink in case.sinks:
                out.append(
                    SelectorCaseDifference(
                        kind="sink_without_gate",
                        item_id=sink.operation.id,
                        item_kind=sink.operation.sink_kind,
                        present_cases=[case.label],
                        missing_cases=[],
                        reason=(
                            f"{case.label} has sink {sink.operation.id} "
                            "with no matching gate call in the same case"
                        ),
                    )
                )
    return out


def _missing_differences(
    cases: list[SelectorCaseSummary],
    labels: list[str],
    kind: Literal["operation", "gate"],
) -> list[SelectorCaseDifference]:
    out: list[SelectorCaseDifference] = []
    all_ids = sorted(
        {
            item_id
            for case in cases
            for item_id in (case.operation_ids if kind == "operation" else case.gate_ids)
        }
    )
    for item_id in all_ids:
        present = [
            case.label
            for case in cases
            if item_id in (case.operation_ids if kind == "operation" else case.gate_ids)
        ]
        missing = [label for label in labels if label not in present]
        if present and missing:
            out.append(
                SelectorCaseDifference(
                    kind=(
                        "operation_missing_in_cases"
                        if kind == "operation"
                        else "gate_missing_in_cases"
                    ),
                    item_id=item_id,
                    item_kind=kind,
                    present_cases=present,
                    missing_cases=missing,
                    reason=f"{item_id} appears in {present} but not {missing}",
                )
            )
    return out


def build_tool() -> MemoryTool[
    WindowsCompareSelectorCasesArgs,
    WindowsCompareSelectorCasesResult,
]:
    return WindowsCompareSelectorCasesTool()
