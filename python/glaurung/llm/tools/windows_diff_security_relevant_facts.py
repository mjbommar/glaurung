from __future__ import annotations

import difflib
import re
from typing import Literal

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_check_gate_to_sink import (
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


FactKind = Literal["gate", "sink", "helper_call", "constant"]
DiffDirection = Literal["added", "removed"]


class SecurityFactDelta(BaseModel):
    direction: DiffDirection
    fact_kind: FactKind
    item_id: str
    detail: str


class SecurityFactSnapshot(BaseModel):
    label: str
    pseudocode_source: str
    gates: list[GateSite]
    sinks: list[SinkSite]
    helper_calls: list[str]
    constants: list[str]
    line_count: int


class WindowsDiffSecurityRelevantFactsArgs(BaseModel):
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    before_pseudocode: str | None = Field(
        None,
        description="Optional before/old pseudocode or source-like text.",
    )
    after_pseudocode: str | None = Field(
        None,
        description="Optional after/new pseudocode or source-like text.",
    )
    before_function_va: int | None = Field(
        None,
        description="Optional before function VA. Used only when before_pseudocode is omitted.",
    )
    after_function_va: int | None = Field(
        None,
        description="Optional after function VA. Used only when after_pseudocode is omitted.",
    )
    before_path: str | None = Field(
        None,
        description="Optional before binary path. Defaults to current file.",
    )
    after_path: str | None = Field(
        None,
        description="Optional after binary path. Defaults to current file.",
    )
    gate_kind: str | None = Field(None, description="Optional gate kind filter.")
    sink_kind: str | None = Field(None, description="Optional sink kind filter.")
    timeout_ms: int = Field(500, description="Decompile timeout when VA is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact security-fact-diff evidence node to the KB.",
    )


class WindowsDiffSecurityRelevantFactsResult(BaseModel):
    before: SecurityFactSnapshot
    after: SecurityFactSnapshot
    deltas: list[SecurityFactDelta]
    similarity: float = Field(ge=0.0, le=1.0)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsDiffSecurityRelevantFactsTool(
    MemoryTool[
        WindowsDiffSecurityRelevantFactsArgs,
        WindowsDiffSecurityRelevantFactsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_diff_security_relevant_facts",
                description=(
                    "Diff Windows security-relevant pseudocode facts: gates, "
                    "operation sinks, helper calls, and constants."
                ),
                tags=("windows", "pe", "diff", "facts", "pseudocode"),
            ),
            WindowsDiffSecurityRelevantFactsArgs,
            WindowsDiffSecurityRelevantFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsDiffSecurityRelevantFactsArgs,
    ) -> WindowsDiffSecurityRelevantFactsResult:
        gates_path = _resolve_metadata_path(args.gates_path, "data/kg/pe-gates.yaml")
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        gates = [_gate_record(entry, gates_path) for entry in _load_yaml_list(gates_path)]
        operations = [
            _operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)
        ]
        before_text, before_source, before_notes = _text_for(
            ctx,
            pseudocode=args.before_pseudocode,
            function_va=args.before_function_va,
            path=args.before_path,
            timeout_ms=args.timeout_ms,
            pdb_cache=args.pdb_cache,
            label="before",
        )
        after_text, after_source, after_notes = _text_for(
            ctx,
            pseudocode=args.after_pseudocode,
            function_va=args.after_function_va,
            path=args.after_path,
            timeout_ms=args.timeout_ms,
            pdb_cache=args.pdb_cache,
            label="after",
        )
        tool_args = WindowsCheckGateToSinkArgs(
            gates_path=str(gates_path),
            sinks_path=str(sinks_path),
            gate_kind=args.gate_kind,
            sink_kind=args.sink_kind,
        )
        before = _snapshot("before", before_text, before_source, gates, operations, tool_args)
        after = _snapshot("after", after_text, after_source, gates, operations, tool_args)
        deltas = _deltas(before, after)
        similarity = difflib.SequenceMatcher(
            None,
            before_text.splitlines(),
            after_text.splitlines(),
        ).ratio()

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_diff_security_relevant_facts",
                    props={
                        "delta_count": len(deltas),
                        "similarity": round(similarity, 4),
                        "before_source": before_source,
                        "after_source": after_source,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsDiffSecurityRelevantFactsResult(
            before=before,
            after=after,
            deltas=deltas,
            similarity=round(similarity, 4),
            evidence_node_id=evidence_node_id,
            notes=[
                *before_notes,
                *after_notes,
                "security fact diff uses pseudocode/decompiler evidence; it is not binary diff or CFG proof",
            ],
        )


def _text_for(
    ctx: MemoryContext,
    *,
    pseudocode: str | None,
    function_va: int | None,
    path: str | None,
    timeout_ms: int,
    pdb_cache: str,
    label: str,
) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    if pseudocode:
        return pseudocode, f"supplied_{label}_pseudocode", notes
    if function_va is None:
        notes.append(f"no {label}_pseudocode or {label}_function_va supplied")
        return "", "none", notes
    binary_path = path or str(ctx.file_path)
    try:
        text = g.ir.decompile_at(
            binary_path,
            int(function_va),
            timeout_ms=max(200, int(timeout_ms)),
            style="c",
            pdb_cache=pdb_cache,
        )
        return text, f"glaurung_{label}_decompiler", notes
    except Exception as exc:
        notes.append(f"{label} decompile failed: {exc}")
        return "", f"glaurung_{label}_decompiler_failed", notes


def _snapshot(
    label: str,
    text: str,
    source: str,
    gates,
    operations,
    tool_args: WindowsCheckGateToSinkArgs,
) -> SecurityFactSnapshot:
    calls = _extract_calls(text)
    gates_found = _gate_sites(calls, gates, tool_args)
    sinks_found = _sink_sites(calls, operations, tool_args)
    known_symbols = {
        call.symbol.lower()
        for gate in gates_found
        for call in [gate.call]
    } | {
        call.symbol.lower()
        for sink in sinks_found
        for call in [sink.call]
    }
    helper_calls = sorted(
        {
            call.symbol
            for call in calls
            if call.symbol.lower() not in known_symbols
        }
    )
    return SecurityFactSnapshot(
        label=label,
        pseudocode_source=source,
        gates=gates_found,
        sinks=sinks_found,
        helper_calls=helper_calls,
        constants=sorted(_constants(text)),
        line_count=len(text.splitlines()),
    )


def _constants(text: str) -> set[str]:
    constants = set(re.findall(r"\b0x[0-9A-Fa-f]+\b", text))
    constants.update(re.findall(r"\bSTATUS_[A-Z0-9_]+\b", text))
    constants.update(re.findall(r"\b[A-Z][A-Z0-9_]{3,}\b", text))
    constants.update(re.findall(r"(?<![A-Za-z_])\b\d{2,}\b(?![A-Za-z_])", text))
    return constants


def _deltas(
    before: SecurityFactSnapshot,
    after: SecurityFactSnapshot,
) -> list[SecurityFactDelta]:
    deltas: list[SecurityFactDelta] = []
    deltas.extend(
        _set_deltas(
            "gate",
            {gate.gate.id: gate.gate.gate_kind for gate in before.gates},
            {gate.gate.id: gate.gate.gate_kind for gate in after.gates},
        )
    )
    deltas.extend(
        _set_deltas(
            "sink",
            {sink.operation.id: sink.operation.sink_kind for sink in before.sinks},
            {sink.operation.id: sink.operation.sink_kind for sink in after.sinks},
        )
    )
    deltas.extend(
        _set_deltas(
            "helper_call",
            {call: call for call in before.helper_calls},
            {call: call for call in after.helper_calls},
        )
    )
    deltas.extend(
        _set_deltas(
            "constant",
            {constant: constant for constant in before.constants},
            {constant: constant for constant in after.constants},
        )
    )
    return sorted(deltas, key=lambda delta: (delta.fact_kind, delta.item_id, delta.direction))


def _set_deltas(
    fact_kind: FactKind,
    before: dict[str, str],
    after: dict[str, str],
) -> list[SecurityFactDelta]:
    out: list[SecurityFactDelta] = []
    for item_id in sorted(set(after) - set(before)):
        out.append(
            SecurityFactDelta(
                direction="added",
                fact_kind=fact_kind,
                item_id=item_id,
                detail=after[item_id],
            )
        )
    for item_id in sorted(set(before) - set(after)):
        out.append(
            SecurityFactDelta(
                direction="removed",
                fact_kind=fact_kind,
                item_id=item_id,
                detail=before[item_id],
            )
        )
    return out


def build_tool() -> MemoryTool[
    WindowsDiffSecurityRelevantFactsArgs,
    WindowsDiffSecurityRelevantFactsResult,
]:
    return WindowsDiffSecurityRelevantFactsTool()
