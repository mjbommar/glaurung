from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_operation_metadata import OperationArgRole, OperationRecord
from .windows_surface_metadata import GateRecord, _resolve_metadata_path


GateSinkStatus = Literal[
    "missing",
    "gate_before_sink",
    "gate_after_sink",
    "gate_same_line",
]


class WindowsCheckGateToSinkArgs(BaseModel):
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
    gate_symbol: str | None = Field(None, description="Optional gate symbol filter.")
    gate_kind: str | None = Field(None, description="Optional gate kind filter.")
    sink_symbol: str | None = Field(None, description="Optional sink symbol filter.")
    sink_kind: str | None = Field(None, description="Optional sink kind filter.")
    timeout_ms: int = Field(500, description="Decompile timeout when function_va is used.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact gate-to-sink evidence node to the KB.",
    )


class CallSite(BaseModel):
    symbol: str
    line: int
    snippet: str


class GateSite(BaseModel):
    call: CallSite
    gate: GateRecord


class SinkSite(BaseModel):
    call: CallSite
    operation: OperationRecord


class GateSinkAssessment(BaseModel):
    sink: SinkSite
    status: GateSinkStatus
    gate: GateSite | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    provenance: list[str] = Field(default_factory=list)


class WindowsCheckGateToSinkResult(BaseModel):
    gates_path: str
    sinks_path: str
    assessments: list[GateSinkAssessment]
    gate_call_count: int
    sink_call_count: int
    pseudocode_source: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsCheckGateToSinkTool(
    MemoryTool[WindowsCheckGateToSinkArgs, WindowsCheckGateToSinkResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_check_gate_to_sink",
                description=(
                    "Check simple pseudocode ordering between Windows validation "
                    "gates and operation sinks using ASB gate/sink metadata."
                ),
                tags=("windows", "pe", "gates", "sinks", "pseudocode"),
            ),
            WindowsCheckGateToSinkArgs,
            WindowsCheckGateToSinkResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsCheckGateToSinkArgs,
    ) -> WindowsCheckGateToSinkResult:
        gates_path = _resolve_metadata_path(args.gates_path, "data/kg/pe-gates.yaml")
        sinks_path = _resolve_metadata_path(args.sinks_path, "data/kg/pe-sinks.yaml")
        gates = [_gate_record(entry, gates_path) for entry in _load_yaml_list(gates_path)]
        operations = [
            _operation_record(entry, sinks_path) for entry in _load_yaml_list(sinks_path)
        ]
        text, source, notes = _scan_text(ctx, args)
        calls = _extract_calls(text)
        gate_sites = _gate_sites(calls, gates, args)
        sink_sites = _sink_sites(calls, operations, args)
        assessments = [_assess_sink(sink, gate_sites, source) for sink in sink_sites]
        notes.append(
            "line-order evidence only; result is not CFG dominance or path coverage"
        )

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_check_gate_to_sink",
                    props={
                        "gate_call_count": len(gate_sites),
                        "sink_call_count": len(sink_sites),
                        "assessment_count": len(assessments),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsCheckGateToSinkResult(
            gates_path=str(gates_path),
            sinks_path=str(sinks_path),
            assessments=assessments,
            gate_call_count=len(gate_sites),
            sink_call_count=len(sink_sites),
            pseudocode_source=source,
            evidence_node_id=evidence_node_id,
            notes=notes,
        )


def _scan_text(
    ctx: MemoryContext,
    args: WindowsCheckGateToSinkArgs,
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


def _extract_calls(text: str) -> list[CallSite]:
    calls: list[CallSite] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in re.finditer(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_!:.$@]*)\s*\(",
            line,
        ):
            name = match.group("name")
            if name.lower() in {"if", "for", "while", "switch", "return", "sizeof"}:
                continue
            calls.append(CallSite(symbol=name, line=line_no, snippet=line.strip()))
    return calls


def _gate_sites(
    calls: list[CallSite],
    gates: list[GateRecord],
    args: WindowsCheckGateToSinkArgs,
) -> list[GateSite]:
    out: list[GateSite] = []
    by_symbol = _gates_by_symbol(gates)
    for call in calls:
        for gate in _matches_by_symbol(call.symbol, by_symbol):
            if args.gate_symbol and args.gate_symbol not in gate.symbols:
                continue
            if args.gate_kind and gate.gate_kind != args.gate_kind:
                continue
            out.append(GateSite(call=call, gate=gate))
    return out


def _sink_sites(
    calls: list[CallSite],
    operations: list[OperationRecord],
    args: WindowsCheckGateToSinkArgs,
) -> list[SinkSite]:
    out: list[SinkSite] = []
    by_symbol = _operations_by_symbol(operations)
    for call in calls:
        for operation in _matches_by_symbol(call.symbol, by_symbol):
            if args.sink_symbol and args.sink_symbol not in operation.symbols:
                continue
            if args.sink_kind and operation.sink_kind != args.sink_kind:
                continue
            out.append(SinkSite(call=call, operation=operation))
    return out


def _assess_sink(
    sink: SinkSite,
    gate_sites: list[GateSite],
    provenance_source: str,
) -> GateSinkAssessment:
    before = [gate for gate in gate_sites if gate.call.line < sink.call.line]
    same_line = [gate for gate in gate_sites if gate.call.line == sink.call.line]
    after = [gate for gate in gate_sites if gate.call.line > sink.call.line]
    if before:
        gate = before[-1]
        return GateSinkAssessment(
            sink=sink,
            status="gate_before_sink",
            gate=gate,
            confidence=0.5,
            reason=(
                f"gate {gate.call.symbol} appears before sink {sink.call.symbol}; "
                "ordering is not dominance"
            ),
            provenance=["asb_pe_gate_metadata", "asb_pe_sink_metadata", provenance_source],
        )
    if same_line:
        gate = same_line[0]
        return GateSinkAssessment(
            sink=sink,
            status="gate_same_line",
            gate=gate,
            confidence=0.35,
            reason=(
                f"gate {gate.call.symbol} and sink {sink.call.symbol} appear on the same line"
            ),
            provenance=["asb_pe_gate_metadata", "asb_pe_sink_metadata", provenance_source],
        )
    if after:
        gate = after[0]
        return GateSinkAssessment(
            sink=sink,
            status="gate_after_sink",
            gate=gate,
            confidence=0.45,
            reason=f"nearest gate {gate.call.symbol} appears after sink {sink.call.symbol}",
            provenance=["asb_pe_gate_metadata", "asb_pe_sink_metadata", provenance_source],
        )
    return GateSinkAssessment(
        sink=sink,
        status="missing",
        gate=None,
        confidence=0.55,
        reason=f"no matching gate call found around sink {sink.call.symbol}",
        provenance=["asb_pe_gate_metadata", "asb_pe_sink_metadata", provenance_source],
    )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: entry {idx} is not a mapping")
        out.append(entry)
    return out


def _gate_record(entry: dict[str, Any], path: Path) -> GateRecord:
    return GateRecord(
        id=_required_str(entry, "id", path),
        symbols=_required_str_list(entry, "symbols", path),
        gate_kind=_required_str(entry, "gate_kind", path),
        proves=[str(x) for x in entry.get("proves") or []],
        required_conditions=[str(x) for x in entry.get("required_conditions") or []],
        invalid_when=[str(x) for x in entry.get("invalid_when") or []],
        notes=entry.get("notes"),
    )


def _operation_record(entry: dict[str, Any], path: Path) -> OperationRecord:
    return OperationRecord(
        id=_required_str(entry, "id", path),
        symbols=_required_str_list(entry, "symbols", path),
        sink_kind=_required_str(entry, "sink_kind", path),
        effects=[str(x) for x in entry.get("effects") or []],
        arg_roles=_arg_roles(entry.get("arg_roles"), path, entry.get("id")),
        required_gates=[str(x) for x in entry.get("required_gates") or []],
        notes=entry.get("notes"),
    )


def _arg_roles(raw: Any, path: Path, owner: Any) -> list[OperationArgRole]:
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path}: operation {owner!r} missing non-empty arg_roles")
    roles = []
    for key, value in raw.items():
        roles.append(OperationArgRole(index=int(key), role=str(value)))
    return sorted(roles, key=lambda role: role.index)


def _gates_by_symbol(gates: list[GateRecord]) -> dict[str, list[GateRecord]]:
    out: dict[str, list[GateRecord]] = {}
    for gate in gates:
        for symbol in gate.symbols:
            for key in _symbol_keys(symbol):
                out.setdefault(key, []).append(gate)
    return out


def _operations_by_symbol(
    operations: list[OperationRecord],
) -> dict[str, list[OperationRecord]]:
    out: dict[str, list[OperationRecord]] = {}
    for operation in operations:
        for symbol in operation.symbols:
            for key in _symbol_keys(symbol):
                out.setdefault(key, []).append(operation)
    return out


def _matches_by_symbol(name: str, by_symbol: dict[str, list[Any]]) -> list[Any]:
    matches: list[Any] = []
    seen: set[str] = set()
    for key in _symbol_keys(name):
        for item in by_symbol.get(key, []):
            item_id = getattr(item, "id", repr(item))
            if item_id in seen:
                continue
            seen.add(item_id)
            matches.append(item)
    return matches


def _symbol_keys(symbol: str) -> list[str]:
    raw = symbol.strip()
    if not raw:
        return []
    suffix = raw.rsplit("!", 1)[-1].rsplit("::", 1)[-1]
    return [raw.lower(), suffix.lower()]


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty list field {key!r}")
    return [str(v) for v in values if str(v)]


def build_tool() -> MemoryTool[
    WindowsCheckGateToSinkArgs, WindowsCheckGateToSinkResult
]:
    return WindowsCheckGateToSinkTool()
