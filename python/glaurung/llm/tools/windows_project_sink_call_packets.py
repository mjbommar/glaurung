from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_cfg_dominance import WindowsCfgDominanceResult, WindowsCfgDominanceTool, WindowsCfgDominanceArgs
from .windows_check_gate_to_sink import (
    _gate_record,
    _gates_by_symbol,
    _load_yaml_list,
    _matches_by_symbol,
)
from .windows_emit_review_packet import (
    GateStatus,
    WindowsEmitReviewPacketArgs,
    WindowsEmitReviewPacketTool,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from .windows_project_callsite_facts import (
    ProjectCallsiteFact,
    WindowsProjectCallsiteFactsArgs,
    WindowsProjectCallsiteFactsTool,
)
from .windows_project_call_argument_snapshot import (
    ProjectCallArgumentFact,
    WindowsProjectCallArgumentSnapshotArgs,
    WindowsProjectCallArgumentSnapshotTool,
)
from .windows_surface_metadata import GateRecord, _resolve_metadata_path


class WindowsProjectSinkCallPacketsArgs(BaseModel):
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    binary_path: str | None = Field(
        None,
        description=(
            "Optional PE binary path. When supplied, local call-argument snapshots "
            "are attached to emitted packets."
        ),
    )
    binary: str = Field(..., description="Binary or driver filename.")
    build: str | None = Field(None, description="Windows build or corpus label.")
    attacker_class: str = Field(
        "unknown",
        description="Attacker class to attach to emitted packets.",
    )
    source_role: str = Field(
        "unknown",
        description="Source role to attach before source-specific rules refine the packet.",
    )
    source_arg: str | None = Field(
        None,
        description="Optional source argument/expression if already known.",
    )
    binary_id: int | None = Field(None, description="Optional project binary_id filter.")
    function_va: int | None = Field(
        None,
        description="Optional caller function VA used to filter callsites.",
    )
    call_symbol: str | None = Field(
        None,
        description="Optional sink/callee symbol filter, e.g. RtlCopyMemory.",
    )
    sink_kind: str | None = Field(
        None,
        description="Optional ASB sink kind filter, e.g. copy, free, completion.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    refine_gates: bool = Field(
        False,
        description=(
            "If true, look for required-gate callsites in the same project "
            "function and attach persisted-CFG dominance evidence."
        ),
    )
    project_facts_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-project-facts.yaml for packet auto-join.",
    )
    ghidra_delta_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-ghidra-delta.yaml for packet auto-join.",
    )
    manifest_target_id: str | None = Field(
        None,
        description="Optional ASB target id used for packet manifest auto-join.",
    )
    manifest_build_label: str | None = Field(
        None,
        description="Optional ASB build label used for packet manifest auto-join.",
    )
    manifest_component: str | None = Field(
        None,
        description="Optional component filename used for Ghidra-delta auto-join.",
    )
    required_project_facts: list[str] = Field(
        default_factory=lambda: ["function_names", "call_xrefs"],
        description="Project fact classes required before packet promotion.",
    )
    max_packets: int = Field(16, ge=0, le=256, description="Maximum packets to emit.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact project-sink packet evidence node to the KB.",
    )


class WindowsProjectSinkCallPacketsResult(BaseModel):
    project_path: str
    packet_count: int
    scanned_callsite_count: int
    argument_snapshot_count: int
    gate_refinement_count: int
    packets: list[WindowsReviewPacket]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectSinkCallPacketsTool(
    MemoryTool[WindowsProjectSinkCallPacketsArgs, WindowsProjectSinkCallPacketsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_sink_call_packets",
                description=(
                    "Scan persisted .glaurung call xrefs for ASB sink operations "
                    "and emit manifest-backed Windows review packets."
                ),
                tags=("windows", "pe", "project", "callsites", "candidate", "packet"),
            ),
            WindowsProjectSinkCallPacketsArgs,
            WindowsProjectSinkCallPacketsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectSinkCallPacketsArgs,
    ) -> WindowsProjectSinkCallPacketsResult:
        callsites = WindowsProjectCallsiteFactsTool().run(
            ctx,
            kb,
            WindowsProjectCallsiteFactsArgs(
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                function_va=args.function_va,
                call_symbol=args.call_symbol,
                operation_only=True,
                max_calls=args.max_packets,
                add_to_kb=False,
            ),
        )

        packets: list[WindowsReviewPacket] = []
        argument_snapshot_count = 0
        gate_refinement_count = 0
        for callsite in callsites.callsites:
            if callsite.operation is None:
                continue
            if args.sink_kind and callsite.operation.sink_kind != args.sink_kind:
                continue
            snapshot_args = _snapshot_arguments(ctx, kb, args, callsite)
            if snapshot_args:
                argument_snapshot_count += 1
            gate_refinement = _refine_gate(ctx, kb, args, callsite)
            if gate_refinement is not None:
                gate_refinement_count += 1
            packets.append(
                _emit_packet(ctx, kb, args, callsite, snapshot_args, gate_refinement)
            )
            if len(packets) >= args.max_packets:
                break

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_sink_call_packets",
                    props={
                        "project_path": args.project_path,
                        "binary": args.binary,
                        "call_symbol": args.call_symbol,
                        "sink_kind": args.sink_kind,
                        "packet_count": len(packets),
                        "scanned_callsite_count": callsites.scanned_call_count,
                        "argument_snapshot_count": argument_snapshot_count,
                        "gate_refinement_count": gate_refinement_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectSinkCallPacketsResult(
            project_path=args.project_path,
            packet_count=len(packets),
            scanned_callsite_count=callsites.scanned_call_count,
            argument_snapshot_count=argument_snapshot_count,
            gate_refinement_count=gate_refinement_count,
            packets=packets,
            evidence_node_id=evidence_node_id,
            notes=[
                "packets are project-scan seeds from sink callsites; source and gate proof still need dedicated rules"
            ],
        )


def _emit_packet(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    callsite: ProjectCallsiteFact,
    snapshot_args: list[ProjectCallArgumentFact],
    gate_refinement: "_GateRefinement | None",
) -> WindowsReviewPacket:
    assert callsite.operation is not None
    sink_symbol = (
        callsite.callee_name
        or callsite.callee_demangled
        or args.call_symbol
        or callsite.operation.symbols[0]
    )
    entrypoint = callsite.caller_name or callsite.caller_demangled or _va_label(
        callsite.caller_va,
        "function",
    )
    role = _first_arg_role(callsite)
    gate_status: GateStatus = "unknown"
    evidence = [
        WindowsReviewEvidence(
            source="windows_project_callsite_facts",
            summary=(
                f"{entrypoint} calls {sink_symbol} at "
                f"0x{callsite.callsite_va:x}; sink_kind="
                f"{callsite.operation.sink_kind}"
            ),
            provenance=[
                *callsite.provenance,
                "windows_project_callsite_facts",
            ],
        )
    ]
    path = []
    if gate_refinement is not None:
        gate_status = gate_refinement.packet_gate_status
        path.append(
            WindowsReviewPathStep(
                function=entrypoint,
                symbol=gate_refinement.gate_symbol,
                role="gate",
                evidence=(
                    f"project gate call xref at VA "
                    f"0x{gate_refinement.gate_va:x}"
                ),
            )
        )
        evidence.append(
            WindowsReviewEvidence(
                source="windows_cfg_dominance",
                summary=gate_refinement.summary,
                provenance=[
                    "windows_project_sink_call_packets",
                    "asb_pe_gate_metadata",
                    "persisted_project_cfg",
                    *gate_refinement.provenance,
                ],
            )
        )
    if snapshot_args:
        evidence.append(
            WindowsReviewEvidence(
                source="windows_project_call_argument_snapshot",
                summary=_argument_summary(snapshot_args),
                provenance=[
                    "windows_project_call_argument_snapshot",
                    "nearby_disassembly",
                ],
            )
        )
    result = WindowsEmitReviewPacketTool().run(
        ctx,
        kb,
        WindowsEmitReviewPacketArgs(
            candidate_id=_candidate_id(args.binary, callsite.callsite_va, sink_symbol),
            binary=args.binary,
            build=args.build,
            entrypoint=entrypoint,
            attacker_class=args.attacker_class,
            source_role=args.source_role,
            source_arg=args.source_arg,
            sink_symbol=sink_symbol,
            sink_kind=callsite.operation.sink_kind,
            required_gates=callsite.operation.required_gates,
            gate_status=gate_status,
            path=[
                *path,
                WindowsReviewPathStep(
                    function=entrypoint,
                    symbol=sink_symbol,
                    arg_index=role[0],
                    role=role[1],
                    evidence=f"project call xref at VA 0x{callsite.callsite_va:x}",
                ),
            ],
            evidence=evidence,
            provenance=["project_sink_call_scan"],
            required_project_facts=args.required_project_facts,
            auto_join_manifest_context=True,
            project_facts_path=args.project_facts_path,
            ghidra_delta_path=args.ghidra_delta_path,
            manifest_target_id=args.manifest_target_id,
            manifest_build_label=args.manifest_build_label,
            manifest_component=args.manifest_component or args.binary,
            notes=[
                "emitted from project sink-call scan",
                "source role and gate status are placeholders until source/gate rules refine this packet",
            ],
        ),
    )
    return result.packet


def _first_arg_role(callsite: ProjectCallsiteFact) -> tuple[int | None, str | None]:
    if callsite.operation is None or not callsite.operation.arg_roles:
        return None, None
    role = callsite.operation.arg_roles[0]
    return role.index, role.role


@dataclass(frozen=True)
class _GateRefinement:
    gate_symbol: str
    gate_va: int
    packet_gate_status: GateStatus
    summary: str
    provenance: list[str]


def _refine_gate(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    sink_callsite: ProjectCallsiteFact,
) -> _GateRefinement | None:
    if not args.refine_gates or sink_callsite.operation is None:
        return None
    if not sink_callsite.operation.required_gates or sink_callsite.caller_va is None:
        return None
    try:
        gates_path = _resolve_metadata_path(args.gates_path, "data/kg/pe-gates.yaml")
        gates = [_gate_record(entry, gates_path) for entry in _load_yaml_list(gates_path)]
        function_calls = WindowsProjectCallsiteFactsTool().run(
            ctx,
            kb,
            WindowsProjectCallsiteFactsArgs(
                project_path=args.project_path,
                sinks_path=args.sinks_path,
                binary_id=args.binary_id,
                function_va=sink_callsite.caller_va,
                operation_only=False,
                max_calls=512,
                add_to_kb=False,
            ),
        ).callsites
    except Exception:
        return None

    gates_by_symbol = _gates_by_symbol(gates)
    for candidate in function_calls:
        if candidate.callsite_va == sink_callsite.callsite_va:
            continue
        name = candidate.callee_name or candidate.callee_demangled
        if not name:
            continue
        for gate in _matches_by_symbol(name, gates_by_symbol):
            if not _gate_compatible(gate, sink_callsite.operation.required_gates):
                continue
            dominance = _dominance(ctx, kb, args, sink_callsite, candidate)
            if dominance is None:
                continue
            return _GateRefinement(
                gate_symbol=name,
                gate_va=candidate.callsite_va,
                packet_gate_status=_packet_gate_status(dominance.status),
                summary=(
                    f"{name}@0x{candidate.callsite_va:x} vs "
                    f"sink@0x{sink_callsite.callsite_va:x}: {dominance.reason}"
                ),
                provenance=dominance.provenance,
            )
    return None


def _gate_compatible(gate: GateRecord, required_gates: list[str]) -> bool:
    required = set(required_gates)
    if not required:
        return False
    return bool(required & set(gate.proves))


def _dominance(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    sink_callsite: ProjectCallsiteFact,
    gate_callsite: ProjectCallsiteFact,
) -> WindowsCfgDominanceResult | None:
    try:
        return WindowsCfgDominanceTool().run(
            ctx,
            kb,
            WindowsCfgDominanceArgs(
                project_path=args.project_path,
                function_va=sink_callsite.caller_va,
                gate_va=gate_callsite.callsite_va,
                sink_va=sink_callsite.callsite_va,
                add_to_kb=False,
            ),
        )
    except Exception:
        return None


def _packet_gate_status(status: str) -> GateStatus:
    if status == "dominated":
        return "dominated"
    if status == "not_dominated":
        return "not_dominated"
    if status == "same_block":
        return "gate_same_line"
    return "unknown"


def _snapshot_arguments(
    ctx: MemoryContext,
    kb: KnowledgeBase,
    args: WindowsProjectSinkCallPacketsArgs,
    callsite: ProjectCallsiteFact,
) -> list[ProjectCallArgumentFact]:
    if not args.binary_path:
        return []
    try:
        result = WindowsProjectCallArgumentSnapshotTool().run(
            ctx,
            kb,
            WindowsProjectCallArgumentSnapshotArgs(
                binary_path=args.binary_path,
                project_path=args.project_path,
                callsite_va=callsite.callsite_va,
                binary_id=args.binary_id,
                add_to_kb=False,
            ),
        )
    except Exception:
        return []
    return result.arguments


def _argument_summary(arguments: list[ProjectCallArgumentFact]) -> str:
    rendered = []
    for argument in arguments[:6]:
        expr = argument.expression or "unknown"
        rendered.append(f"arg{argument.index}={expr}")
    suffix = "" if len(arguments) <= 6 else f"; +{len(arguments) - 6} more"
    return "local call argument snapshot: " + ", ".join(rendered) + suffix


def _candidate_id(binary: str, callsite_va: int, sink_symbol: str) -> str:
    safe_binary = binary.lower().replace("\\", "-").replace("/", "-")
    safe_symbol = sink_symbol.lower().replace("!", "-").replace("::", "-")
    return f"{safe_binary}-sink-0x{callsite_va:x}-{safe_symbol}"


def _va_label(value: int | None, fallback: str) -> str:
    if value is None:
        return fallback
    return f"{fallback}_0x{value:x}"


def build_tool() -> MemoryTool[
    WindowsProjectSinkCallPacketsArgs, WindowsProjectSinkCallPacketsResult
]:
    return WindowsProjectSinkCallPacketsTool()
