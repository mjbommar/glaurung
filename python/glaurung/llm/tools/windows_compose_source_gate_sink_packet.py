from __future__ import annotations

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_cfg_dominance import CfgBlockFact
from .windows_cfg_gate_to_sink import (
    WindowsCfgGateToSinkArgs,
    WindowsCfgGateToSinkTool,
)
from .windows_emit_review_packet import (
    WindowsComponentProfileContext,
    WindowsDiffContext,
    WindowsEmitReviewPacketArgs,
    WindowsEmitReviewPacketTool,
    WindowsGhidraDeltaContext,
    WindowsPdbIdentityContext,
    WindowsProjectFactContext,
    WindowsReviewEvidence,
    WindowsReviewPacket,
    WindowsReviewPathStep,
)
from .windows_source_sink_operand_match import (
    WindowsSourceSinkOperandMatchArgs,
    WindowsSourceSinkOperandMatchTool,
)


class WindowsComposeSourceGateSinkPacketArgs(BaseModel):
    binary: str = Field(..., description="Binary or driver name.")
    build: str | None = Field(None, description="Windows build or product version.")
    entrypoint: str = Field(..., description="Entrypoint or audited function name.")
    attacker_class: str = Field(..., description="Attacker class for the source.")
    source_role: str = Field(
        ...,
        description="Role of attacker-controlled value: buffer, length, handle, etc.",
    )
    source_arg_index: int | None = Field(
        None,
        description="Zero-based source argument index to derive from the function signature.",
    )
    source_name: str | None = Field(None, description="Explicit source variable name.")
    sink_symbol: str = Field(..., description="Sink call symbol to inspect.")
    sink_arg_index: int = Field(..., description="Zero-based sink argument index.")
    gate_symbol: str = Field(..., description="Gate call or branch symbol.")
    gate_va: int = Field(..., description="VA of the validation gate call or branch.")
    sink_va: int = Field(..., description="VA of the sink call or memory operation.")
    function_va: int | None = Field(
        None,
        description="Function entry VA. Required when cfg_blocks is omitted.",
    )
    pseudocode: str | None = Field(
        None,
        description="Optional pseudocode or source-like text for operand matching.",
    )
    cfg_blocks: list[CfgBlockFact] = Field(
        default_factory=list,
        description="Optional explicit CFG blocks; if omitted, native CFG analysis is used.",
    )
    gates_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-gates.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    sinks_path: str | None = Field(
        None,
        description="Path to ASB data/kg/pe-sinks.yaml. Defaults to ASB_REPO or sibling repo.",
    )
    timeout_ms: int = Field(1000, description="Native analysis/decompile timeout.")
    pdb_cache: str = Field(
        "",
        description="Optional Microsoft-style PDB cache directory for decompile name recovery.",
    )
    pdb_identity: WindowsPdbIdentityContext | None = None
    component_profile: WindowsComponentProfileContext | None = None
    diff_context: WindowsDiffContext | None = None
    project_facts: WindowsProjectFactContext | None = None
    required_project_facts: list[str] = Field(
        default_factory=list,
        description="Project fact classes required before packet promotion.",
    )
    ghidra_delta: WindowsGhidraDeltaContext | None = None
    auto_join_manifest_context: bool = Field(
        False,
        description="If true, fill missing project/Ghidra context from ASB manifests.",
    )
    project_facts_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-project-facts.yaml for auto-join.",
    )
    ghidra_delta_path: str | None = Field(
        None,
        description="Optional path to ASB data/kg/pe-ghidra-delta.yaml for auto-join.",
    )
    manifest_target_id: str | None = Field(
        None,
        description="Optional ASB target id used for manifest auto-join.",
    )
    manifest_build_label: str | None = Field(
        None,
        description="Optional ASB build label used for manifest auto-join.",
    )
    manifest_component: str | None = Field(
        None,
        description="Optional Windows component filename used for Ghidra-delta auto-join.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact composition evidence node to the KB.",
    )


class WindowsComposeSourceGateSinkPacketResult(BaseModel):
    packet: WindowsReviewPacket
    operand_status: str
    gate_status: str
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsComposeSourceGateSinkPacketTool(
    MemoryTool[
        WindowsComposeSourceGateSinkPacketArgs,
        WindowsComposeSourceGateSinkPacketResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_compose_source_gate_sink_packet",
                description=(
                    "Compose source/sink operand matching and CFG gate dominance "
                    "into a Windows candidate review packet."
                ),
                tags=("windows", "pe", "candidate", "review", "cfg", "flow"),
            ),
            WindowsComposeSourceGateSinkPacketArgs,
            WindowsComposeSourceGateSinkPacketResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsComposeSourceGateSinkPacketArgs,
    ) -> WindowsComposeSourceGateSinkPacketResult:
        operand = WindowsSourceSinkOperandMatchTool().run(
            ctx,
            kb,
            WindowsSourceSinkOperandMatchArgs(
                source_arg_index=args.source_arg_index,
                source_name=args.source_name,
                sink_symbol=args.sink_symbol,
                sink_arg_index=args.sink_arg_index,
                pseudocode=args.pseudocode,
                function_va=args.function_va,
                sinks_path=args.sinks_path,
                timeout_ms=args.timeout_ms,
                pdb_cache=args.pdb_cache,
            ),
        )
        gate = WindowsCfgGateToSinkTool().run(
            ctx,
            kb,
            WindowsCfgGateToSinkArgs(
                gates_path=args.gates_path,
                sinks_path=args.sinks_path,
                function_va=args.function_va,
                gate_va=args.gate_va,
                sink_va=args.sink_va,
                gate_symbol=args.gate_symbol,
                sink_symbol=args.sink_symbol,
                cfg_blocks=args.cfg_blocks,
                timeout_ms=args.timeout_ms,
            ),
        )

        packet = _emit_packet(ctx, kb, args, operand, gate)
        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_compose_source_gate_sink_packet",
                    props={
                        "entrypoint": args.entrypoint,
                        "source_name": operand.source_name,
                        "sink_symbol": args.sink_symbol,
                        "operand_status": operand.status,
                        "gate_status": gate.status,
                        "packet_id": packet.candidate_id,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsComposeSourceGateSinkPacketResult(
            packet=packet,
            operand_status=operand.status,
            gate_status=gate.status,
            evidence_node_id=evidence_node_id,
            notes=[
                "candidate composes operand evidence and CFG gate evidence; it is not a finding verdict"
            ],
        )


def _emit_packet(ctx, kb, args, operand, gate) -> WindowsReviewPacket:
    sink_kind = (
        gate.sink.operation.sink_kind
        if gate.sink.operation is not None
        else "unknown"
    )
    required_gates = (
        list(gate.sink.operation.required_gates)
        if gate.sink.operation is not None
        else []
    )
    proven_gates = _matched_required_gates(gate, required_gates)
    missing_required_gates = _missing_required_gates(gate, required_gates)
    path = [
        WindowsReviewPathStep(
            function=args.entrypoint,
            symbol=args.gate_symbol,
            role="gate",
            evidence=f"gate callsite VA 0x{args.gate_va:x}",
        ),
        WindowsReviewPathStep(
            function=args.entrypoint,
            symbol=args.sink_symbol,
            arg_index=args.sink_arg_index,
            role=operand.sink.arg_role if operand.sink else args.source_role,
            evidence=operand.sink.snippet if operand.sink else gate.reason,
        ),
    ]
    evidence = [
        WindowsReviewEvidence(
            source="windows_source_sink_operand_match",
            summary=operand.reason,
            provenance=operand.provenance,
        ),
        WindowsReviewEvidence(
            source="windows_cfg_gate_to_sink",
            summary=gate.reason,
            provenance=[
                "asb_pe_gate_metadata",
                "asb_pe_sink_metadata",
                *gate.dominance_provenance,
            ],
        ),
    ]
    result = WindowsEmitReviewPacketTool().run(
        ctx,
        kb,
        WindowsEmitReviewPacketArgs(
            binary=args.binary,
            build=args.build,
            entrypoint=args.entrypoint,
            attacker_class=args.attacker_class,
            source_role=args.source_role,
            source_arg=operand.source_name or args.source_name,
            sink_symbol=args.sink_symbol,
            sink_kind=sink_kind,
            required_gates=required_gates,
            proven_gates=proven_gates,
            missing_required_gates=missing_required_gates,
            gate_status=gate.suggested_packet_gate_status,
            path=path,
            evidence=evidence,
            provenance=[
                "source_sink_operand_match",
                "cfg_gate_to_sink",
            ],
            pdb_identity=args.pdb_identity,
            component_profile=args.component_profile,
            diff_context=args.diff_context,
            project_facts=args.project_facts,
            required_project_facts=args.required_project_facts,
            ghidra_delta=args.ghidra_delta,
            auto_join_manifest_context=args.auto_join_manifest_context,
            project_facts_path=args.project_facts_path,
            ghidra_delta_path=args.ghidra_delta_path,
            manifest_target_id=args.manifest_target_id,
            manifest_build_label=args.manifest_build_label,
            manifest_component=args.manifest_component,
            notes=[
                f"operand_status={operand.status}",
                f"cfg_gate_status={gate.status}",
                "source/sink operand evidence is pseudocode-derived unless provenance says otherwise",
            ],
        ),
    )
    return result.packet


def _matched_required_gates(gate, required_gates: list[str]) -> list[str]:
    if gate.gate.gate is None:
        return []
    proven = set(gate.gate.gate.proves)
    return [required for required in required_gates if required in proven]


def _missing_required_gates(gate, required_gates: list[str]) -> list[str]:
    if gate.gate.gate is None:
        return list(required_gates)
    proven = set(gate.gate.gate.proves)
    return [required for required in required_gates if required not in proven]


def build_tool() -> WindowsComposeSourceGateSinkPacketTool:
    return WindowsComposeSourceGateSinkPacketTool()
