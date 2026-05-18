from __future__ import annotations

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_emit_review_packet import (
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
        for callsite in callsites.callsites:
            if callsite.operation is None:
                continue
            if args.sink_kind and callsite.operation.sink_kind != args.sink_kind:
                continue
            snapshot_args = _snapshot_arguments(ctx, kb, args, callsite)
            if snapshot_args:
                argument_snapshot_count += 1
            packets.append(_emit_packet(ctx, kb, args, callsite, snapshot_args))
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
            gate_status="unknown",
            path=[
                WindowsReviewPathStep(
                    function=entrypoint,
                    symbol=sink_symbol,
                    arg_index=role[0],
                    role=role[1],
                    evidence=f"project call xref at VA 0x{callsite.callsite_va:x}",
                )
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
