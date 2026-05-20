from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb import xref_db
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)


class WindowsDecompileContextPacketArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary.")
    function_va: int = Field(..., description="Function entry VA to packetize.")
    project_path: str | None = Field(
        None,
        description="Optional .glaurung project path for names, comments, and labels.",
    )
    max_instructions: int = Field(
        80,
        ge=1,
        le=512,
        description="Maximum disassembly instructions to include.",
    )
    window_bytes: int = Field(
        4096,
        ge=16,
        le=65536,
        description="Maximum bytes to disassemble from the function entry.",
    )
    max_decompile_chars: int = Field(
        12000,
        ge=0,
        le=100000,
        description="Maximum decompiler characters to include; 0 disables decompile.",
    )
    timeout_ms: int = Field(
        3000,
        ge=1,
        description="Decompiler/disassembler timeout budget in milliseconds.",
    )
    pdb_cache: str = Field("", description="Optional Microsoft PDB cache path.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact decompile-context evidence node.",
    )


class WindowsContextInstruction(BaseModel):
    va: int
    address: str
    text: str
    bytes_hex: str = ""


class WindowsContextCall(BaseModel):
    va: int
    address: str
    target_va: int | None = None
    target: str | None = None
    text: str


class WindowsContextProjectFacts(BaseModel):
    project_path: str
    function_name: str | None = None
    entry_comment: str | None = None
    inline_comments: dict[str, str] = Field(default_factory=dict)
    data_labels: dict[str, str] = Field(default_factory=dict)
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)


class WindowsContextCfgSummary(BaseModel):
    function_name: str | None = None
    basic_block_count: int = 0
    instruction_count: int = 0
    edge_count: int = 0
    recovered_from_analysis: bool = False


class WindowsDecompileContextPacket(BaseModel):
    binary_path: str
    function_va: int
    address: str
    cfg: WindowsContextCfgSummary
    decompile_text: str | None = None
    decompile_truncated: bool = False
    instructions: list[WindowsContextInstruction] = Field(default_factory=list)
    calls: list[WindowsContextCall] = Field(default_factory=list)
    project_facts: WindowsContextProjectFacts | None = None
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WindowsDecompileContextPacketResult(BaseModel):
    packet: WindowsDecompileContextPacket
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None


class WindowsDecompileContextPacketTool(
    MemoryTool[WindowsDecompileContextPacketArgs, WindowsDecompileContextPacketResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_decompile_context_packet",
                description=(
                    "Build a bounded Windows function context packet with "
                    "decompiler text, disassembly, CFG shape, calls, and "
                    "optional .glaurung names/comments/data labels."
                ),
                tags=("windows", "pe", "decompile", "context", "agentic"),
            ),
            WindowsDecompileContextPacketArgs,
            WindowsDecompileContextPacketResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsDecompileContextPacketArgs,
    ) -> WindowsDecompileContextPacketResult:
        binary_path = Path(args.binary_path).expanduser()
        if not binary_path.exists():
            raise ValueError(f"{binary_path}: binary_path does not exist")

        cfg = _cfg_summary(binary_path, args.function_va)
        instructions = _instructions(binary_path, args)
        calls = _calls(instructions)
        decompile_text, truncated, decompile_missing = _decompile(binary_path, args)
        project_facts = _project_facts(
            args.project_path, args.function_va, instructions
        )
        coverage, missing = _coverage(
            cfg=cfg,
            instructions=instructions,
            decompile_text=decompile_text,
            decompile_missing=decompile_missing,
            project_facts=project_facts,
        )
        packet = WindowsDecompileContextPacket(
            binary_path=str(binary_path),
            function_va=args.function_va,
            address=f"0x{args.function_va:x}",
            cfg=cfg,
            decompile_text=decompile_text,
            decompile_truncated=truncated,
            instructions=instructions,
            calls=calls,
            project_facts=project_facts,
            coverage=coverage,
            missing_capabilities=missing,
            notes=[
                "context packet is bounded static context, not proof of reachability or vulnerability"
            ],
        )
        evidence_bundle = _evidence_bundle(packet)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_decompile_context_packet",
                    props={
                        "binary_path": str(binary_path),
                        "function_va": args.function_va,
                        "instruction_count": len(instructions),
                        "call_count": len(calls),
                        "coverage": coverage,
                        "missing_capabilities": missing,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsDecompileContextPacketResult(
            packet=packet,
            evidence_bundle=evidence_bundle,
            evidence_node_id=evidence_node_id,
        )


def _cfg_summary(binary_path: Path, function_va: int) -> WindowsContextCfgSummary:
    try:
        functions, _callgraph = g.analysis.analyze_functions_path(  # ty: ignore[unresolved-attribute]
            str(binary_path)
        )
    except Exception:
        return WindowsContextCfgSummary()
    for func in functions:
        entry = int(func.entry_point.value)
        if entry != int(function_va):
            continue
        blocks = list(getattr(func, "basic_blocks", []) or [])
        instruction_count = 0
        edge_count = 0
        for block in blocks:
            instruction_count += int(getattr(block, "instruction_count", 0) or 0)
            edge_count += len(getattr(block, "successors", []) or [])
        return WindowsContextCfgSummary(
            function_name=str(getattr(func, "name", None) or ""),
            basic_block_count=len(blocks),
            instruction_count=instruction_count,
            edge_count=edge_count,
            recovered_from_analysis=True,
        )
    return WindowsContextCfgSummary()


def _instructions(
    binary_path: Path,
    args: WindowsDecompileContextPacketArgs,
) -> list[WindowsContextInstruction]:
    try:
        raw = g.disasm.disassemble_window_at(  # ty: ignore[unresolved-attribute]
            str(binary_path),
            args.function_va,
            window_bytes=args.window_bytes,
            max_instructions=args.max_instructions,
            max_time_ms=args.timeout_ms,
        )
    except Exception:
        return []
    return [
        WindowsContextInstruction(
            va=int(ins.address.value),
            address=f"0x{int(ins.address.value):x}",
            text=_instruction_text(ins),
            bytes_hex=(ins.bytes or b"").hex(),
        )
        for ins in raw
    ]


def _calls(instructions: list[WindowsContextInstruction]) -> list[WindowsContextCall]:
    calls: list[WindowsContextCall] = []
    for instruction in instructions:
        if not instruction.text.lower().lstrip().startswith("call"):
            continue
        target_va = _first_hex(instruction.text)
        calls.append(
            WindowsContextCall(
                va=instruction.va,
                address=instruction.address,
                target_va=target_va,
                target=f"0x{target_va:x}" if target_va is not None else None,
                text=instruction.text,
            )
        )
    return calls


def _decompile(
    binary_path: Path,
    args: WindowsDecompileContextPacketArgs,
) -> tuple[str | None, bool, str | None]:
    if args.max_decompile_chars == 0:
        return None, False, "decompile_disabled"
    try:
        text = g.ir.decompile_at(  # ty: ignore[unresolved-attribute]
            str(binary_path),
            args.function_va,
            timeout_ms=args.timeout_ms,
            pdb_cache=args.pdb_cache,
        )
    except Exception as exc:
        return None, False, f"decompile_failed:{type(exc).__name__}"
    truncated = len(text) > args.max_decompile_chars
    if truncated:
        text = text[: args.max_decompile_chars]
    return text, truncated, None


def _project_facts(
    project_path: str | None,
    function_va: int,
    instructions: list[WindowsContextInstruction],
) -> WindowsContextProjectFacts | None:
    if not project_path:
        return None
    path = Path(project_path).expanduser()
    if not path.exists():
        return WindowsContextProjectFacts(
            project_path=str(path),
            missing_capabilities=["project_path_missing"],
        )
    kb = PersistentKnowledgeBase.open(path)
    try:
        function_name = xref_db.get_function_name(kb, function_va)
        comments = dict(xref_db.list_comments(kb))
        labels = {label.va: label for label in xref_db.list_data_labels(kb)}
        instruction_vas = {item.va for item in instructions}
        inline_comments = {
            f"0x{va:x}": body
            for va, body in comments.items()
            if va == function_va or va in instruction_vas
        }
        data_labels = {
            f"0x{va:x}": label.name
            for va, label in labels.items()
            if va in instruction_vas or abs(va - function_va) <= 0x10000
        }
    finally:
        kb.close()
    coverage: list[str] = []
    missing: list[str] = []
    if function_name is not None:
        coverage.append("function_names")
    else:
        missing.append("function_name_for_entry")
    if inline_comments:
        coverage.append("comments")
    else:
        missing.append("entry_or_instruction_comments")
    if data_labels:
        coverage.append("data_labels")
    else:
        missing.append("nearby_data_labels")
    return WindowsContextProjectFacts(
        project_path=str(path),
        function_name=function_name.display if function_name is not None else None,
        entry_comment=comments.get(function_va),
        inline_comments=inline_comments,
        data_labels=data_labels,
        coverage=coverage,
        missing_capabilities=missing,
    )


def _coverage(
    *,
    cfg: WindowsContextCfgSummary,
    instructions: list[WindowsContextInstruction],
    decompile_text: str | None,
    decompile_missing: str | None,
    project_facts: WindowsContextProjectFacts | None,
) -> tuple[list[str], list[str]]:
    coverage: list[str] = []
    missing: list[str] = []
    if cfg.recovered_from_analysis:
        coverage.append("cfg_summary")
    else:
        missing.append("cfg_summary")
    if instructions:
        coverage.append("disassembly")
    else:
        missing.append("disassembly")
    if decompile_text:
        coverage.append("decompile_text")
    elif decompile_missing:
        missing.append(decompile_missing)
    if project_facts is None:
        missing.append("project_facts")
    else:
        coverage.extend(project_facts.coverage)
        missing.extend(project_facts.missing_capabilities)
    return _dedupe(coverage), _dedupe(missing)


def _evidence_bundle(packet: WindowsDecompileContextPacket) -> WindowsEvidenceBundle:
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            binary=Path(packet.binary_path).name,
            va=packet.function_va,
            attributes={
                "function_name": packet.cfg.function_name,
                "instruction_count": len(packet.instructions),
                "call_count": len(packet.calls),
            },
        ),
        source_tools=["windows_decompile_context_packet"],
        evidence_refs=[
            evidence_ref(
                kind="tool_result",
                source="windows_decompile_context_packet",
                summary=(
                    f"{packet.address}: {len(packet.instructions)} instructions, "
                    f"{len(packet.calls)} calls"
                ),
                address=packet.function_va,
                confidence=0.7 if packet.coverage else 0.3,
                reason_codes=packet.coverage,
                provenance=[packet.binary_path],
            )
        ],
        coverage=WindowsEvidenceCoverage(
            fact_coverage=packet.coverage,
            missing_facts=packet.missing_capabilities,
        ),
        confidence=0.7 if packet.coverage else 0.3,
        confidence_reason="bounded static function context packet",
        blockers=packet.missing_capabilities,
        next_actions=[
            "windows_project_call_argument_snapshot",
            "windows_project_cfg_path_query",
            "windows_analyst_notebook",
        ],
        notes=packet.notes,
    )


def _instruction_text(ins: object) -> str:
    mnemonic = str(getattr(ins, "mnemonic", "") or "")
    operands = ", ".join(str(op) for op in (getattr(ins, "operands", []) or []))
    return f"{mnemonic} {operands}".strip()


def _first_hex(text: str) -> int | None:
    match = re.search(r"0x[0-9a-fA-F]+", text)
    if not match:
        return None
    try:
        return int(match.group(0), 16)
    except ValueError:
        return None


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsDecompileContextPacketTool:
    return WindowsDecompileContextPacketTool()
