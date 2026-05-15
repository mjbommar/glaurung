from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .java_view_bytecode import JavaBytecodeInstruction
from .java_view_bytecode import build_tool as build_bytecode_tool


JavaCfgEdgeKind = Literal[
    "fallthrough",
    "conditional_true",
    "conditional_false",
    "goto",
    "switch_default",
    "jsr",
]


class JavaCfgArgs(BaseModel):
    path: str | None = Field(None, description="Path to the JAR/ZIP archive")
    class_name: str | None = Field(
        None,
        description="Class name in internal, dotted, obfuscated, or official namespace",
    )
    method_name: str | None = Field(
        None,
        description="Method name in obfuscated or mapped namespace",
    )
    method_descriptor: str | None = Field(None, description="Optional JVM descriptor")
    mapping_path: str | None = Field(
        None,
        description="Optional ProGuard/Mojang mapping file for de-obfuscation",
    )
    max_instructions: int = Field(50_000, ge=1)
    max_blocks: int = Field(4_096, ge=1)
    max_edges: int = Field(8_192, ge=1)


class JavaCfgBlock(BaseModel):
    block_id: str
    start_bci: int
    end_bci: int
    end_bci_exclusive: int
    instruction_count: int
    first_line_number: int | None = None
    last_line_number: int | None = None
    terminator_mnemonic: str | None = None


class JavaCfgEdge(BaseModel):
    source_block_id: str
    target_block_id: str
    source_start_bci: int
    target_start_bci: int
    kind: JavaCfgEdgeKind


class JavaCfgResult(BaseModel):
    archive_path: str
    class_found: bool
    method_found: bool
    class_name: str | None = None
    mapped_class_name: str | None = None
    method_name: str | None = None
    mapped_method_names: list[str] = Field(default_factory=list)
    method_descriptor: str | None = None
    instruction_count: int = 0
    block_count: int = 0
    edge_count: int = 0
    blocks: list[JavaCfgBlock] = Field(default_factory=list)
    edges: list[JavaCfgEdge] = Field(default_factory=list)
    stop_reasons: list[str] = Field(default_factory=list)
    truncated: bool = False
    cfg_node_id: str | None = None


class JavaCfgTool(MemoryTool[JavaCfgArgs, JavaCfgResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="java_cfg",
                description=(
                    "Build an initial JVM bytecode control-flow graph for a selected "
                    "method using instruction boundaries, branch targets, fallthrough "
                    "edges, and source-line anchors."
                ),
                tags=("java", "bytecode", "cfg", "control-flow", "kb"),
            ),
            JavaCfgArgs,
            JavaCfgResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: JavaCfgArgs,
    ) -> JavaCfgResult:
        path = Path(args.path or ctx.file_path)
        bytecode_tool = build_bytecode_tool()
        bytecode = bytecode_tool.run(
            ctx,
            kb,
            bytecode_tool.input_model(
                path=str(path),
                class_name=args.class_name,
                method_name=args.method_name,
                method_descriptor=args.method_descriptor,
                mapping_path=args.mapping_path,
                include_xrefs=False,
                max_instructions=args.max_instructions,
            ),
        )
        if not bytecode.method_found:
            return JavaCfgResult(
                archive_path=str(path),
                class_found=bytecode.class_found,
                method_found=False,
                class_name=bytecode.class_name,
                mapped_class_name=bytecode.mapped_class_name,
                method_name=bytecode.method_name,
                mapped_method_names=bytecode.mapped_method_names,
                method_descriptor=bytecode.method_descriptor,
                stop_reasons=["method_not_found"],
            )

        blocks, edges, stop_reasons, truncated = _build_cfg(
            bytecode.instructions,
            max_blocks=args.max_blocks,
            max_edges=args.max_edges,
        )
        cfg_node = kb.add_node(
            Node(
                kind=NodeKind.java_cfg,
                label=(
                    f"{bytecode.mapped_class_name or bytecode.class_name}#"
                    f"{bytecode.mapped_method_names[0] if bytecode.mapped_method_names else bytecode.method_name}"
                    f"{bytecode.method_descriptor}"
                ),
                props={
                    "tool": "java_cfg",
                    "archive_path": str(path),
                    "class_name": bytecode.class_name,
                    "mapped_class_name": bytecode.mapped_class_name,
                    "method_name": bytecode.method_name,
                    "mapped_method_names": bytecode.mapped_method_names,
                    "method_descriptor": bytecode.method_descriptor,
                    "instruction_count": len(bytecode.instructions),
                    "block_count": len(blocks),
                    "edge_count": len(edges),
                    "stop_reasons": stop_reasons,
                    "truncated": truncated or bytecode.truncated,
                },
                tags=["java", "cfg", "bytecode"],
            )
        )
        return JavaCfgResult(
            archive_path=str(path),
            class_found=True,
            method_found=True,
            class_name=bytecode.class_name,
            mapped_class_name=bytecode.mapped_class_name,
            method_name=bytecode.method_name,
            mapped_method_names=bytecode.mapped_method_names,
            method_descriptor=bytecode.method_descriptor,
            instruction_count=len(bytecode.instructions),
            block_count=len(blocks),
            edge_count=len(edges),
            blocks=blocks,
            edges=edges,
            stop_reasons=stop_reasons,
            truncated=truncated or bytecode.truncated,
            cfg_node_id=cfg_node.id,
        )


def _build_cfg(
    instructions: list[JavaBytecodeInstruction],
    *,
    max_blocks: int,
    max_edges: int,
) -> tuple[list[JavaCfgBlock], list[JavaCfgEdge], list[str], bool]:
    if not instructions:
        return [], [], ["no_instructions"], False
    sorted_instructions = sorted(instructions, key=lambda instruction: instruction.bci)
    bci_to_instruction = {
        instruction.bci: instruction for instruction in sorted_instructions
    }
    bcis = [instruction.bci for instruction in sorted_instructions]
    next_bci = {
        instruction.bci: bcis[index + 1]
        for index, instruction in enumerate(sorted_instructions[:-1])
    }

    leaders = {sorted_instructions[0].bci}
    for instruction in sorted_instructions:
        targets = _branch_targets(instruction)
        for target in targets:
            if target in bci_to_instruction:
                leaders.add(target)
        if _terminates_block(instruction):
            fallthrough_bci = next_bci.get(instruction.bci)
            if fallthrough_bci is not None and not _is_unconditional_terminal(
                instruction
            ):
                leaders.add(fallthrough_bci)

    sorted_leaders = sorted(leaders)
    block_ranges: list[tuple[int, list[JavaBytecodeInstruction]]] = []
    for index, leader in enumerate(sorted_leaders):
        next_leader = (
            sorted_leaders[index + 1] if index + 1 < len(sorted_leaders) else None
        )
        block_instructions = [
            instruction
            for instruction in sorted_instructions
            if instruction.bci >= leader
            and (next_leader is None or instruction.bci < next_leader)
        ]
        if block_instructions:
            block_ranges.append((leader, block_instructions))

    truncated = len(block_ranges) > max_blocks
    block_ranges = block_ranges[:max_blocks]
    block_by_start = {
        start: _block_summary(block_instructions)
        for start, block_instructions in block_ranges
    }
    blocks = [block_by_start[start] for start, _ in block_ranges]
    edges: list[JavaCfgEdge] = []
    for start, block_instructions in block_ranges:
        if len(edges) >= max_edges:
            truncated = True
            break
        block = block_by_start[start]
        terminator = block_instructions[-1]
        candidate_edges = _edges_for_terminator(
            terminator,
            next_bci=next_bci,
            block_by_start=block_by_start,
            source_block=block,
        )
        for edge in candidate_edges:
            if len(edges) >= max_edges:
                truncated = True
                break
            edges.append(edge)

    stop_reasons = [
        "exception_edges_not_yet_modeled",
        "stack_frame_analysis_not_yet_available",
    ]
    return blocks, edges, stop_reasons, truncated


def _block_summary(
    block_instructions: list[JavaBytecodeInstruction],
) -> JavaCfgBlock:
    first = block_instructions[0]
    last = block_instructions[-1]
    lines = [
        instruction.line_number
        for instruction in block_instructions
        if instruction.line_number is not None
    ]
    return JavaCfgBlock(
        block_id=f"bci_{first.bci}",
        start_bci=first.bci,
        end_bci=last.bci,
        end_bci_exclusive=last.bci + last.length,
        instruction_count=len(block_instructions),
        first_line_number=lines[0] if lines else None,
        last_line_number=lines[-1] if lines else None,
        terminator_mnemonic=last.mnemonic,
    )


def _edges_for_terminator(
    terminator: JavaBytecodeInstruction,
    *,
    next_bci: dict[int, int],
    block_by_start: dict[int, JavaCfgBlock],
    source_block: JavaCfgBlock,
) -> list[JavaCfgEdge]:
    mnemonic = terminator.mnemonic
    targets = _branch_targets(terminator)
    out: list[JavaCfgEdge] = []
    if _is_conditional_branch(mnemonic):
        if targets:
            out.extend(
                _edge(source_block, block_by_start, targets[0], "conditional_true")
            )
        fallthrough_bci = next_bci.get(terminator.bci)
        if fallthrough_bci is not None:
            out.extend(
                _edge(
                    source_block,
                    block_by_start,
                    fallthrough_bci,
                    "conditional_false",
                )
            )
        return out
    if mnemonic in {"goto", "goto_w"}:
        if targets:
            out.extend(_edge(source_block, block_by_start, targets[0], "goto"))
        return out
    if mnemonic in {"jsr", "jsr_w"}:
        if targets:
            out.extend(_edge(source_block, block_by_start, targets[0], "jsr"))
        return out
    if mnemonic in {"tableswitch", "lookupswitch"}:
        for target in targets:
            out.extend(_edge(source_block, block_by_start, target, "switch_default"))
        return out
    if _is_return_or_throw(mnemonic):
        return out
    fallthrough_bci = next_bci.get(terminator.bci)
    if fallthrough_bci is not None:
        out.extend(_edge(source_block, block_by_start, fallthrough_bci, "fallthrough"))
    return out


def _edge(
    source_block: JavaCfgBlock,
    block_by_start: dict[int, JavaCfgBlock],
    target_bci: int,
    kind: JavaCfgEdgeKind,
) -> list[JavaCfgEdge]:
    target_block = block_by_start.get(target_bci)
    if target_block is None:
        return []
    return [
        JavaCfgEdge(
            source_block_id=source_block.block_id,
            target_block_id=target_block.block_id,
            source_start_bci=source_block.start_bci,
            target_start_bci=target_block.start_bci,
            kind=kind,
        )
    ]


def _branch_targets(instruction: JavaBytecodeInstruction) -> list[int]:
    targets: list[int] = []
    for operand in instruction.operands:
        if operand.startswith("target="):
            value = operand.removeprefix("target=")
        elif operand.startswith("default="):
            value = operand.removeprefix("default=")
        else:
            continue
        try:
            targets.append(int(value))
        except ValueError:
            continue
    return targets


def _terminates_block(instruction: JavaBytecodeInstruction) -> bool:
    return (
        _is_conditional_branch(instruction.mnemonic)
        or instruction.mnemonic
        in {"goto", "goto_w", "jsr", "jsr_w", "tableswitch", "lookupswitch"}
        or _is_return_or_throw(instruction.mnemonic)
    )


def _is_conditional_branch(mnemonic: str) -> bool:
    return mnemonic.startswith("if")


def _is_return_or_throw(mnemonic: str) -> bool:
    return mnemonic in {
        "ireturn",
        "lreturn",
        "freturn",
        "dreturn",
        "areturn",
        "return",
        "athrow",
    }


def _is_unconditional_terminal(instruction: JavaBytecodeInstruction) -> bool:
    return instruction.mnemonic in {
        "goto",
        "goto_w",
        "tableswitch",
        "lookupswitch",
    } or _is_return_or_throw(instruction.mnemonic)


def build_tool() -> MemoryTool[JavaCfgArgs, JavaCfgResult]:
    return JavaCfgTool()
