from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_project_call_argument_snapshot import (
    WINDOWS_X64_ARG_ROLES,
    _callsite_row,
    _canonical_register,
    _first_binary_id,
    _instruction_text,
    _is_register,
    _present_tables,
    _strip_memory_prefix,
    _written_register,
)


RETURN_ALIASES = {"rax"}
CONDITIONAL_BRANCH_PREFIXES = ("ja", "jb", "jc", "je", "jg", "jl", "jn", "jo", "jp", "js", "jz")


class WindowsProjectReturnValueUseSnapshotArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary backing the project.")
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    callsite_va: int = Field(..., description="Exact callsite VA from persisted call xrefs.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    max_window_bytes: int = Field(
        4096,
        ge=16,
        description="Maximum bytes to disassemble from function entry through the post-call window.",
    )
    max_instructions: int = Field(
        512,
        ge=1,
        description="Maximum instructions to disassemble from the caller function entry.",
    )
    max_after_instructions: int = Field(
        16,
        ge=1,
        description="Maximum instructions to inspect after the callsite.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact return-value-use evidence node to the KB.",
    )


class ProjectReturnValueUseFact(BaseModel):
    use_kind: str
    instruction_va: int
    instruction_text: str
    mnemonic: str
    operands: list[str] = Field(default_factory=list)
    register_name: str = "rax"
    expression: str | None = None
    argument_role: str | None = None
    branch_va: int | None = None
    branch_text: str | None = None
    branch_taken_constraint: str | None = None
    fallthrough_constraint: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    notes: list[str] = Field(default_factory=list)


class WindowsProjectReturnValueUseSnapshotResult(BaseModel):
    binary_path: str
    project_path: str
    binary_id: int | None = None
    callsite_va: int
    caller_va: int | None = None
    caller_name: str | None = None
    callee_va: int | None = None
    callee_name: str | None = None
    callsite_text: str | None = None
    uses: list[ProjectReturnValueUseFact]
    first_use_kind: str | None = None
    inspected_instruction_count: int
    inspected_after_instruction_count: int
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectReturnValueUseSnapshotTool(
    MemoryTool[
        WindowsProjectReturnValueUseSnapshotArgs,
        WindowsProjectReturnValueUseSnapshotResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_return_value_use_snapshot",
                description=(
                    "Recover a conservative local post-call Windows x64 RAX return-value "
                    "use snapshot for one persisted PE callsite using nearby disassembly."
                ),
                tags=("windows", "pe", "project", "callsites", "return-values"),
            ),
            WindowsProjectReturnValueUseSnapshotArgs,
            WindowsProjectReturnValueUseSnapshotResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectReturnValueUseSnapshotArgs,
    ) -> WindowsProjectReturnValueUseSnapshotResult:
        binary_path = Path(args.binary_path)
        project_path = Path(args.project_path)
        if not binary_path.exists():
            raise ValueError(f"{binary_path}: PE binary does not exist")
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        conn = sqlite3.connect(f"file:{project_path}?mode=ro", uri=True)
        try:
            present = _present_tables(conn)
            binary_id = args.binary_id or _first_binary_id(conn, present)
            row = _callsite_row(conn, present, binary_id, args.callsite_va)
        finally:
            conn.close()

        instructions = _disassemble_around_callsite(binary_path, row, args)
        callsite_text = _callsite_text(instructions, args.callsite_va)
        after = _instructions_after_callsite(instructions, args.callsite_va, args.max_after_instructions)
        uses = _return_value_uses(after)
        coverage = _coverage(row, instructions, after, uses)
        missing = _missing_capabilities(row, instructions, after, uses)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_return_value_use_snapshot",
                    props={
                        "binary_path": str(binary_path),
                        "project_path": str(project_path),
                        "callsite_va": args.callsite_va,
                        "caller_va": row.get("caller_va"),
                        "callee_va": row.get("callee_va"),
                        "use_count": len(uses),
                        "first_use_kind": uses[0].use_kind if uses else None,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectReturnValueUseSnapshotResult(
            binary_path=str(binary_path),
            project_path=str(project_path),
            binary_id=binary_id,
            callsite_va=args.callsite_va,
            caller_va=row.get("caller_va"),
            caller_name=row.get("caller_name"),
            callee_va=row.get("callee_va"),
            callee_name=row.get("callee_name"),
            callsite_text=callsite_text,
            uses=uses,
            first_use_kind=uses[0].use_kind if uses else None,
            inspected_instruction_count=len(instructions),
            inspected_after_instruction_count=len(after),
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "return-value use snapshot is local and conservative; full aliasing, "
                "path-sensitive value constraints, helper side effects, and IR-level "
                "flag flow need separate facts"
            ],
        )


def _disassemble_around_callsite(
    binary_path: Path,
    row: dict[str, Any],
    args: WindowsProjectReturnValueUseSnapshotArgs,
) -> list[g.Instruction]:
    caller_va = row.get("caller_va")
    if not isinstance(caller_va, int):
        caller_va = args.callsite_va
    requested = max(16, args.callsite_va - caller_va + args.max_window_bytes)
    window_bytes = min(args.max_window_bytes, requested)
    try:
        return list(
            g.disasm.disassemble_window_at(
                str(binary_path),
                caller_va,
                window_bytes=window_bytes,
                max_instructions=args.max_instructions,
            )
        )
    except Exception:
        return []


def _callsite_text(instructions: list[g.Instruction], callsite_va: int) -> str | None:
    for instruction in instructions:
        if int(instruction.address.value) == callsite_va:
            return _instruction_text(instruction)
    return None


def _instructions_after_callsite(
    instructions: list[g.Instruction],
    callsite_va: int,
    max_after_instructions: int,
) -> list[g.Instruction]:
    out: list[g.Instruction] = []
    seen_callsite = False
    for instruction in instructions:
        va = int(instruction.address.value)
        if va == callsite_va:
            seen_callsite = True
            continue
        if not seen_callsite:
            continue
        if va < callsite_va:
            continue
        out.append(instruction)
        if len(out) >= max_after_instructions:
            break
    return out


def _return_value_uses(instructions: list[g.Instruction]) -> list[ProjectReturnValueUseFact]:
    uses: list[ProjectReturnValueUseFact] = []
    aliases: set[str] = set(RETURN_ALIASES)
    for index, instruction in enumerate(instructions):
        mnemonic = str(instruction.mnemonic or "").lower()
        operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
        next_branch = _next_conditional_branch(instructions, index + 1)

        if mnemonic == "call":
            arg_fact = _call_argument_fact(instruction, aliases)
            if arg_fact is not None:
                uses.append(arg_fact)
            elif "rax" in aliases:
                uses.append(
                    _fact(
                        "clobbered_by_call",
                        instruction,
                        confidence=0.82,
                        notes=["nested call overwrites RAX before a local return-value use was proven"],
                    )
                )
            aliases.discard("rax")
            continue

        comparison = _comparison_fact(instruction, aliases, next_branch)
        if comparison is not None:
            uses.append(comparison)
            continue

        store = _store_fact(instruction, aliases)
        if store is not None:
            uses.append(store)
            assigned = _assigned_register(mnemonic, operands)
            if assigned is not None:
                aliases.add(assigned)
            continue

        zeroing = _zeroing_clobber_fact(instruction, aliases)
        if zeroing is not None:
            uses.append(zeroing)
            assigned = _assigned_register(mnemonic, operands)
            if assigned is not None:
                aliases.discard(assigned)
            continue

        arithmetic = _arithmetic_fact(instruction, aliases)
        if arithmetic is not None:
            uses.append(arithmetic)
            assigned = _assigned_register(mnemonic, operands)
            if assigned is not None and _operand_mentions_alias(operands[0], aliases):
                aliases.add(assigned)
            continue

        assigned = _assigned_register(mnemonic, operands)
        if assigned is not None:
            if assigned == "rax" and "rax" in aliases:
                uses.append(
                    _fact(
                        "clobbered_by_write",
                        instruction,
                        confidence=0.82,
                        notes=["RAX was overwritten before a local return-value use was proven"],
                    )
                )
            aliases.discard(assigned)

    if not uses and instructions:
        uses.append(
            ProjectReturnValueUseFact(
                use_kind="ignored_in_window",
                instruction_va=int(instructions[-1].address.value),
                instruction_text=_instruction_text(instructions[-1]),
                mnemonic=str(instructions[-1].mnemonic or "").lower(),
                operands=[str(op).strip() for op in getattr(instructions[-1], "operands", []) or []],
                expression=None,
                confidence=0.55,
                notes=["no RAX use or clobber was observed in the inspected post-call window"],
            )
        )
    return uses


def _comparison_fact(
    instruction: g.Instruction,
    aliases: set[str],
    next_branch: g.Instruction | None,
) -> ProjectReturnValueUseFact | None:
    mnemonic = str(instruction.mnemonic or "").lower()
    operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
    if mnemonic not in {"cmp", "test"}:
        return None
    if not any(_operand_mentions_alias(operand, aliases) for operand in operands):
        return None
    use_kind = "comparison_gate"
    if mnemonic == "test" and len(operands) >= 2 and _same_register(operands[0], operands[1]):
        use_kind = "null_or_status_check"
    return _fact(
        use_kind,
        instruction,
        expression=", ".join(operands),
        branch=next_branch,
        branch_constraint=_branch_constraint(mnemonic, operands, next_branch),
        confidence=0.86 if next_branch is not None else 0.78,
    )


def _store_fact(instruction: g.Instruction, aliases: set[str]) -> ProjectReturnValueUseFact | None:
    mnemonic = str(instruction.mnemonic or "").lower()
    operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
    if mnemonic not in {"mov", "movsxd", "movzx", "lea"} or len(operands) < 2:
        return None
    dst = operands[0]
    src = operands[1]
    if not _operand_mentions_alias(src, aliases):
        if _operand_mentions_alias(dst, aliases) and not _is_register(_canonical_register(dst)):
            return _fact(
                "return_used_as_address",
                instruction,
                expression=dst,
                confidence=0.74,
            )
        return None
    dst_register = _canonical_register(dst)
    if _is_register(dst_register):
        return _fact(
            "stored_to_register",
            instruction,
            expression=dst_register,
            confidence=0.82,
        )
    return _fact(
        "stored_to_memory",
        instruction,
        expression=dst,
        confidence=0.78,
    )


def _arithmetic_fact(
    instruction: g.Instruction,
    aliases: set[str],
) -> ProjectReturnValueUseFact | None:
    mnemonic = str(instruction.mnemonic or "").lower()
    operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
    if mnemonic not in {
        "add",
        "and",
        "bt",
        "dec",
        "imul",
        "inc",
        "neg",
        "not",
        "or",
        "sar",
        "shl",
        "shr",
        "sub",
        "xor",
    }:
        return None
    if not any(_operand_mentions_alias(operand, aliases) for operand in operands):
        return None
    return _fact(
        "arithmetic_or_bitwise_use",
        instruction,
        expression=", ".join(operands),
        confidence=0.74,
    )


def _zeroing_clobber_fact(
    instruction: g.Instruction,
    aliases: set[str],
) -> ProjectReturnValueUseFact | None:
    mnemonic = str(instruction.mnemonic or "").lower()
    operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
    if mnemonic != "xor" or len(operands) < 2:
        return None
    if not _same_register(operands[0], operands[1]):
        return None
    assigned = _assigned_register(mnemonic, operands)
    if assigned not in aliases:
        return None
    return _fact(
        "clobbered_by_zeroing",
        instruction,
        confidence=0.84,
        notes=["zeroing idiom overwrote the return register before a use was proven"],
    )


def _call_argument_fact(
    instruction: g.Instruction,
    aliases: set[str],
) -> ProjectReturnValueUseFact | None:
    for register, role in WINDOWS_X64_ARG_ROLES.items():
        if register in aliases:
            return _fact(
                "passed_as_argument",
                instruction,
                expression=register,
                argument_role=role,
                confidence=0.76,
            )
    return None


def _next_conditional_branch(
    instructions: list[g.Instruction],
    start_index: int,
) -> g.Instruction | None:
    if start_index >= len(instructions):
        return None
    instruction = instructions[start_index]
    mnemonic = str(instruction.mnemonic or "").lower()
    if _is_conditional_branch(mnemonic):
        return instruction
    return None


def _is_conditional_branch(mnemonic: str) -> bool:
    return mnemonic.startswith(CONDITIONAL_BRANCH_PREFIXES) and mnemonic != "jmp"


def _fact(
    use_kind: str,
    instruction: g.Instruction,
    *,
    expression: str | None = None,
    argument_role: str | None = None,
    branch: g.Instruction | None = None,
    branch_constraint: tuple[str, str] | None = None,
    confidence: float,
    notes: list[str] | None = None,
) -> ProjectReturnValueUseFact:
    return ProjectReturnValueUseFact(
        use_kind=use_kind,
        instruction_va=int(instruction.address.value),
        instruction_text=_instruction_text(instruction),
        mnemonic=str(instruction.mnemonic or "").lower(),
        operands=[str(op).strip() for op in getattr(instruction, "operands", []) or []],
        expression=expression,
        argument_role=argument_role,
        branch_va=int(branch.address.value) if branch is not None else None,
        branch_text=_instruction_text(branch) if branch is not None else None,
        branch_taken_constraint=branch_constraint[0] if branch_constraint else None,
        fallthrough_constraint=branch_constraint[1] if branch_constraint else None,
        confidence=confidence,
        notes=notes or [],
    )


def _branch_constraint(
    compare_mnemonic: str,
    compare_operands: list[str],
    branch: g.Instruction | None,
) -> tuple[str, str] | None:
    if branch is None:
        return None
    branch_mnemonic = str(branch.mnemonic or "").lower()
    if compare_mnemonic == "test" and _is_self_zero_test(compare_operands):
        return _zero_constraint(branch_mnemonic)
    if compare_mnemonic == "cmp" and _is_zero_compare(compare_operands):
        return _zero_constraint(branch_mnemonic)
    return None


def _is_self_zero_test(operands: list[str]) -> bool:
    return len(operands) >= 2 and _same_register(operands[0], operands[1])


def _is_zero_compare(operands: list[str]) -> bool:
    if len(operands) < 2:
        return False
    return _is_zero_immediate(operands[1])


def _is_zero_immediate(operand: str) -> bool:
    text = operand.strip().lower()
    return text in {"0", "0x0"}


def _zero_constraint(branch_mnemonic: str) -> tuple[str, str] | None:
    if branch_mnemonic in {"je", "jz"}:
        return ("return_value_zero_or_null", "return_value_nonzero")
    if branch_mnemonic in {"jne", "jnz"}:
        return ("return_value_nonzero", "return_value_zero_or_null")
    if branch_mnemonic in {"jl", "jnge"}:
        return (
            "return_value_signed_less_than_zero",
            "return_value_signed_greater_equal_zero",
        )
    if branch_mnemonic in {"jle", "jng"}:
        return (
            "return_value_signed_less_equal_zero",
            "return_value_signed_greater_than_zero",
        )
    if branch_mnemonic in {"jg", "jnle"}:
        return (
            "return_value_signed_greater_than_zero",
            "return_value_signed_less_equal_zero",
        )
    if branch_mnemonic in {"jge", "jnl"}:
        return (
            "return_value_signed_greater_equal_zero",
            "return_value_signed_less_than_zero",
        )
    return None


def _operand_mentions_alias(operand: str, aliases: set[str]) -> bool:
    register = _canonical_register(operand)
    if register in aliases:
        return True
    text = _strip_memory_prefix(operand)
    for token in re.findall(r"\b(?:r(?:1[0-5]|[abcd]x|[sd]i|[bs]p|[89])|e[abcd]x|r[89]d|[abcd][lh])\b", text):
        if _canonical_register(token) in aliases:
            return True
    return False


def _same_register(left: str, right: str) -> bool:
    return _canonical_register(left) == _canonical_register(right)


def _assigned_register(mnemonic: str, operands: list[str]) -> str | None:
    assigned = _written_register(mnemonic, operands)
    return assigned if assigned and _is_register(assigned) else None


def _coverage(
    row: dict[str, Any],
    instructions: list[g.Instruction],
    after: list[g.Instruction],
    uses: list[ProjectReturnValueUseFact],
) -> list[str]:
    coverage: list[str] = ["project_call_xref"]
    if row.get("caller_name") or row.get("callee_name"):
        coverage.append("function_names")
    if instructions:
        coverage.append("nearby_disassembly")
    if after:
        coverage.append("post_call_window")
    if any(use.use_kind in {"comparison_gate", "null_or_status_check"} for use in uses):
        coverage.append("return_value_check")
    if any(use.branch_va is not None for use in uses):
        coverage.append("adjacent_branch_relation")
    if any(use.branch_taken_constraint is not None for use in uses):
        coverage.append("adjacent_branch_return_constraint")
    if any(use.use_kind in {"stored_to_register", "stored_to_memory"} for use in uses):
        coverage.append("return_value_store")
    if any(use.use_kind == "passed_as_argument" for use in uses):
        coverage.append("return_value_argument_use")
    if any(use.use_kind.startswith("clobbered") for use in uses):
        coverage.append("return_value_clobber")
    return coverage


def _missing_capabilities(
    row: dict[str, Any],
    instructions: list[g.Instruction],
    after: list[g.Instruction],
    uses: list[ProjectReturnValueUseFact],
) -> list[str]:
    missing: list[str] = []
    if not row.get("caller_name") or not row.get("callee_name"):
        missing.append("function_names")
    if not instructions:
        missing.append("nearby_disassembly")
    if not after:
        missing.append("post_call_disassembly")
    if any(use.use_kind == "ignored_in_window" for use in uses):
        missing.append("larger_post_call_window")
    missing.append("path_sensitive_return_value_flow")
    missing.append("non_adjacent_flag_flow")
    missing.append("full_alias_tracking")
    missing.append("helper_side_effect_summaries")
    return missing


def build_tool() -> WindowsProjectReturnValueUseSnapshotTool:
    return WindowsProjectReturnValueUseSnapshotTool()
