from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


WINDOWS_X64_ARGS = (("rcx", "arg0"), ("rdx", "arg1"), ("r8", "arg2"), ("r9", "arg3"))
WINDOWS_X64_ARG_ROLES = {register: role for register, role in WINDOWS_X64_ARGS}
WINDOWS_X64_STACK_ARG_BASE = 0x20
WINDOWS_X64_STACK_ARG_SLOT = 8
WINDOWS_X64_MAX_STACK_ARG_OFFSET = 0x100


class WindowsProjectCallArgumentSnapshotArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary backing the project.")
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    callsite_va: int = Field(..., description="Exact callsite VA from persisted call xrefs.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    max_window_bytes: int = Field(
        4096,
        ge=16,
        description="Maximum bytes to disassemble from function entry to the callsite.",
    )
    max_instructions: int = Field(
        256,
        ge=1,
        description="Maximum instructions to inspect before the callsite.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact call-argument evidence node to the KB.",
    )


class ProjectCallArgumentFact(BaseModel):
    index: int
    register_name: str
    role: str
    location: str = "register"
    stack_offset: int | None = None
    expression: str | None = None
    source_va: int | None = None
    source_text: str | None = None
    alias_depth: int = 0
    alias_kind: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class WindowsProjectCallArgumentSnapshotResult(BaseModel):
    binary_path: str
    project_path: str
    binary_id: int | None = None
    callsite_va: int
    caller_va: int | None = None
    caller_name: str | None = None
    callee_va: int | None = None
    callee_name: str | None = None
    callsite_text: str | None = None
    arguments: list[ProjectCallArgumentFact]
    inspected_instruction_count: int
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class _Assignment:
    va: int
    expression: str
    source_text: str
    alias_depth: int = 0
    alias_kind: str | None = None


@dataclass(frozen=True)
class _StackAssignment:
    va: int
    offset: int
    expression: str
    source_text: str
    alias_depth: int = 0
    alias_kind: str | None = None


@dataclass(frozen=True)
class _ResolvedExpression:
    expression: str
    alias_depth: int = 0
    alias_kind: str | None = None


class WindowsProjectCallArgumentSnapshotTool(
    MemoryTool[
        WindowsProjectCallArgumentSnapshotArgs,
        WindowsProjectCallArgumentSnapshotResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_call_argument_snapshot",
                description=(
                    "Recover a conservative Windows x64 RCX/RDX/R8/R9 argument "
                    "snapshot and obvious stack argument stores for one persisted "
                    "PE callsite using nearby disassembly."
                ),
                tags=("windows", "pe", "project", "callsites", "arguments"),
            ),
            WindowsProjectCallArgumentSnapshotArgs,
            WindowsProjectCallArgumentSnapshotResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectCallArgumentSnapshotArgs,
    ) -> WindowsProjectCallArgumentSnapshotResult:
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

        instructions = _disassemble_to_callsite(binary_path, row, args)
        callsite_text = None
        if instructions:
            callsite_text = _instruction_text(instructions[-1])
        arguments = _argument_snapshot(instructions, args.callsite_va)
        coverage = _coverage(row, instructions, arguments)
        missing = _missing_capabilities(row, instructions, arguments)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_call_argument_snapshot",
                    props={
                        "binary_path": str(binary_path),
                        "project_path": str(project_path),
                        "callsite_va": args.callsite_va,
                        "caller_va": row.get("caller_va"),
                        "callee_va": row.get("callee_va"),
                        "argument_count": len(arguments),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectCallArgumentSnapshotResult(
            binary_path=str(binary_path),
            project_path=str(project_path),
            binary_id=binary_id,
            callsite_va=args.callsite_va,
            caller_va=row.get("caller_va"),
            caller_name=row.get("caller_name"),
            callee_va=row.get("callee_va"),
            callee_name=row.get("callee_name"),
            callsite_text=callsite_text,
            arguments=arguments,
            inspected_instruction_count=len(instructions),
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "argument snapshot is local and conservative; full aliasing, "
                "non-obvious stack arguments, and path conditions need IR/CFG facts"
            ],
        )


def _present_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _first_binary_id(conn: sqlite3.Connection, present: set[str]) -> int | None:
    if "binaries" not in present:
        return None
    row = conn.execute(
        "SELECT binary_id FROM binaries ORDER BY binary_id LIMIT 1"
    ).fetchone()
    return int(row[0]) if row else None


def _callsite_row(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    callsite_va: int,
) -> dict[str, Any]:
    if "xrefs" not in present:
        raise ValueError("project has no xrefs table")
    fn_join = "function_names" in present
    caller_select = (
        "caller.canonical AS caller_name" if fn_join else "NULL AS caller_name"
    )
    callee_select = (
        "callee.canonical AS callee_name" if fn_join else "NULL AS callee_name"
    )
    joins = ""
    if fn_join:
        joins = """
LEFT JOIN function_names caller ON
    caller.binary_id = x.binary_id AND caller.entry_va = x.src_function_va
LEFT JOIN function_names callee ON
    callee.binary_id = x.binary_id AND callee.entry_va = x.dst_va
"""
    clauses = ["x.kind = 'call'", "x.src_va = ?"]
    params: list[object] = [callsite_va]
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    cur = conn.execute(
        f"""
SELECT
    x.binary_id AS binary_id,
    x.src_va AS callsite_va,
    x.src_function_va AS caller_va,
    x.dst_va AS callee_va,
    {caller_select},
    {callee_select}
FROM xrefs x
{joins}
WHERE {' AND '.join(clauses)}
ORDER BY x.xref_id
LIMIT 1
""",
        params,
    )
    columns = [col[0] for col in cur.description or []]
    row = cur.fetchone()
    if not row:
        raise ValueError(f"callsite 0x{callsite_va:x} not found in project call xrefs")
    return dict(zip(columns, row, strict=True))


def _disassemble_to_callsite(
    binary_path: Path,
    row: dict[str, Any],
    args: WindowsProjectCallArgumentSnapshotArgs,
) -> list[g.Instruction]:
    caller_va = row.get("caller_va")
    if not isinstance(caller_va, int):
        caller_va = args.callsite_va
    window_bytes = min(args.max_window_bytes, max(16, args.callsite_va - caller_va + 16))
    try:
        instructions = g.disasm.disassemble_window_at(
            str(binary_path),
            caller_va,
            window_bytes=window_bytes,
            max_instructions=args.max_instructions,
        )
    except Exception:
        return []
    out: list[g.Instruction] = []
    for instruction in instructions:
        va = int(instruction.address.value)
        if va > args.callsite_va:
            break
        out.append(instruction)
        if va == args.callsite_va:
            break
    return out


def _argument_snapshot(
    instructions: list[g.Instruction],
    callsite_va: int,
) -> list[ProjectCallArgumentFact]:
    assignments: dict[str, _Assignment] = {}
    frame_assignments: dict[str, _Assignment] = {}
    stack_assignments: dict[int, _StackAssignment] = {}
    clobbered_registers: set[str] = set()
    for instruction in instructions:
        va = int(instruction.address.value)
        mnemonic = str(instruction.mnemonic or "").lower()
        operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
        if va == callsite_va:
            break
        if mnemonic == "call":
            assignments.clear()
            frame_assignments.clear()
            stack_assignments.clear()
            clobbered_registers.clear()
            continue
        assignment = _register_assignment(mnemonic, operands)
        if assignment is not None:
            register, expression = assignment
            resolved = _resolve_expression(
                expression,
                assignments,
                frame_assignments,
                clobbered_registers,
                allow_address_alias=mnemonic == "lea",
                allow_memory_load_alias=mnemonic in {"mov", "movsxd", "movzx"},
            )
            assignments[register] = _Assignment(
                va=va,
                expression=resolved.expression,
                source_text=_instruction_text(instruction),
                alias_depth=resolved.alias_depth,
                alias_kind=resolved.alias_kind,
            )
            clobbered_registers.add(register)
        else:
            written_register = _written_register(mnemonic, operands)
            if written_register is not None:
                assignments.pop(written_register, None)
                clobbered_registers.add(written_register)
        frame_assignment = _frame_slot_assignment(mnemonic, operands)
        if frame_assignment is not None:
            slot, expression = frame_assignment
            resolved = _resolve_expression(
                expression,
                assignments,
                frame_assignments,
                clobbered_registers,
            )
            frame_assignments[slot] = _Assignment(
                va=va,
                expression=resolved.expression,
                source_text=_instruction_text(instruction),
                alias_depth=resolved.alias_depth,
                alias_kind=resolved.alias_kind,
            )
        stack_assignment = _stack_argument_assignment(mnemonic, operands)
        if stack_assignment is not None:
            index, offset, expression = stack_assignment
            resolved = _resolve_expression(
                expression,
                assignments,
                frame_assignments,
                clobbered_registers,
            )
            stack_assignments[index] = _StackAssignment(
                va=va,
                offset=offset,
                expression=resolved.expression,
                source_text=_instruction_text(instruction),
                alias_depth=resolved.alias_depth,
                alias_kind=resolved.alias_kind,
            )

    facts: list[ProjectCallArgumentFact] = []
    for index, (register, role) in enumerate(WINDOWS_X64_ARGS):
        if register not in assignments:
            continue
        assignment = assignments[register]
        facts.append(
            ProjectCallArgumentFact(
                index=index,
                register_name=register,
                role=role,
                expression=assignment.expression,
                source_va=assignment.va,
                source_text=assignment.source_text,
                alias_depth=assignment.alias_depth,
                alias_kind=assignment.alias_kind,
                confidence=_assignment_confidence(
                    assignment.expression,
                    alias_depth=assignment.alias_depth,
                ),
            )
        )
    for index in sorted(stack_assignments):
        assignment = stack_assignments[index]
        facts.append(
            ProjectCallArgumentFact(
                index=index,
                register_name=f"stack+0x{assignment.offset:x}",
                role=f"arg{index}",
                location="stack",
                stack_offset=assignment.offset,
                expression=assignment.expression,
                source_va=assignment.va,
                source_text=assignment.source_text,
                alias_depth=assignment.alias_depth,
                alias_kind=assignment.alias_kind,
                confidence=min(
                    _assignment_confidence(
                        assignment.expression,
                        alias_depth=assignment.alias_depth,
                    ),
                    0.72,
                ),
            )
        )
    return sorted(facts, key=lambda fact: fact.index)


def _register_assignment(mnemonic: str, operands: list[str]) -> tuple[str, str] | None:
    if len(operands) < 2:
        return None
    dst = _canonical_register(operands[0])
    if not _is_register(dst):
        return None
    if mnemonic in {"mov", "movsxd", "movzx", "lea"}:
        return dst, operands[1]
    if mnemonic == "xor" and _canonical_register(operands[1]) == dst:
        return dst, "0"
    return None


def _resolve_expression(
    expression: str,
    assignments: dict[str, _Assignment],
    frame_assignments: dict[str, _Assignment],
    clobbered_registers: set[str],
    *,
    allow_address_alias: bool = False,
    allow_memory_load_alias: bool = False,
) -> _ResolvedExpression:
    source_register = _canonical_register(expression)
    source = assignments.get(source_register)
    if source is not None:
        return _ResolvedExpression(
            expression=source.expression,
            alias_depth=source.alias_depth + 1,
            alias_kind=source.alias_kind or "register",
        )
    incoming_role = WINDOWS_X64_ARG_ROLES.get(source_register)
    if incoming_role is not None and source_register not in clobbered_registers:
        return _ResolvedExpression(
            expression=f"caller_{incoming_role}",
            alias_depth=1,
            alias_kind="incoming_arg",
        )
    if allow_address_alias:
        global_address = _resolve_global_address_expression(expression)
        if global_address is not None:
            return global_address
        address_source = _resolve_address_expression(
            expression,
            assignments,
            clobbered_registers,
        )
        if address_source is not None:
            return address_source
        stack_local = _resolve_stack_local_address(expression)
        if stack_local is not None:
            return stack_local
    if allow_memory_load_alias:
        memory_load = _resolve_memory_load_expression(
            expression,
            assignments,
            clobbered_registers,
        )
        if memory_load is not None:
            return memory_load
    frame_slot = _frame_slot_key(expression)
    if frame_slot is None:
        return _ResolvedExpression(expression=expression)
    frame_source = frame_assignments.get(frame_slot)
    if frame_source is None:
        return _ResolvedExpression(expression=expression)
    return _ResolvedExpression(
        expression=frame_source.expression,
        alias_depth=frame_source.alias_depth + 1,
        alias_kind="frame_slot",
    )


def _resolve_address_expression(
    expression: str,
    assignments: dict[str, _Assignment],
    clobbered_registers: set[str],
) -> _ResolvedExpression | None:
    memory = _simple_memory_expression(expression)
    if memory is None:
        return None
    base_register, displacement = memory
    source = assignments.get(base_register)
    if source is not None:
        base_expression = source.expression
        alias_depth = source.alias_depth + 1
    else:
        incoming_role = WINDOWS_X64_ARG_ROLES.get(base_register)
        if incoming_role is None or base_register in clobbered_registers:
            return None
        base_expression = f"caller_{incoming_role}"
        alias_depth = 1
    return _ResolvedExpression(
        expression=_format_address_expression(base_expression, displacement),
        alias_depth=alias_depth,
        alias_kind="derived_address",
    )


def _resolve_global_address_expression(expression: str) -> _ResolvedExpression | None:
    displacement = _rip_relative_displacement(expression)
    if displacement is None:
        return None
    return _ResolvedExpression(
        expression=f"global({_format_address_expression('rip', displacement)})",
        alias_kind="global_address",
    )


def _resolve_memory_load_expression(
    expression: str,
    assignments: dict[str, _Assignment],
    clobbered_registers: set[str],
) -> _ResolvedExpression | None:
    memory = _simple_memory_expression(expression)
    if memory is None:
        return None
    base_register, displacement = memory
    source = assignments.get(base_register)
    if source is not None:
        if source.alias_kind != "incoming_arg":
            return None
        base_expression = source.expression
        alias_depth = source.alias_depth + 1
    else:
        incoming_role = WINDOWS_X64_ARG_ROLES.get(base_register)
        if incoming_role is None or base_register in clobbered_registers:
            return None
        base_expression = f"caller_{incoming_role}"
        alias_depth = 1
    address_expression = _format_address_expression(base_expression, displacement)
    return _ResolvedExpression(
        expression=f"load({address_expression})",
        alias_depth=alias_depth,
        alias_kind="memory_load",
    )


def _resolve_stack_local_address(expression: str) -> _ResolvedExpression | None:
    memory = _simple_memory_expression(expression)
    if memory is None:
        return None
    base_register, displacement = memory
    if base_register != "rbp" or displacement >= 0:
        return None
    return _ResolvedExpression(
        expression=_format_address_expression(base_register, displacement),
        alias_kind="stack_local_address",
    )


def _rip_relative_displacement(raw: str) -> int | None:
    text = _strip_memory_prefix(raw).replace(" ", "")
    match = re.fullmatch(r"(?:[a-z][a-z0-9]*:)?\[rip([+-][^+\-*]+)?\]", text)
    if not match:
        return None
    displacement_text = match.group(1)
    if displacement_text is None:
        return 0
    try:
        return _parse_int(displacement_text)
    except ValueError:
        return None


def _simple_memory_expression(raw: str) -> tuple[str, int] | None:
    text = _strip_memory_prefix(raw).replace(" ", "")
    match = re.fullmatch(r"(?:[a-z][a-z0-9]*:)?\[([a-z0-9]+)([+-][^+\-*]+)?\]", text)
    if not match:
        return None
    base_register = _canonical_register(match.group(1))
    if not _is_register(base_register):
        return None
    displacement_text = match.group(2)
    if displacement_text is None:
        return base_register, 0
    try:
        displacement = _parse_int(displacement_text)
    except ValueError:
        return None
    return base_register, displacement


def _strip_memory_prefix(raw: str) -> str:
    return re.sub(
        r"\b(?:byte|word|dword|qword|oword|xmmword)\s+ptr\s+",
        "",
        raw.lower().strip(),
    )


def _format_address_expression(base_expression: str, displacement: int) -> str:
    if displacement == 0:
        return f"[{base_expression}]"
    sign = "+" if displacement > 0 else "-"
    return f"[{base_expression} {sign} 0x{abs(displacement):x}]"


def _written_register(mnemonic: str, operands: list[str]) -> str | None:
    if not operands:
        return None
    if mnemonic not in {
        "add",
        "and",
        "dec",
        "imul",
        "inc",
        "lea",
        "mov",
        "movsxd",
        "movzx",
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
    register = _canonical_register(operands[0])
    return register if _is_register(register) else None


def _frame_slot_assignment(
    mnemonic: str,
    operands: list[str],
) -> tuple[str, str] | None:
    if mnemonic != "mov" or len(operands) < 2:
        return None
    slot = _frame_slot_key(operands[0])
    if slot is None:
        return None
    return slot, operands[1]


def _frame_slot_key(raw: str) -> str | None:
    text = _strip_memory_prefix(raw)
    text = text.replace(" ", "")
    match = re.fullmatch(r"\[rbp([+-].+)?\]", text)
    if not match:
        return None
    displacement = match.group(1)
    if not displacement:
        return "rbp+0x0"
    try:
        offset = _parse_int(displacement)
    except ValueError:
        return None
    sign = "+" if offset >= 0 else "-"
    return f"rbp{sign}0x{abs(offset):x}"


def _stack_argument_assignment(
    mnemonic: str,
    operands: list[str],
) -> tuple[int, int, str] | None:
    if mnemonic != "mov" or len(operands) < 2:
        return None
    offset = _stack_arg_offset(operands[0])
    if offset is None:
        return None
    index = 4 + ((offset - WINDOWS_X64_STACK_ARG_BASE) // WINDOWS_X64_STACK_ARG_SLOT)
    return index, offset, operands[1]


def _stack_arg_offset(raw: str) -> int | None:
    text = _strip_memory_prefix(raw)
    text = text.replace(" ", "")
    match = re.fullmatch(r"\[(rsp|esp)([+-].+)?\]", text)
    if not match:
        return None
    displacement = match.group(2)
    if not displacement:
        offset = 0
    else:
        try:
            offset = _parse_int(displacement)
        except ValueError:
            return None
    if offset < WINDOWS_X64_STACK_ARG_BASE:
        return None
    if offset > WINDOWS_X64_MAX_STACK_ARG_OFFSET:
        return None
    if (offset - WINDOWS_X64_STACK_ARG_BASE) % WINDOWS_X64_STACK_ARG_SLOT:
        return None
    return offset


def _parse_int(text: str) -> int:
    sign = 1
    if text.startswith("+"):
        text = text[1:]
    elif text.startswith("-"):
        sign = -1
        text = text[1:]
    if text.endswith("h") and not text.startswith("0x"):
        return sign * int(text[:-1], 16)
    return sign * int(text, 0)


def _canonical_register(raw: str) -> str:
    text = _strip_memory_prefix(raw)
    aliases = {
        "rax": "rax",
        "eax": "rax",
        "ax": "rax",
        "al": "rax",
        "ah": "rax",
        "rbx": "rbx",
        "ebx": "rbx",
        "bx": "rbx",
        "bl": "rbx",
        "bh": "rbx",
        "rcx": "rcx",
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "ch": "rcx",
        "rdx": "rdx",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "dh": "rdx",
        "rsi": "rsi",
        "esi": "rsi",
        "si": "rsi",
        "sil": "rsi",
        "rdi": "rdi",
        "edi": "rdi",
        "di": "rdi",
        "dil": "rdi",
        "rbp": "rbp",
        "ebp": "rbp",
        "bp": "rbp",
        "bpl": "rbp",
        "rsp": "rsp",
        "esp": "rsp",
        "sp": "rsp",
        "spl": "rsp",
        "r8": "r8",
        "r8d": "r8",
        "r8w": "r8",
        "r8b": "r8",
        "r9": "r9",
        "r9d": "r9",
        "r9w": "r9",
        "r9b": "r9",
        "r10": "r10",
        "r10d": "r10",
        "r10w": "r10",
        "r10b": "r10",
        "r11": "r11",
        "r11d": "r11",
        "r11w": "r11",
        "r11b": "r11",
        "r12": "r12",
        "r12d": "r12",
        "r12w": "r12",
        "r12b": "r12",
        "r13": "r13",
        "r13d": "r13",
        "r13w": "r13",
        "r13b": "r13",
        "r14": "r14",
        "r14d": "r14",
        "r14w": "r14",
        "r14b": "r14",
        "r15": "r15",
        "r15d": "r15",
        "r15w": "r15",
        "r15b": "r15",
    }
    return aliases.get(text, text)


def _is_register(text: str) -> bool:
    return text in {
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    }


def _instruction_text(instruction: g.Instruction) -> str:
    operands = ", ".join(str(op) for op in getattr(instruction, "operands", []) or [])
    return f"{instruction.mnemonic} {operands}".strip()


def _assignment_confidence(expression: str, *, alias_depth: int = 0) -> float:
    if expression == "0" or expression.lower().startswith(("0x", "-0x")):
        base = 0.82
    elif expression.startswith("[") or " ptr " in expression.lower():
        base = 0.7
    else:
        base = 0.76
    if alias_depth:
        return max(0.55, base - (0.04 * alias_depth))
    return base


def _coverage(
    row: dict[str, Any],
    instructions: list[g.Instruction],
    arguments: list[ProjectCallArgumentFact],
) -> list[str]:
    coverage: list[str] = ["project_call_xref"]
    if row.get("caller_name") or row.get("callee_name"):
        coverage.append("function_names")
    if instructions:
        coverage.append("nearby_disassembly")
    if any(arg.location == "register" for arg in arguments):
        coverage.append("windows_x64_register_arguments")
    if any(arg.location == "stack" for arg in arguments):
        coverage.append("windows_x64_stack_arguments")
    if any(arg.alias_kind == "register" for arg in arguments):
        coverage.append("simple_register_aliases")
    if any(arg.alias_kind == "incoming_arg" for arg in arguments):
        coverage.append("incoming_argument_aliases")
    if any(arg.alias_kind == "frame_slot" for arg in arguments):
        coverage.append("simple_spill_reload_aliases")
    if any(arg.alias_kind == "derived_address" for arg in arguments):
        coverage.append("derived_address_arguments")
    if any(arg.alias_kind == "stack_local_address" for arg in arguments):
        coverage.append("stack_local_address_arguments")
    if any(arg.alias_kind == "memory_load" for arg in arguments):
        coverage.append("memory_load_arguments")
    if any(arg.alias_kind == "global_address" for arg in arguments):
        coverage.append("global_address_arguments")
    return coverage


def _missing_capabilities(
    row: dict[str, Any],
    instructions: list[g.Instruction],
    arguments: list[ProjectCallArgumentFact],
) -> list[str]:
    missing: list[str] = []
    if not row.get("caller_name") or not row.get("callee_name"):
        missing.append("function_names")
    if not instructions:
        missing.append("nearby_disassembly")
    register_arguments = [arg for arg in arguments if arg.location == "register"]
    if len(register_arguments) < len(WINDOWS_X64_ARGS):
        missing.append("all_register_arguments")
    if not any(arg.location == "stack" for arg in arguments):
        missing.append("stack_arguments")
    missing.append("full_alias_tracking")
    missing.append("cfg_path_conditions")
    return missing


def build_tool() -> MemoryTool[
    WindowsProjectCallArgumentSnapshotArgs,
    WindowsProjectCallArgumentSnapshotResult,
]:
    return WindowsProjectCallArgumentSnapshotTool()
