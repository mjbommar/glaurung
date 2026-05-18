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


WINDOWS_X64_ARGS = (("rcx", "arg0"), ("rdx", "arg1"), ("r8", "arg2"), ("r9", "arg3"))
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
                "argument snapshot is local and conservative; aliases, non-obvious "
                "stack arguments, and path conditions need IR/CFG facts"
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
    assignments: dict[str, tuple[int, str, str]] = {}
    stack_assignments: dict[int, tuple[int, int, str, str]] = {}
    for instruction in instructions:
        va = int(instruction.address.value)
        mnemonic = str(instruction.mnemonic or "").lower()
        operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
        if va == callsite_va:
            break
        if mnemonic == "call":
            assignments.clear()
            stack_assignments.clear()
            continue
        assignment = _register_assignment(mnemonic, operands)
        if assignment is not None:
            register, expression = assignment
            assignments[register] = (va, expression, _instruction_text(instruction))
        stack_assignment = _stack_argument_assignment(mnemonic, operands)
        if stack_assignment is not None:
            index, offset, expression = stack_assignment
            stack_assignments[index] = (
                va,
                offset,
                expression,
                _instruction_text(instruction),
            )

    facts: list[ProjectCallArgumentFact] = []
    for index, (register, role) in enumerate(WINDOWS_X64_ARGS):
        if register not in assignments:
            continue
        source_va, expression, source_text = assignments[register]
        facts.append(
            ProjectCallArgumentFact(
                index=index,
                register_name=register,
                role=role,
                expression=expression,
                source_va=source_va,
                source_text=source_text,
                confidence=_assignment_confidence(expression),
            )
        )
    for index in sorted(stack_assignments):
        source_va, offset, expression, source_text = stack_assignments[index]
        facts.append(
            ProjectCallArgumentFact(
                index=index,
                register_name=f"stack+0x{offset:x}",
                role=f"arg{index}",
                location="stack",
                stack_offset=offset,
                expression=expression,
                source_va=source_va,
                source_text=source_text,
                confidence=min(_assignment_confidence(expression), 0.72),
            )
        )
    return sorted(facts, key=lambda fact: fact.index)


def _register_assignment(mnemonic: str, operands: list[str]) -> tuple[str, str] | None:
    if len(operands) < 2:
        return None
    dst = _canonical_register(operands[0])
    if dst not in {reg for reg, _role in WINDOWS_X64_ARGS}:
        return None
    if mnemonic in {"mov", "movsxd", "movzx", "lea"}:
        return dst, operands[1]
    if mnemonic == "xor" and _canonical_register(operands[1]) == dst:
        return dst, "0"
    return None


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
    text = raw.lower().strip()
    text = re.sub(r"\b(?:byte|word|dword|qword|oword|xmmword)\s+ptr\s+", "", text)
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
    text = raw.lower().strip()
    text = text.removeprefix("qword ptr ").removeprefix("dword ptr ")
    aliases = {
        "rcx": "rcx",
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "rdx": "rdx",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "r8": "r8",
        "r8d": "r8",
        "r8w": "r8",
        "r8b": "r8",
        "r9": "r9",
        "r9d": "r9",
        "r9w": "r9",
        "r9b": "r9",
    }
    return aliases.get(text, text)


def _instruction_text(instruction: g.Instruction) -> str:
    operands = ", ".join(str(op) for op in getattr(instruction, "operands", []) or [])
    return f"{instruction.mnemonic} {operands}".strip()


def _assignment_confidence(expression: str) -> float:
    if expression == "0" or expression.lower().startswith(("0x", "-0x")):
        return 0.82
    if expression.startswith("[") or " ptr " in expression.lower():
        return 0.7
    return 0.76


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
    missing.append("alias_tracking")
    missing.append("cfg_path_conditions")
    return missing


def build_tool() -> MemoryTool[
    WindowsProjectCallArgumentSnapshotArgs,
    WindowsProjectCallArgumentSnapshotResult,
]:
    return WindowsProjectCallArgumentSnapshotTool()
