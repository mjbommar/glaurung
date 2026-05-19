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
from .windows_project_call_argument_snapshot import (
    _canonical_register,
    _first_binary_id,
    _instruction_text,
    _is_register,
    _parse_int,
    _present_tables,
    _strip_memory_prefix,
)


class WindowsProjectMemoryOperandFactsArgs(BaseModel):
    binary_path: str = Field(..., description="Path to the PE binary backing the project.")
    project_path: str = Field(..., description="Path to a .glaurung SQLite project.")
    function_va: int = Field(..., description="Function entry VA to inspect.")
    binary_id: int | None = Field(None, description="Optional binary_id filter.")
    max_window_bytes: int = Field(
        4096,
        ge=16,
        description="Maximum bytes to disassemble from the function entry.",
    )
    max_instructions: int = Field(
        512,
        ge=1,
        description="Maximum instructions to inspect from the function entry.",
    )
    max_facts: int = Field(256, ge=0, le=4096, description="Maximum facts to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact memory-operand evidence node to the KB.",
    )


class ProjectMemoryOperandFact(BaseModel):
    function_va: int
    function_name: str | None = None
    instruction_va: int
    instruction_text: str
    mnemonic: str
    operand_index: int
    operand_text: str
    access_kind: str
    width_bytes: int | None = None
    address_expression: str
    base_register: str | None = None
    index_register: str | None = None
    scale: int | None = None
    displacement: int = 0
    role_hint: str = "memory"
    data_target_va: int | None = None
    data_target_kind: str | None = None
    data_target_name: str | None = None
    data_target_type: str | None = None
    data_target_size: int | None = None


class WindowsProjectMemoryOperandFactsResult(BaseModel):
    binary_path: str
    project_path: str
    binary_id: int | None = None
    function_va: int
    function_name: str | None = None
    scanned_instruction_count: int
    returned_fact_count: int
    facts: list[ProjectMemoryOperandFact]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class _DataTarget:
    va: int
    kind: str
    name: str | None = None
    c_type: str | None = None
    size: int | None = None


@dataclass(frozen=True)
class _MemoryOperand:
    operand_text: str
    width_bytes: int | None
    address_expression: str
    base_register: str | None
    index_register: str | None
    scale: int | None
    displacement: int


class WindowsProjectMemoryOperandFactsTool(
    MemoryTool[
        WindowsProjectMemoryOperandFactsArgs,
        WindowsProjectMemoryOperandFactsResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_memory_operand_facts",
                description=(
                    "Extract conservative native memory operand facts for one "
                    "Windows PE project function, including access kind, width, "
                    "address expression, stack/global hints, and data-label joins."
                ),
                tags=("windows", "pe", "project", "memory", "operands"),
            ),
            WindowsProjectMemoryOperandFactsArgs,
            WindowsProjectMemoryOperandFactsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectMemoryOperandFactsArgs,
    ) -> WindowsProjectMemoryOperandFactsResult:
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
            function_name = _function_name(conn, present, binary_id, args.function_va)
            data_targets = _data_xref_targets(conn, present, binary_id, args.function_va)
        finally:
            conn.close()

        instructions = _disassemble_function(binary_path, args)
        facts = _memory_operand_facts(
            instructions,
            args.function_va,
            function_name,
            data_targets,
        )[: args.max_facts]
        coverage = _coverage(facts)
        missing = _missing_capabilities(facts)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_memory_operand_facts",
                    props={
                        "binary_path": str(binary_path),
                        "project_path": str(project_path),
                        "function_va": args.function_va,
                        "function_name": function_name,
                        "fact_count": len(facts),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectMemoryOperandFactsResult(
            binary_path=str(binary_path),
            project_path=str(project_path),
            binary_id=binary_id,
            function_va=args.function_va,
            function_name=function_name,
            scanned_instruction_count=len(instructions),
            returned_fact_count=len(facts),
            facts=facts,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "memory operand facts are local instruction facts; type layouts, "
                "aliasing, field names, and path-sensitive value flow need separate facts"
            ],
        )


def _function_name(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_va: int,
) -> str | None:
    if "function_names" not in present:
        return None
    clauses = ["entry_va = ?"]
    params: list[object] = [function_va]
    if binary_id is not None:
        clauses.append("binary_id = ?")
        params.append(binary_id)
    row = conn.execute(
        f"SELECT canonical FROM function_names WHERE {' AND '.join(clauses)} LIMIT 1",
        params,
    ).fetchone()
    return str(row[0]) if row else None


def _data_xref_targets(
    conn: sqlite3.Connection,
    present: set[str],
    binary_id: int | None,
    function_va: int,
) -> dict[int, _DataTarget]:
    if "xrefs" not in present:
        return {}
    clauses = [
        "x.kind IN ('data_read', 'data_write')",
        "x.src_function_va = ?",
    ]
    params: list[object] = [function_va]
    if binary_id is not None:
        clauses.append("x.binary_id = ?")
        params.append(binary_id)
    if "data_labels" in present:
        query = f"""
SELECT x.src_va, x.dst_va, x.kind, dl.name, dl.c_type, dl.size
FROM xrefs x
LEFT JOIN data_labels dl ON dl.binary_id = x.binary_id AND dl.va = x.dst_va
WHERE {' AND '.join(clauses)}
ORDER BY x.src_va, x.xref_id
"""
    else:
        query = f"""
SELECT x.src_va, x.dst_va, x.kind, NULL AS name, NULL AS c_type, NULL AS size
FROM xrefs x
WHERE {' AND '.join(clauses)}
ORDER BY x.src_va, x.xref_id
"""
    out: dict[int, _DataTarget] = {}
    for src_va, dst_va, kind, name, c_type, size in conn.execute(query, params):
        out.setdefault(
            int(src_va),
            _DataTarget(
                va=int(dst_va),
                kind=str(kind),
                name=str(name) if name is not None else None,
                c_type=str(c_type) if c_type is not None else None,
                size=int(size) if size is not None else None,
            ),
        )
    return out


def _disassemble_function(
    binary_path: Path,
    args: WindowsProjectMemoryOperandFactsArgs,
) -> list[g.Instruction]:
    try:
        return list(
            g.disasm.disassemble_window_at(
                str(binary_path),
                args.function_va,
                window_bytes=args.max_window_bytes,
                max_instructions=args.max_instructions,
            )
        )
    except Exception:
        return []


def _memory_operand_facts(
    instructions: list[g.Instruction],
    function_va: int,
    function_name: str | None,
    data_targets: dict[int, _DataTarget],
) -> list[ProjectMemoryOperandFact]:
    facts: list[ProjectMemoryOperandFact] = []
    for instruction in instructions:
        mnemonic = str(instruction.mnemonic or "").lower()
        operands = [str(op).strip() for op in getattr(instruction, "operands", []) or []]
        for index, operand in enumerate(operands):
            memory = _parse_memory_operand(operand)
            if memory is None:
                continue
            access_kind = _access_kind(mnemonic, index)
            if access_kind is None:
                continue
            data_target = data_targets.get(int(instruction.address.value))
            facts.append(
                ProjectMemoryOperandFact(
                    function_va=function_va,
                    function_name=function_name,
                    instruction_va=int(instruction.address.value),
                    instruction_text=_instruction_text(instruction),
                    mnemonic=mnemonic,
                    operand_index=index,
                    operand_text=operand,
                    access_kind=access_kind,
                    width_bytes=memory.width_bytes,
                    address_expression=memory.address_expression,
                    base_register=memory.base_register,
                    index_register=memory.index_register,
                    scale=memory.scale,
                    displacement=memory.displacement,
                    role_hint=_role_hint(memory, data_target),
                    data_target_va=data_target.va if data_target else None,
                    data_target_kind=data_target.kind if data_target else None,
                    data_target_name=data_target.name if data_target else None,
                    data_target_type=data_target.c_type if data_target else None,
                    data_target_size=data_target.size if data_target else None,
                )
            )
    return facts


def _parse_memory_operand(raw: str) -> _MemoryOperand | None:
    if "[" not in raw or "]" not in raw:
        return None
    width = _width_bytes(raw)
    text = _strip_memory_prefix(raw)
    match = re.search(r"\[([^\]]+)\]", text)
    if not match:
        return None
    body = match.group(1).replace(" ", "").lower()
    terms = re.sub(r"(?<!^)-", "+-", body).split("+")
    base_register: str | None = None
    index_register: str | None = None
    scale: int | None = None
    displacement = 0
    for term in terms:
        if not term:
            continue
        if "*" in term:
            register_text, scale_text = term.split("*", 1)
            register = _canonical_register(register_text)
            if not _is_memory_register(register):
                return None
            try:
                parsed_scale = _parse_int(scale_text)
            except ValueError:
                return None
            index_register = register
            scale = parsed_scale
            continue
        register = _canonical_register(term)
        if _is_memory_register(register):
            if base_register is None:
                base_register = register
            elif index_register is None:
                index_register = register
                scale = 1
            else:
                return None
            continue
        try:
            displacement += _parse_int(term)
        except ValueError:
            return None
    if base_register is None and index_register is None:
        return None
    return _MemoryOperand(
        operand_text=raw,
        width_bytes=width,
        address_expression=_format_address_expression(
            base_register,
            index_register,
            scale,
            displacement,
        ),
        base_register=base_register,
        index_register=index_register,
        scale=scale,
        displacement=displacement,
    )


def _width_bytes(raw: str) -> int | None:
    text = raw.lower()
    for label, width in (
        ("xmmword ptr", 16),
        ("oword ptr", 16),
        ("qword ptr", 8),
        ("dword ptr", 4),
        ("word ptr", 2),
        ("byte ptr", 1),
    ):
        if label in text:
            return width
    return None


def _is_memory_register(register: str) -> bool:
    return register == "rip" or _is_register(register)


def _format_address_expression(
    base_register: str | None,
    index_register: str | None,
    scale: int | None,
    displacement: int,
) -> str:
    parts: list[str] = []
    if base_register is not None:
        parts.append(base_register)
    if index_register is not None:
        if scale and scale != 1:
            parts.append(f"{index_register}*{scale}")
        else:
            parts.append(index_register)
    expression = " + ".join(parts)
    if displacement:
        sign = "+" if displacement > 0 else "-"
        disp = f"0x{abs(displacement):x}"
        expression = f"{expression} {sign} {disp}" if expression else f"{sign}{disp}"
    return f"[{expression}]"


def _access_kind(mnemonic: str, operand_index: int) -> str | None:
    if mnemonic == "lea":
        return None
    if operand_index > 0:
        return "read"
    if mnemonic in {"cmp", "test", "call", "jmp", "push"}:
        return "read"
    if mnemonic == "pop":
        return "write"
    if mnemonic in {"mov", "movdqu", "movups", "movaps", "stos", "stosb", "stosd", "stosq"}:
        return "write"
    if mnemonic in {
        "adc",
        "add",
        "and",
        "dec",
        "inc",
        "lock",
        "neg",
        "not",
        "or",
        "sbb",
        "sub",
        "xadd",
        "xchg",
        "xor",
    }:
        return "read_write"
    return "write"


def _role_hint(memory: _MemoryOperand, data_target: _DataTarget | None) -> str:
    if data_target is not None or memory.base_register == "rip":
        return "global_data"
    if memory.base_register == "rbp" and memory.displacement < 0:
        return "stack_local"
    if memory.base_register == "rsp" and memory.displacement >= 0x20:
        return "stack_argument"
    if memory.base_register in {"rbp", "rsp"}:
        return "stack"
    if memory.displacement:
        return "field_access"
    return "memory"


def _coverage(facts: list[ProjectMemoryOperandFact]) -> list[str]:
    coverage: list[str] = []
    if facts:
        coverage.append("native_memory_operand_facts")
    if any(fact.width_bytes is not None for fact in facts):
        coverage.append("memory_operand_widths")
    if any(fact.access_kind == "read" for fact in facts):
        coverage.append("memory_read_operands")
    if any(fact.access_kind == "write" for fact in facts):
        coverage.append("memory_write_operands")
    if any(fact.access_kind == "read_write" for fact in facts):
        coverage.append("memory_read_write_operands")
    if any(fact.role_hint.startswith("stack") for fact in facts):
        coverage.append("stack_memory_operands")
    if any(fact.role_hint == "global_data" for fact in facts):
        coverage.append("global_memory_operands")
    if any(fact.role_hint == "field_access" for fact in facts):
        coverage.append("field_like_memory_operands")
    if any(fact.data_target_va is not None for fact in facts):
        coverage.append("project_data_xref_targets")
    if any(fact.data_target_name for fact in facts):
        coverage.append("project_data_label_targets")
    return coverage


def _missing_capabilities(facts: list[ProjectMemoryOperandFact]) -> list[str]:
    missing = [
        "type_layout_field_names",
        "full_memory_alias_tracking",
        "path_sensitive_memory_state",
        "persisted_project_memory_operand_table",
    ]
    if not facts:
        missing.append("native_memory_operand_facts")
    if any(fact.width_bytes is None for fact in facts):
        missing.append("complete_memory_operand_widths")
    return missing


def build_tool() -> WindowsProjectMemoryOperandFactsTool:
    return WindowsProjectMemoryOperandFactsTool()
