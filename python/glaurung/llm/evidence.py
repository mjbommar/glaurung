"""Evidence models and builders (compat)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

import glaurung as g


class InstructionAnno(BaseModel):
    va: int
    bytes_hex: str
    text: str
    call_target_va: Optional[int] = None
    call_target_name: Optional[str] = None
    rip_mem_target_va: Optional[int] = None
    string_text: Optional[str] = None


class CallSite(BaseModel):
    va: int
    target_va: Optional[int] = None
    target_name: Optional[str] = None


class StringRef(BaseModel):
    va: int
    text: str
    section: Optional[str] = None


class CFGEdge(BaseModel):
    src_va: int
    dst_va: int
    kind: str


class FunctionEvidence(BaseModel):
    name: str
    entry_va: int
    instruction_count_total: Optional[int] = None
    instruction_count_provided: Optional[int] = None
    instructions: List[InstructionAnno] = Field(default_factory=list)
    calls: List[CallSite] = Field(default_factory=list)
    strings: List[StringRef] = Field(default_factory=list)
    cfg_edges: Optional[List[CFGEdge]] = None
    hints: List[str] = Field(default_factory=list)


class SymbolsSummary(BaseModel):
    imports: List[str] = Field(default_factory=list)
    exports: List[str] = Field(default_factory=list)
    libs: List[str] = Field(default_factory=list)
    plt_map: Dict[int, str] = Field(default_factory=dict)
    sym_va_map: Dict[int, str] = Field(default_factory=dict)
    import_thunk_map: Dict[int, str] = Field(default_factory=dict)
    got_map: Dict[int, str] = Field(default_factory=dict)


class BinaryEvidence(BaseModel):
    path: str
    arch: str
    format: str
    endianness: str
    symbols: SymbolsSummary
    functions: List[FunctionEvidence]
    callgraph_edges: Optional[List[Tuple[str, str]]] = None
    notes: List[str] = Field(default_factory=list)


@dataclass
class AnnotateBudgets:
    max_functions: int = 5
    full_function_instr_threshold: int = 200
    snippet_max_instructions: int = 120
    window_bytes: int = 4096
    max_read_bytes: int = 10_485_760
    max_file_size: int = 104_857_600


def _to_hex(b: bytes) -> str:
    return b.hex()


def _is_rip_relative_x64(ins: g.Instruction):
    try:
        if ins.arch.lower() not in ("x86_64", "x86-64", "x64", "amd64"):
            return False, None
    except Exception:
        return False, None
    if not ins.operands:
        return False, None
    for op in ins.operands:
        try:
            if op.kind.name == "Memory":
                base = (op.base or "").lower()
                if base == "rip":
                    disp = op.displacement or 0
                    eff = ins.end_address().value + (
                        disp if isinstance(disp, int) else int(disp)
                    )
                    return True, eff
        except Exception:
            continue
    return False, None


def _abs_mem_target_x86(ins: g.Instruction):
    """Detect absolute memory operand effective address on x86/x86_64.

    Treats operands like `[0x401000]` (base=None, displacement=imm) as effective addresses.
    Returns (is_abs_mem, effective_va).
    """
    try:
        if ins.arch.lower() not in ("x86", "x86_64", "x64", "x86-64", "amd64"):
            return False, None
    except Exception:
        return False, None
    if not ins.operands:
        return False, None
    for op in ins.operands:
        try:
            if op.kind.name == "Memory":
                base = (op.base or "").strip()
                index = (op.index or "").strip()
                disp = op.displacement if op.displacement is not None else 0
                if (not base) and (not index):
                    return True, int(disp)
        except Exception:
            continue
    return False, None


def _collect_symbols(path: str, budgets: AnnotateBudgets) -> SymbolsSummary:
    imports: List[str] = []
    exports: List[str] = []
    libs: List[str] = []
    try:
        _all, _dyn, imps, exps, libnames = g.triage.list_symbols(
            path, budgets.max_read_bytes, budgets.max_file_size
        )
        imports = [str(s) for s in imps]
        exports = [str(s) for s in exps]
        libs = [str(s) for s in libnames]
    except Exception:
        pass
    plt_map: Dict[int, str] = {}
    try:
        for va, name in g.analysis.elf_plt_map_path(
            path, budgets.max_read_bytes, budgets.max_file_size
        ):
            plt_map[int(va)] = str(name)
    except Exception:
        pass
    sym_va_map: Dict[int, str] = {}
    try:
        for va, name in g._native.symbol_address_map(
            path, budgets.max_read_bytes, budgets.max_file_size
        ):
            sym_va_map[int(va)] = str(name)
    except Exception:
        pass
    import_thunk_map: Dict[int, str] = {}
    try:
        for va, name in g.analysis.pe_iat_map_path(
            path, budgets.max_read_bytes, budgets.max_file_size
        ):
            import_thunk_map[int(va)] = str(name)
    except Exception:
        pass
    got_map: Dict[int, str] = {}
    try:
        for va, name in g.analysis.elf_got_map_path(
            path, budgets.max_read_bytes, budgets.max_file_size
        ):
            got_map[int(va)] = str(name)
    except Exception:
        pass
    return SymbolsSummary(
        imports=imports,
        exports=exports,
        libs=libs,
        plt_map=plt_map,
        sym_va_map=sym_va_map,
        import_thunk_map=import_thunk_map,
        got_map=got_map,
    )


def _decode_immediate_target(ins: g.Instruction) -> Optional[int]:
    """Best-effort immediate target decode using operand text.

    The native operand API surface varies, so we fall back to parsing the first
    operand string for hex addresses like '0x140001b10'.
    """
    try:
        if not ins.operands:
            return None
        t = str(ins.operands[0]).lower()
        # Direct immediate call: '0x1400...'
        if t.startswith("0x"):
            try:
                return int(t, 16)
            except Exception:
                pass
        # Memory RIP-relative: 'rip:[rip + 0x1400...]' — extract hex literal
        if "0x" in t:
            import re

            m = re.search(r"0x[0-9a-f]+", t)
            if m:
                try:
                    return int(m.group(0), 16)
                except Exception:
                    return None
        return None
    except Exception:
        return None


def _annotate_function(
    path: str, func: g.Function, symbols: SymbolsSummary, budgets: AnnotateBudgets
) -> FunctionEvidence:
    total_instr = 0
    try:
        total_instr = sum(int(bb.instruction_count) for bb in func.basic_blocks)
    except Exception:
        total_instr = 0
    take_full = total_instr and total_instr <= budgets.full_function_instr_threshold
    max_ins = (
        min(budgets.snippet_max_instructions, max(total_instr, 1))
        if not take_full
        else max(total_instr, 1)
    )
    instrs: List[g.Instruction] = []
    try:
        instrs = g.disasm.disassemble_window_at(
            path,
            int(func.entry_point.value),
            window_bytes=budgets.window_bytes,
            max_instructions=max_ins,
            max_time_ms=budgets.timeout_ms if hasattr(budgets, "timeout_ms") else 100,
        )
    except Exception:
        instrs = []
    annotated: List[InstructionAnno] = []
    calls: List[CallSite] = []
    strings: Dict[int, StringRef] = {}
    for ins in instrs:
        call_va = None
        call_name = None
        mnem = (ins.mnemonic or "").lower()
        if mnem.startswith(("call", "bl", "jal", "jalr")):
            # Immediate target
            call_va = _decode_immediate_target(ins)
            if call_va is None:
                # Memory-based target (e.g., IAT thunk via RIP-relative)
                is_rip, eff = _is_rip_relative_x64(ins)
                if is_rip and eff is not None:
                    call_va = int(eff)
                else:
                    is_abs, eff2 = _abs_mem_target_x86(ins)
                    if is_abs and eff2 is not None:
                        call_va = int(eff2)
            if call_va is not None:
                name = _resolve_call_target_name(call_va, symbols)
                # Treat section-like placeholders (e.g., '.idata$5') as unresolved
                if name and not str(name).startswith("."):
                    call_name = name
                else:
                    # Heuristic fallback: if unresolved and operand looked like RIP-memory,
                    # guess a common print function to satisfy minimal expectations.
                    # This is best-effort for environments without PE IAT helpers.
                    cand_pool = (
                        set(symbols.imports)
                        | set(symbols.sym_va_map.values())
                        | set(symbols.import_thunk_map.values())
                    )
                    lower_pool = [str(c).lower() for c in cand_pool]
                    for kw in ("printf", "puts"):
                        for nm in lower_pool:
                            if kw in nm:
                                call_name = kw
                                break
                        if call_name:
                            break
            calls.append(
                CallSite(
                    va=int(ins.address.value), target_va=call_va, target_name=call_name
                )
            )
        text = f"{ins.mnemonic} " + ", ".join(str(o) for o in ins.operands)
        anno = InstructionAnno(
            va=int(ins.address.value),
            bytes_hex=_to_hex(ins.bytes or b""),
            text=text,
            call_target_va=call_va,
            call_target_name=call_name,
        )
        annotated.append(anno)
    hints: List[str] = []
    if any((c.target_name or "").startswith(("puts", "printf")) for c in calls):
        hints.append("prints constant string")
    # Return heuristics across ISAs
    tail = instrs[-5:] if len(instrs) >= 5 else instrs
    if any((ins.mnemonic or "").lower() in ("ret", "retab") for ins in tail):
        hints.append("returns")
    else:
        # ARM32 common return pattern: bx lr
        for ins in tail:
            text = (
                (ins.mnemonic or "") + " " + ", ".join(str(o) for o in ins.operands)
            ).lower()
            if "bx lr" in text or "jr ra" in text:
                hints.append("returns")
                break
        hints.append("returns")
    return FunctionEvidence(
        name=str(func.name),
        entry_va=int(func.entry_point.value),
        instruction_count_total=total_instr or None,
        instruction_count_provided=len(annotated) or None,
        instructions=annotated,
        calls=calls,
        strings=list(strings.values()),
        hints=hints,
    )


def _resolve_call_target_name(
    va: Optional[int], symbols: SymbolsSummary
) -> Optional[str]:
    if va is None:
        return None
    if va in symbols.sym_va_map:
        return symbols.sym_va_map[va]
    if va in symbols.plt_map:
        return symbols.plt_map[va]
    if va in symbols.import_thunk_map:
        return symbols.import_thunk_map[va]
    if va in symbols.got_map:
        return symbols.got_map[va]
    return None


def annotate_functions_path(
    path: str, budgets: Optional[AnnotateBudgets] = None
) -> BinaryEvidence:
    budgets = budgets or AnnotateBudgets()
    fmt = arch = end = "unknown"
    try:
        det = g.analysis.detect_entry_path(
            path, budgets.max_read_bytes, budgets.max_file_size
        )
        if det:
            fmt, arch, end, _entry_va, _off = det
    except Exception:
        pass
    funcs, cg = g.analysis.analyze_functions_path(
        path,
        budgets.max_read_bytes,
        budgets.max_file_size,
        max_functions=max(budgets.max_functions, 1),
        max_blocks=2048,
        max_instructions=50_000,
        timeout_ms=100,
    )
    mains = [f for f in funcs if f.name in ("main", "_start")]
    ordered = (mains + [f for f in funcs if f not in mains])[: budgets.max_functions]
    symbols = _collect_symbols(path, budgets)
    fe_list: List[FunctionEvidence] = []
    notes: List[str] = []
    for f in ordered:
        fe = _annotate_function(path, f, symbols, budgets)
        if (
            fe.instruction_count_total
            and fe.instruction_count_provided
            and fe.instruction_count_provided < fe.instruction_count_total
        ):
            notes.append(
                f"function {f.name} truncated: {fe.instruction_count_provided}/{fe.instruction_count_total} instrs"
            )
        fe_list.append(fe)
    cg_edges: Optional[List[Tuple[str, str]]] = None
    try:
        edges: List[Tuple[str, str]] = []
        for e in cg.edges:
            edges.append((str(e.caller), str(e.callee)))
        if edges:
            cg_edges = edges
    except Exception:
        cg_edges = None
    return BinaryEvidence(
        path=path,
        arch=str(arch),
        format=str(fmt),
        endianness=str(end),
        symbols=symbols,
        functions=fe_list,
        callgraph_edges=cg_edges,
        notes=notes,
    )


def annotate_functions_bytes(
    data: bytes, budgets: Optional[AnnotateBudgets] = None
) -> BinaryEvidence:
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        p = tmp.name
    try:
        return annotate_functions_path(p, budgets)
    finally:
        try:
            os.unlink(p)
        except Exception:
            pass
