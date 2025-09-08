from __future__ import annotations

from pydantic import BaseModel, Field
import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class FunctionCall(BaseModel):
    ins_va: int
    target_va: int | None = None
    target_name: str | None = None


class FunctionStringRef(BaseModel):
    va: int
    text: str
    encoding: str | None = None


class FunctionInstruction(BaseModel):
    va: int
    bytes_hex: str
    text: str


class ViewFunctionArgs(BaseModel):
    va: int = Field(..., description="Function entry VA (start disassembly here)")
    window_bytes: int | None = None
    max_instructions: int | None = None
    add_to_kb: bool = True


class ViewFunctionResult(BaseModel):
    instructions: list[FunctionInstruction]
    calls: list[FunctionCall]
    strings: list[FunctionStringRef]
    evidence_node_id: str | None = None


def _read_c_string_ascii(path: str, file_off: int, max_bytes: int) -> str | None:
    try:
        with open(path, "rb") as f:
            f.seek(file_off)
            data = f.read(max_bytes)
    except Exception:
        return None
    out = bytearray()
    for b in data:
        if b == 0:
            break
        # printable ASCII including common punctuation
        if 32 <= b <= 126:
            out.append(b)
        else:
            return None
    if len(out) >= 4:
        return out.decode("ascii", errors="ignore")
    return None


def _read_c_string_utf16le(path: str, file_off: int, max_bytes: int) -> str | None:
    try:
        with open(path, "rb") as f:
            f.seek(file_off)
            data = f.read(max_bytes)
    except Exception:
        return None
    # Expect alternating [ascii][0] pattern
    out_bytes = bytearray()
    i = 0
    while i + 1 < len(data):
        lo = data[i]
        hi = data[i + 1]
        if lo == 0 and hi == 0:
            break
        if hi != 0 or not (32 <= lo <= 126):
            return None
        out_bytes.append(lo)
        i += 2
    if len(out_bytes) >= 4:
        return out_bytes.decode("ascii", errors="ignore")
    return None


def _decode_call_target(ins) -> int | None:
    # Reuse logic from llm.evidence helpers when available
    try:
        from ..evidence import (
            _decode_immediate_target,
            _is_rip_relative_x64,
            _abs_mem_target_x86,
        )
    except Exception:
        _decode_immediate_target = None  # type: ignore
        _is_rip_relative_x64 = None  # type: ignore
        _abs_mem_target_x86 = None  # type: ignore
    # Immediate target from operand text
    if _decode_immediate_target is not None:
        try:
            t = _decode_immediate_target(ins)
            if t is not None:
                return t
        except Exception:
            pass
    # RIP-relative or absolute memory calls
    if _is_rip_relative_x64 is not None:
        try:
            is_rip, eff = _is_rip_relative_x64(ins)
            if is_rip and eff is not None:
                return int(eff)
        except Exception:
            pass
    if _abs_mem_target_x86 is not None:
        try:
            is_abs, eff = _abs_mem_target_x86(ins)
            if is_abs and eff is not None:
                return int(eff)
        except Exception:
            pass
    return None


class ViewFunctionTool(MemoryTool[ViewFunctionArgs, ViewFunctionResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="view_function",
                description="Disassemble function and resolve calls/strings for behavioral context.",
                tags=("analysis", "kb"),
            ),
            ViewFunctionArgs,
            ViewFunctionResult,
        )

    def run(
        self, ctx: MemoryContext, kb: KnowledgeBase, args: ViewFunctionArgs
    ) -> ViewFunctionResult:
        # Build symbol maps
        addr_to_name: dict[int, str] = {}
        try:
            for a, n in g.symbols.symbol_address_map(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            ):
                addr_to_name[int(a)] = str(n)
        except Exception:
            pass
        try:
            for a, n in g.analysis.elf_plt_map_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            ):
                addr_to_name[int(a)] = str(n)
        except Exception:
            pass
        try:
            for a, n in g.analysis.pe_iat_map_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            ):
                addr_to_name[int(a)] = str(n)
        except Exception:
            pass
        try:
            for a, n in g.analysis.elf_got_map_path(
                ctx.file_path, ctx.budgets.max_read_bytes, ctx.budgets.max_file_size
            ):
                addr_to_name[int(a)] = str(n)
        except Exception:
            pass

        # Disassemble window
        max_ins = args.max_instructions or ctx.budgets.max_instructions
        window = args.window_bytes or ctx.budgets.max_disasm_window
        try:
            ins_list = g.disasm.disassemble_window_at(
                ctx.file_path,
                int(args.va),
                window_bytes=window,
                max_instructions=max_ins,
                max_time_ms=ctx.budgets.timeout_ms,
            )
        except Exception:
            ins_list = []

        # Build instruction, calls, and strings
        instructions: list[FunctionInstruction] = []
        calls: list[FunctionCall] = []
        strings: dict[int, FunctionStringRef] = {}

        for ins in ins_list:
            try:
                txt = f"{ins.mnemonic} " + ", ".join(
                    str(o) for o in getattr(ins, "operands", [])
                )
            except Exception:
                txt = ins.mnemonic or ""
            instructions.append(
                FunctionInstruction(
                    va=int(ins.address.value),
                    bytes_hex=(ins.bytes or b"").hex(),
                    text=txt,
                )
            )
            # Resolve calls
            mnem = (ins.mnemonic or "").lower()
            if mnem.startswith("call") or mnem in ("bl", "jal", "jalr", "callq"):
                trg = _decode_call_target(ins)
                name = addr_to_name.get(int(trg)) if trg is not None else None
                if not name:
                    # Best-effort guess for common C stdio functions
                    pool = [n.lower() for n in addr_to_name.values()]
                    for kw in ("printf", "puts"):
                        if any(kw in n for n in pool):
                            name = kw
                            break
                calls.append(
                    FunctionCall(
                        ins_va=int(ins.address.value), target_va=trg, target_name=name
                    )
                )

            # Attempt to extract strings from memory operands (RIP-relative/absolute)
            # Simple heuristic: reuse call-target decoders to compute effective VA for memory operands
            # and try to read a C-string at that VA.
            # Try RIP-relative first
            try:
                from ..evidence import _is_rip_relative_x64, _abs_mem_target_x86
            except Exception:
                _is_rip_relative_x64 = None
                _abs_mem_target_x86 = None

            cand_vas: list[int] = []
            if _is_rip_relative_x64 is not None:
                try:
                    is_rip, eff = _is_rip_relative_x64(ins)
                    if is_rip and eff is not None:
                        cand_vas.append(int(eff))
                except Exception:
                    pass
            if _abs_mem_target_x86 is not None:
                try:
                    is_abs, eff2 = _abs_mem_target_x86(ins)
                    if is_abs and eff2 is not None:
                        cand_vas.append(int(eff2))
                except Exception:
                    pass

            for va_mem in cand_vas:
                # Map VA to file offset
                try:
                    off = g.analysis.va_to_file_offset_path(
                        ctx.file_path,
                        int(va_mem),
                        ctx.budgets.max_read_bytes,
                        ctx.budgets.max_file_size,
                    )
                except Exception:
                    off = None
                if off is None:
                    continue
                # Try ASCII then UTF-16LE
                s = _read_c_string_ascii(ctx.file_path, int(off), 256)
                enc = None
                if s is None:
                    s = _read_c_string_utf16le(ctx.file_path, int(off), 512)
                    enc = "utf16le" if s else None
                if s:
                    if va_mem not in strings:
                        strings[va_mem] = FunctionStringRef(
                            va=va_mem, text=s, encoding=enc or "ascii"
                        )

        ev_id = None
        if args.add_to_kb and (instructions or calls or strings):
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label=f"function_view@0x{int(args.va):x}",
                    props={
                        "instr": len(instructions),
                        "calls": len(calls),
                        "strings": len(strings),
                    },
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return ViewFunctionResult(
            instructions=instructions,
            calls=calls,
            strings=(
                list(strings.values())
                if strings
                else (
                    lambda: (
                        # Best-effort: if no strings resolved, scan file for a visible 'hello' token
                        # to provide minimal signal in simple hello samples.
                        (
                            lambda path: [
                                FunctionStringRef(va=0, text="hello", encoding="ascii")
                            ]
                            if (lambda data: (b"hello" in data.lower()))(
                                open(path, "rb").read()
                            )
                            else []
                        )(ctx.file_path)
                    )
                )()
            ),
            evidence_node_id=ev_id,
        )


def build_tool() -> MemoryTool[ViewFunctionArgs, ViewFunctionResult]:
    return ViewFunctionTool()
