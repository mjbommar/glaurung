"""KB-aware function disassembly with symbol annotation.

The analyst loop kept re-deriving, per session, what glaurung already
owns: function bounds (from the discovered entry set), call-target names
(from ``function_names``), data/IAT names (from ``data_labels`` /
the import table). This module turns a ``.glaurung`` project + a function
name-or-VA into annotated disassembly so nobody hand-rolls
capstone+pefile+rva-mapping again.

    >>> fd = disasm_function("driver.sys", db_path="proj.glaurung",
    ...                      function="VidSchiCheckPendingDeviceCommand")
    >>> print(fd.render())

Direct call/branch targets and RIP-relative references (the resolved
absolute that iced already computes, e.g. ``[rip + 0x14008a7c0]``) are
annotated from, in order: function_names, the IAT import map, data_labels.
A coverage footer reports how many targets resolved and how many indirect
(register / memory) calls were left unresolved, so the output never reads
as more complete than it is.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from glaurung.llm.coverage import CoverageFooter

# Absolute hex token, e.g. "0x140013f24" or inside "rip:[rip + 0x14008a7c0]".
_ABS = re.compile(r"0x[0-9a-fA-F]+")


@dataclass
class AnnotatedInsn:
    va: int
    text: str
    comment: Optional[str] = None


@dataclass
class FunctionDisasm:
    name: str
    start_va: int
    end_va: int
    insns: List[AnnotatedInsn] = field(default_factory=list)
    coverage: Optional[CoverageFooter] = None

    def render(self) -> str:
        head = f"; {self.name}  0x{self.start_va:x}-0x{self.end_va:x}  ({len(self.insns)} insns)"
        body = []
        for ins in self.insns:
            line = f"  0x{ins.va:x}: {ins.text}"
            if ins.comment:
                line += f"   ; {ins.comment}"
            body.append(line)
        out = [head, *body]
        if self.coverage is not None:
            out.append("")
            out.append(self.coverage.render())
        return "\n".join(out)


def _load_symbols(
    db_path: str,
) -> Tuple[Dict[int, str], Dict[str, int], Dict[int, str], List[int]]:
    """Return (va->func_name, name->va, va->data_label, sorted_entry_vas)."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    va_name: Dict[int, str] = {}
    name_va: Dict[str, int] = {}
    for va, canon, dem in con.execute(
        "SELECT entry_va, canonical, demangled FROM function_names"
    ):
        va_name[int(va)] = canon
        name_va.setdefault(canon, int(va))
        if dem:
            name_va.setdefault(dem, int(va))
    data_label: Dict[int, str] = {}
    try:
        for va, nm in con.execute("SELECT va, name FROM data_labels"):
            data_label[int(va)] = nm
    except sqlite3.OperationalError:
        pass
    con.close()
    return va_name, name_va, data_label, sorted(va_name)


def _binary_path_from_db(db_path: str) -> Optional[str]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT first_path FROM binaries ORDER BY binary_id LIMIT 1"
        ).fetchone()
        return row[0] if row else None
    finally:
        con.close()


def disasm_function(
    binary_path: Optional[str] = None,
    *,
    db_path: Optional[str] = None,
    function: Optional[str] = None,
    va: Optional[int] = None,
    max_window: int = 0x6000,
    max_instructions: int = 4096,
) -> FunctionDisasm:
    """Disassemble one function from a ``.glaurung`` project, symbol-annotated.

    Bounds come from the discovered entry set (end = next entry > start,
    capped at ``max_window``). ``function`` may be a canonical/demangled
    name or a hex/decimal VA; or pass ``va`` directly.
    """
    if db_path is None:
        raise ValueError("db_path is required for KB-aware disassembly")
    if binary_path is None:
        binary_path = _binary_path_from_db(db_path)
        if not binary_path or not Path(binary_path).is_file():
            raise FileNotFoundError(
                f"binary path not resolvable from {db_path}; pass binary_path"
            )

    va_name, name_va, data_label, entries = _load_symbols(db_path)

    # Resolve the start VA.
    start = va
    if start is None:
        if function is None:
            raise ValueError("pass function (name or VA) or va")
        try:
            start = int(function, 0)
        except (TypeError, ValueError):
            start = name_va.get(function)
            if start is None:
                raise KeyError(f"function not found in DB: {function}")
    name = va_name.get(start, function if isinstance(function, str) else f"0x{start:x}")

    # End = next discovered entry after start, capped.
    end = start + max_window
    for e in entries:
        if e > start:
            end = min(e, start + max_window)
            break

    # IAT map for call [rip+slot] annotation. Best-effort.
    iat: Dict[int, str] = {}
    try:
        from glaurung.llm.kb.structural_fingerprint import resolve_iat_map

        iat = resolve_iat_map(binary_path)
    except Exception:
        pass

    from glaurung.disasm import disassemble_window_at

    insns = disassemble_window_at(
        binary_path, int(start),
        window_bytes=int(end - start),
        max_instructions=max_instructions,
        max_time_ms=8000,
    )

    cov = CoverageFooter("function-disasm")
    direct_resolved = direct_unresolved = 0
    indirect_calls = 0
    rip_resolved = 0
    out = FunctionDisasm(name=name, start_va=int(start), end_va=int(end))

    def annotate(text: str, is_cf: bool, is_call: bool) -> Optional[str]:
        nonlocal direct_resolved, direct_unresolved, indirect_calls, rip_resolved
        # Indirect (register / memory-not-rip) call: e.g. "call rax",
        # "call qword ptr [rcx+0x40]". We can't resolve these statically.
        if is_call and "rip" not in text and not _ABS.search(text):
            indirect_calls += 1
            return "indirect call (unresolved target)"
        targets = _ABS.findall(text)
        if not targets:
            return None
        # RIP-relative absolute (iced already resolved rip+disp): IAT > func > data.
        if "rip" in text:
            tgt = int(targets[-1], 16)
            nm = iat.get(tgt) or va_name.get(tgt) or data_label.get(tgt)
            if nm:
                rip_resolved += 1
                return nm
            return None
        # Bare absolute target on a control-flow insn.
        if is_cf:
            tgt = int(targets[-1], 16)
            # Intra-function Jcc/jmp is normal flow, not a symbol reference.
            if not is_call and start <= tgt < end:
                return None
            nm = va_name.get(tgt)
            if nm:
                direct_resolved += 1
                return f"-> {nm}"
            # A call (or tail-call jump) to an address with no name.
            direct_unresolved += 1
            return None
        return None

    for i in insns:
        try:
            is_call = bool(i.is_call())
            is_cf = bool(i.changes_control_flow())
        except Exception:
            is_call = is_cf = False
        # Build text from mnemonic + operands (clean) rather than parsing
        # the "<va>: <bytes> <mnem ops>" disassembly string, whose byte run
        # is ambiguous against hex immediates in the operands.
        ops = ", ".join(str(o) for o in i.operands)
        text = f"{i.mnemonic} {ops}".rstrip()
        out.insns.append(
            AnnotatedInsn(va=int(i.address.value), text=text,
                          comment=annotate(ops, is_cf, is_call))
        )

    cov.fact("instructions", len(out.insns))
    cov.fact("direct call/branch targets resolved", direct_resolved)
    cov.fact("rip-relative refs resolved (iat/func/data)", rip_resolved)
    cov.fact("indirect calls unresolved", indirect_calls)
    cov.fact("function names available", len(va_name))
    cov.fact("iat entries", len(iat))
    if direct_unresolved:
        cov.caveat(
            f"{direct_unresolved} direct target(s) had no name in the DB "
            "(unlisted thunk/data or stale function set)"
        )
    if indirect_calls:
        cov.caveat(
            f"{indirect_calls} indirect call(s) (register/jump-table) "
            "not statically resolved"
        )
    if not iat:
        cov.caveat("IAT map empty/unavailable; [rip+slot] imports unnamed")
    out.coverage = cov
    return out
