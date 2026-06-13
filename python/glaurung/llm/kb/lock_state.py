"""Lock / synchronization-state analysis (primitive-complete, CFG-aware).

Why this exists: during the dxgmms2 investigation (agentic-security-bot,
2026-06-01) an ad-hoc lock tracer modeled ONLY the raw ``Ke*SpinLock``
imports and silently ignored the C++ RAII wrapper
``AcquireSpinLock::Acquire/Release``. It reported a "wrong-lock
double-free" that was false: the path it flagged actually took the lock
through the wrapper. The lessons, baked in here:

  1. Model ALL lock primitives -- raw ``Ke*`` / ``Ex*`` imports AND the
     named RAII wrappers (``Acquire@AcquireSpinLock``, ``Acquire@DXGFASTMUTEX``,
     ``AcquireExclusive@DXGPUSHLOCK``, ...).
  2. Be CFG-aware: held-lock sets are a forward dataflow to a fixpoint over
     glaurung's OWN basic-block graph (authoritative successor/predecessor
     edges), NOT a linear sweep. We report BOTH the MUST-hold set
     (intersection over incoming paths == provably held on every path) AND
     the MAY-hold set (union == held on some path). A lock in MAY but not
     MUST is a path-discrepancy the analyst must see; reporting both is the
     honest lattice, never a single confident guess.
  3. Emit a coverage footer: unresolved indirect calls, lock-object operands
     we could not resolve, and any call target that LOOKS lock-like but was
     not classified (modeling gap), plus the INTRAPROCEDURAL caveat (a lock
     held by a caller is not seen here). Partial coverage must read as partial.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from glaurung.llm.coverage import CoverageFooter

_ABS = re.compile(r"0x[0-9a-fA-F]+")

# Primitive name classification. Matches resolved callee names (IAT import
# names or function_names canonical, including mangled wrapper methods).
_ACQUIRE = re.compile(
    r"(?:^|[A-Za-z])(?:Ke|Ex)?Acquire\w*?(?:SpinLock|Lock|Resource|Mutex|"
    r"PushLock|Rundown|FastMutex)"           # raw kernel APIs
    r"|^\?Acquire(?:Shared|Exclusive)?@"     # ?Acquire@AcquireSpinLock@@...
)
_RELEASE = re.compile(
    r"(?:^|[A-Za-z])(?:Ke|Ex)?Release\w*?(?:SpinLock|Lock|Resource|Mutex|"
    r"PushLock|Rundown|FastMutex)"
    r"|^\?Release(?:Shared|Exclusive)?@"
)
# Anything that *smells* like a synchronization primitive -- used only to
# flag UNMODELED lock-like targets in the coverage footer (requirement c).
_LOCKISH = re.compile(
    r"Lock|Mutex|Spin|Acquire|Release|Rundown|Resource|PushLock|Critical|Sync",
    re.IGNORECASE,
)


@dataclass
class LockOp:
    va: int
    kind: str          # "acquire" | "release"
    primitive: str     # resolved callee name
    lock_id: Optional[str]  # symbolic lock object, e.g. "r14+0x7c0", or None


@dataclass
class HeldAtCall:
    va: int
    callee: str
    must: Set[str]     # locks held on ALL paths reaching this call
    may: Set[str]      # locks held on SOME path reaching this call


@dataclass
class LockReport:
    function: str
    start_va: int
    end_va: int
    ops: List[LockOp] = field(default_factory=list)
    balance: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    held_at_calls: List[HeldAtCall] = field(default_factory=list)
    cfg_blocks: int = 0
    cfg_edges: int = 0
    coverage: Optional[CoverageFooter] = None

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "start_va": self.start_va,
            "end_va": self.end_va,
            "ops": [
                {"va": o.va, "kind": o.kind, "primitive": o.primitive,
                 "lock_id": o.lock_id}
                for o in self.ops
            ],
            "balance": {k: {"acquire": a, "release": r}
                        for k, (a, r) in self.balance.items()},
            "held_at_calls": [
                {"va": h.va, "callee": h.callee,
                 "must_held": sorted(h.must), "may_held": sorted(h.may)}
                for h in self.held_at_calls
            ],
            "cfg": {"blocks": self.cfg_blocks, "edges": self.cfg_edges},
            "coverage": self.coverage.to_dict() if self.coverage else None,
        }

    def held_must(self, va: int) -> Optional[Set[str]]:
        for h in self.held_at_calls:
            if h.va == va:
                return h.must
        return None

    def render(self) -> str:
        out = [f"; lock-state: {self.function}  0x{self.start_va:x}-0x{self.end_va:x}"
               f"  (CFG: {self.cfg_blocks} blocks, {self.cfg_edges} edges)"]
        out.append(f"; acquire/release sites: {len(self.ops)}")
        for op in self.ops:
            out.append(
                f"  0x{op.va:x}  {op.kind:7s} {op.primitive}"
                f"  lock={op.lock_id or '<unresolved>'}"
            )
        if self.balance:
            out.append("; per-lock acquire/release balance:")
            for k in sorted(self.balance):
                a, r = self.balance[k]
                flag = "" if a == r else "  (unbalanced -- see caveats)"
                out.append(f"  {k}: acquire={a} release={r}{flag}")
        if self.held_at_calls:
            out.append("; locks held at call sites (must = all paths, may = some path):")
            for h in self.held_at_calls:
                disc = "" if h.must == h.may else "  [PATH-DISCREPANCY: may>must]"
                out.append(
                    f"  0x{h.va:x} -> {h.callee}  "
                    f"must={{{', '.join(sorted(h.must)) or '-'}}}  "
                    f"may={{{', '.join(sorted(h.may)) or '-'}}}{disc}"
                )
        if self.coverage is not None:
            out.append("")
            out.append(self.coverage.render())
        return "\n".join(out)


def _load(db_path: str) -> Tuple[Dict[int, str], Optional[str]]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    va_name = {int(va): canon for va, canon in
               con.execute("SELECT entry_va, canonical FROM function_names")}
    row = con.execute(
        "SELECT first_path FROM binaries ORDER BY binary_id LIMIT 1"
    ).fetchone()
    con.close()
    return va_name, (row[0] if row else None)


def _bytes_of(dis: str) -> bytes:
    """Extract instruction bytes from a disassembly() string like
    '14001df66: 48 81 c1 c0 07 00 00add rcx'."""
    body = dis.split(":", 1)[1] if ":" in dis else dis
    out = bytearray()
    i = 0
    s = body.strip()
    while i + 1 < len(s):
        pair = s[i:i + 2]
        if len(pair) == 2 and all(c in "0123456789abcdefABCDEF" for c in pair):
            out.append(int(pair, 16))
            i += 2
            if i < len(s) and s[i] == " ":
                i += 1
        else:
            break
    return bytes(out)


def _add_imm_to_rcx(dis: str) -> Optional[int]:
    """Decode the immediate of ``add rcx, imm`` from raw bytes. Reading the bytes
    directly is robust regardless of how the disassembler renders the immediate."""
    b = _bytes_of(dis)
    j = 0
    while j < len(b) and 0x40 <= b[j] <= 0x4F:
        j += 1
    if j + 1 >= len(b):
        return None
    op, modrm = b[j], b[j + 1]
    if modrm != 0xC1:  # mod=11, reg=/0 (add), rm=001 (rcx)
        return None
    if op == 0x81 and j + 6 <= len(b):
        return int.from_bytes(b[j + 2:j + 6], "little")
    if op == 0x83 and j + 3 <= len(b):
        v = b[j + 2]
        return v - 0x100 if v >= 0x80 else v
    return None


def _resolve_lock_id(mnem: str, ops: str, dis: str) -> Optional[str]:
    """Stable lock id from the rcx-source instruction (sign-aware)."""
    m = re.search(r"(\w+):\[\w+ ([+-]) (0x[0-9a-fA-F]+)\]", ops)
    if m and mnem in ("lea", "mov"):
        return f"{m.group(1)}{m.group(2)}{m.group(3)}"
    if mnem == "add" and ops.split(",")[0].strip() == "rcx":
        # The immediate is decoded from the raw bytes (_add_imm_to_rcx), so this
        # works whether or not the disassembler renders the immediate operand.
        imm = _add_imm_to_rcx(dis)
        if imm is not None:
            return f"+0x{imm:x}"
    return None


def _bb_va(bb_id: str) -> Optional[int]:
    """'bb_14000e4eb' -> 0x14000e4eb."""
    m = re.match(r"bb_([0-9a-fA-F]+)$", bb_id)
    return int(m.group(1), 16) if m else None


def _addr(x) -> int:
    v = x() if callable(x) else x
    return v.value if hasattr(v, "value") else int(v)


def _m(obj, name):
    a = getattr(obj, name)
    return a() if callable(a) else a


def analyze_locks(
    binary_path: Optional[str] = None,
    *,
    db_path: str,
    function: Optional[str] = None,
    va: Optional[int] = None,
) -> LockReport:
    """Intraprocedural, CFG-aware lock-state analysis for one function.

    Uses glaurung's authoritative basic-block CFG for the dataflow; reports
    must-held (all paths) and may-held (some path) locks at each call site.
    """
    va_name, db_bin = _load(db_path)
    if binary_path is None:
        binary_path = db_bin
    if not binary_path or not Path(binary_path).is_file():
        raise FileNotFoundError("binary path not resolvable; pass binary_path")

    name_to_va: Dict[str, int] = {}
    for a, n in va_name.items():
        name_to_va.setdefault(n, a)

    start = va
    if start is None:
        try:
            start = int(function, 0)
        except (TypeError, ValueError):
            start = name_to_va.get(function)
            if start is None:
                raise KeyError(f"function not found: {function}")
    fname = va_name.get(start, str(function))

    # ---- glaurung CFG for this function (authoritative edges) ----
    import glaurung as g
    funcs, _cg = g.analysis.analyze_functions_path(binary_path)
    fobj = None
    for f in funcs:
        if _addr(f.entry_point) == start:
            fobj = f
            break
    if fobj is None or not fobj.basic_blocks:
        raise KeyError(f"no CFG for function at 0x{start:x} ({fname})")

    blocks = fobj.basic_blocks
    blk_start = {}      # block-start-va -> (start, end)
    succ: Dict[int, Set[int]] = {}
    for b in blocks:
        s = _addr(b.start_address)
        e = _addr(b.end_address)
        blk_start[s] = (s, e)
        succ[s] = set()
    for b in blocks:
        s = _addr(b.start_address)
        for sid in _m(b, "successor_ids"):
            t = _bb_va(sid)
            if t is not None and t in blk_start:
                succ[s].add(t)
    edges = sum(len(v) for v in succ.values())
    func_end = max(e for (_s, e) in blk_start.values())

    def block_of(addr: int) -> Optional[int]:
        for s, (bs, be) in blk_start.items():
            if bs <= addr < be:
                return s
        return None

    iat: Dict[int, str] = {}
    try:
        from glaurung.llm.kb.structural_fingerprint import resolve_iat_map
        iat = resolve_iat_map(binary_path)
    except Exception:
        pass

    from glaurung.disasm import disassemble_window_at
    insns = disassemble_window_at(
        binary_path, int(start), window_bytes=int(func_end - start),
        max_instructions=16384, max_time_ms=10000,
    )

    rep = LockReport(function=fname, start_va=int(start), end_va=int(func_end),
                     cfg_blocks=len(blocks), cfg_edges=edges)
    cov = CoverageFooter("lock-state")

    # ---- linear pass: classify ops + resolve lock objects ----
    last_rcx: Optional[Tuple[str, str, str]] = None
    last_rdx: Optional[Tuple[str, str, str]] = None
    last_lock_id: Optional[str] = None
    guard_map: Dict[str, Optional[str]] = {}
    handle_map: Dict[str, Optional[str]] = {}
    indirect_calls = 0
    lockobj_unresolved = 0
    primitives_seen: Set[str] = set()
    unmodeled_lockish: Set[str] = set()
    op_by_va: Dict[int, LockOp] = {}
    call_by_va: Dict[int, str] = {}
    insn_count = 0

    for i in insns:
        insn_count += 1
        v = int(i.address.value)
        ops = ", ".join(str(o) for o in i.operands)
        try:
            is_call = bool(i.is_call())
        except Exception:
            is_call = False
        mnem = i.mnemonic
        try:
            dis = i.disassembly()
        except Exception:
            dis = ""
        if ops.split(",")[0].strip() == "rcx" and mnem in ("lea", "add", "mov"):
            last_rcx = (mnem, ops, dis)
            lid0 = _resolve_lock_id(mnem, ops, dis)
            if lid0 is not None:
                last_lock_id = lid0
        if ops.split(",")[0].strip() == "rdx" and mnem in ("lea", "mov"):
            last_rdx = (mnem, ops, dis)
        mg = re.match(r"(\w+):\[\w+ ([+-]) (0x[0-9a-fA-F]+)\], rcx$", ops)
        if mnem == "mov" and mg:
            guard_map[f"{mg.group(1)}{mg.group(2)}{mg.group(3)}"] = last_lock_id
        if not is_call:
            continue
        callee = None
        direct_target = None
        m = _ABS.findall(ops)
        if "rip" in ops:
            if m:
                callee = iat.get(int(m[-1], 16)) or va_name.get(int(m[-1], 16))
        elif m:
            direct_target = int(m[-1], 16)
            callee = va_name.get(direct_target)
        if callee is None:
            if "rip" not in ops and direct_target is None:
                indirect_calls += 1
            continue
        call_by_va[v] = callee
        kind = "acquire" if _ACQUIRE.search(callee) else (
            "release" if _RELEASE.search(callee) else None)
        if kind is None:
            if _LOCKISH.search(callee):
                unmodeled_lockish.add(callee)
            continue
        primitives_seen.add(callee)
        lid = None
        if last_rcx is not None:
            gm = re.match(r"rcx, (\w+):\[\w+ ([+-]) (0x[0-9a-fA-F]+)\]", last_rcx[1])
            if last_rcx[0] == "lea" and gm:
                slot = f"{gm.group(1)}{gm.group(2)}{gm.group(3)}"
                if slot in handle_map:
                    lid = handle_map[slot]
                elif slot in guard_map:
                    lid = guard_map[slot]
            if lid is None:
                lid = _resolve_lock_id(*last_rcx)
        if kind == "acquire" and last_rdx is not None:
            hm = re.match(r"rdx, (\w+):\[\w+ ([+-]) (0x[0-9a-fA-F]+)\]", last_rdx[1])
            if hm:
                handle_map[f"{hm.group(1)}{hm.group(2)}{hm.group(3)}"] = lid
        if kind == "acquire" and lid is None:
            lockobj_unresolved += 1
        op = LockOp(va=v, kind=kind, primitive=callee, lock_id=lid)
        rep.ops.append(op)
        op_by_va[v] = op

    # ---- per-lock balance ----
    for op in rep.ops:
        key = op.lock_id or f"<unresolved@0x{op.va:x}>"
        a, r = rep.balance.get(key, (0, 0))
        rep.balance[key] = (a + 1, r) if op.kind == "acquire" else (a, r + 1)

    # ---- CFG dataflow: must (intersection) + may (union) held-lock sets ----
    # Group ops/calls by block, in address order, for the transfer function.
    ops_in_block: Dict[int, List[Tuple[int, LockOp]]] = {s: [] for s in blk_start}
    for v, op in sorted(op_by_va.items()):
        b = block_of(v)
        if b is not None:
            ops_in_block[b].append((v, op))

    def transfer(entry: Set[str], blk: int) -> Set[str]:
        held = set(entry)
        for _v, op in ops_in_block[blk]:
            if op.lock_id is None:
                continue
            if op.kind == "acquire":
                held.add(op.lock_id)
            else:
                held.discard(op.lock_id)
        return held

    preds: Dict[int, Set[int]] = {s: set() for s in blk_start}
    for s, ss in succ.items():
        for t in ss:
            preds[t].add(s)

    must_out: Dict[int, Set[str]] = {s: set() for s in blk_start}
    may_out: Dict[int, Set[str]] = {s: set() for s in blk_start}
    must_in: Dict[int, Set[str]] = {s: set() for s in blk_start}
    may_in: Dict[int, Set[str]] = {s: set() for s in blk_start}
    order = sorted(blk_start)
    for _pass in range(len(order) + 2):  # bounded fixpoint (acyclic-ish; cycles converge)
        changed = False
        for s in order:
            ps = preds[s]
            if ps:
                acc = None
                for p in ps:
                    acc = set(must_out[p]) if acc is None else (acc & must_out[p])
                m_in = acc or set()
                u_in: Set[str] = set()
                for p in ps:
                    u_in |= may_out[p]
            else:
                m_in = set()
                u_in = set()
            must_in[s], may_in[s] = m_in, u_in
            mo = transfer(m_in, s)
            uo = transfer(u_in, s)
            if mo != must_out[s] or uo != may_out[s]:
                must_out[s], may_out[s] = mo, uo
                changed = True
        if not changed:
            break

    # ---- held at each call site (walk block from its in-state) ----
    for v in sorted(call_by_va):
        b = block_of(v)
        if b is None:
            continue
        must_held = set(must_in[b])
        may_held = set(may_in[b])
        for vv, op in ops_in_block[b]:
            if vv >= v:
                break
            if op.lock_id is None:
                continue
            if op.kind == "acquire":
                must_held.add(op.lock_id)
                may_held.add(op.lock_id)
            else:
                must_held.discard(op.lock_id)
                may_held.discard(op.lock_id)
        # Only report calls that are interesting: lock primitives OR any call
        # while holding >=1 lock (the "is this protected" question).
        if must_held or may_held:
            rep.held_at_calls.append(
                HeldAtCall(va=v, callee=call_by_va[v], must=must_held, may=may_held)
            )

    # ---- coverage footer ----
    cov.fact("instructions", insn_count)
    cov.fact("cfg blocks", len(blocks))
    cov.fact("cfg edges", edges)
    cov.fact("acquire sites", sum(1 for o in rep.ops if o.kind == "acquire"))
    cov.fact("release sites", sum(1 for o in rep.ops if o.kind == "release"))
    cov.fact("lock primitives modeled", sorted(primitives_seen) or ["(none found)"])
    cov.fact("distinct lock objects", len(rep.balance))
    cov.fact("indirect calls unresolved", indirect_calls)
    cov.fact("lock-object operands unresolved", lockobj_unresolved)
    cov.caveat(
        "INTRAPROCEDURAL: locks acquired by a CALLER are not modeled; held "
        "sets reflect only this function's own acquire/release ops"
    )
    if indirect_calls:
        cov.caveat(
            f"{indirect_calls} indirect call(s) could hide a lock primitive "
            "(register/jump-table/vtable dispatch not resolved)"
        )
    if unmodeled_lockish:
        cov.caveat(
            "call target(s) look lock-like but were NOT classified as "
            "acquire/release (modeling gap): "
            + ", ".join(sorted(unmodeled_lockish)[:8])
        )
    if lockobj_unresolved:
        cov.caveat(
            f"{lockobj_unresolved} acquire(s) had an unresolved lock object "
            "(rcx not a simple base+disp); treated as distinct unknown locks"
        )
    unbalanced = {k: v for k, v in rep.balance.items() if v[0] != v[1]}
    if unbalanced:
        cov.caveat(
            "per-lock acquire/release counts differ for "
            + ", ".join(f"{k}({a}/{r})" for k, (a, r) in unbalanced.items())
            + " -- expected for conditional release / handoff, NOT a leak proof"
        )
    rep.coverage = cov
    return rep
