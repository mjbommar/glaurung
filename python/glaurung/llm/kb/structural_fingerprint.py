"""Structural per-function fingerprints for BinDiff/Diaphora-style diff.

Perf note: the fingerprint is computed entirely in Python on top of the
``glaurung.disasm.disassembler_for_path()`` Rust backend. We avoid
``disassemble_window_at`` (re-reads the binary off disk on every
call — fatal for big PEs like ``ntoskrnl.exe``). Instead the caller
hands us the mmap'd bytes and a precomputed VA → file-offset table
(see ``build_va_table`` below); per-function lookup is then a binary
search and a slice.

The raw `body_hash` used by ``binary_diff.diff_binaries`` is a SHA256 of
the function's bytes. That hash flips for *any* address shift —
relinked binaries (e.g. consecutive Windows patch builds) shift every
``call rel32``, every ``mov rip+disp32`` to a different absolute, so
the byte-level hash diverges on every function even when the code is
semantically identical. The diff then drowns the actual patched
functions in thousands of false positives.

This module computes a **structural fingerprint** that is invariant to
those address shifts. The algorithm is closer to Diaphora's "small
prime products" / Bindiff's structural-hash heuristics than to a full
graph isomorphism: we lift each instruction to a normalized token,
hash the per-block token sequence, and combine the per-block hashes
with the function's CFG topology. Two functions with the same fingerprint
are treated as structurally identical even if their raw bytes differ.

What we mask (the noise we want to ignore):

  * Absolute target of ``call rel32`` / ``jmp rel32``. The token is just
    ``call(direct)`` — the address is dropped. Branch targets inside the
    function survive via the CFG edge set, not the operand text.

  * ``call qword ptr [rip+disp]`` against the IAT. We resolve the
    target to the import name (e.g. ``memcpy``) and token it as
    ``call(import:memcpy)``. Identical across builds because IAT entries
    move but names don't.

  * ``mov reg, qword ptr [rip+disp]`` against IAT data / global data.
    The displacement is dropped; we record ``mem(rip,disp:global)``.
    If the IAT name is known we substitute it.

  * Concrete register identity. ``mov rax, rbx`` and ``mov rcx, rdx``
    tokenize identically (``mov R R``) — compilers re-allocate registers
    freely across patch builds without semantic change. The CFG and
    operand *shapes* still differ when the program changes.

  * Stack displacement constants. ``mov [rsp+0x20], rax`` and
    ``mov [rsp+0x28], rax`` collapse to ``mov mem(rsp,disp:stack) R``;
    frame layout often shuffles between builds.

  * Per-block sort order. We sort blocks by entry address within the
    function before hashing the block sequence, so block reorder by
    the linker doesn't change the fingerprint.

What we keep (the signal we DON'T want to lose):

  * Instruction mnemonic (op).
  * Operand kind shape: reg vs imm vs mem(stack|global|other).
  * The CFG edge set (as a multiset of (src_idx, dst_idx) pairs after
    topological-ish ordering by entry-offset).
  * Counts: blocks, edges, calls, direct vs indirect calls,
    memory reads, memory writes, returns.

The result is a 16-hex-char SHA256 digest; equality means structurally
identical. We additionally emit a Jaccard-style similarity score over
the multiset of per-block token hashes so the diff can rank "near-miss"
matches (single-block change vs whole-function rewrite).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple


_STACK_REGS = {"rsp", "esp", "sp", "rbp", "ebp", "bp"}
# rip-relative addressing is x86-64 PC-relative; on PE/ELF this is
# overwhelmingly used for global-data / IAT references.
_GLOBAL_REGS = {"rip", "eip"}


def _classify_mem_base(base: Optional[str]) -> str:
    """Bucket a memory operand by base-register class. ``base`` is the
    string Capstone gives us (e.g. ``rsp``, ``rip``, ``rax``, or ``None``
    for absolute addressing)."""
    if base is None:
        return "abs"
    b = base.lower()
    if b in _STACK_REGS:
        return "stack"
    if b in _GLOBAL_REGS:
        return "global"
    return "reg"


def _bucket_imm(value: Optional[int]) -> str:
    """Bucket a non-control-flow immediate by magnitude. We don't trust
    the exact value (constants get reordered when constant pools move),
    but we do keep a coarse magnitude signal so e.g. ``cmp eax, 0`` vs
    ``cmp eax, 0x100`` aren't identical."""
    if value is None:
        return "?"
    if value == 0:
        return "0"
    v = abs(int(value))
    if v == 1:
        return "1"
    if v < 0x10:
        return "s"  # small
    if v < 0x10000:
        return "m"  # medium
    return "L"      # large (likely a pointer / sentinel)


def _instr_token(
    insn,
    *,
    iat_by_va: Dict[int, str],
) -> str:
    """Build the normalized token for one disassembled instruction.

    Format: ``<mnemonic> <op-shape> <op-shape> ...``.

    The token is intentionally human-readable for debugging; the
    fingerprint is the SHA256 of the joined per-block tokens, so a
    longer-but-readable token is fine.
    """
    parts: List[str] = [insn.mnemonic.lower()]

    is_call = bool(insn.is_call())
    is_branch = bool(insn.is_branch())
    is_ret = bool(insn.is_return())

    if is_ret:
        # `ret` operands are stack-pop counts; ignore them. We just emit
        # the mnemonic.
        return parts[0]

    for op in insn.operands:
        kind = str(op.kind)  # 'Register' | 'Immediate' | 'Memory'
        if kind == "Register":
            parts.append("R")
            continue
        if kind == "Immediate":
            if is_call or is_branch:
                # Direct call/branch target: drop the address, but
                # record direction (forward/backward) for branches —
                # important because a backward branch implies a loop
                # while a forward branch is a forward jump.
                tgt = op.displacement if op.displacement is not None else None
                if is_call:
                    parts.append("call(direct)")
                else:
                    # Branch direction is captured by the CFG edge set
                    # itself; the per-instruction token only marks "this
                    # is a branch immediate" so we don't fingerprint a
                    # `jmp 0x1234` and a `jmp 0x5678` differently.
                    parts.append("br(direct)")
                continue
            # Plain immediate — bucket by magnitude.
            imm_val = op.displacement if op.displacement is not None else None
            parts.append(f"I[{_bucket_imm(imm_val)}]")
            continue
        if kind == "Memory":
            base_cls = _classify_mem_base(op.base)
            # IAT-resolved load: when the operand is rip-relative AND
            # the resolved absolute lands on an IAT slot, we can
            # substitute the import name. Capstone gives us the
            # *resolved* absolute in ``displacement`` for rip-relative
            # memory operands on this codebase.
            if base_cls == "global" and op.displacement is not None:
                name = iat_by_va.get(int(op.displacement))
                if name is not None:
                    op_token = f"M[iat:{name}]"
                else:
                    # Anonymous global: drop the displacement entirely
                    # but keep the indication that this is a global.
                    op_token = "M[global]"
            elif base_cls == "stack":
                # Stack offsets shuffle freely between builds; drop the
                # displacement.
                op_token = "M[stack]"
            else:
                # Pointer arithmetic / array index. Keep the index
                # presence bit but drop displacement values.
                idx = "+I" if op.index else ""
                op_token = f"M[{base_cls}{idx}]"
            parts.append(op_token)
            continue
        parts.append(f"O[{kind}]")

    if is_call and not any(p.startswith("call(") or p.startswith("M[iat:") for p in parts[1:]):
        # An indirect call where the operand wasn't IAT-resolvable
        # (e.g. ``call rax``, ``call [rbx+8]``). Mark it as such so it
        # doesn't collide with direct calls.
        parts.append("call(indirect)")

    return " ".join(parts)


@dataclass(frozen=True)
class FunctionStructure:
    """Structural summary of one function. Field semantics:

    * ``fingerprint`` — 16-hex-char SHA256 digest. Equal across
      structurally identical functions; this is the v1 "are these the
      same?" oracle.

    * ``block_token_hashes`` — sorted list of 16-hex per-block digests.
      Used by ``similarity_score`` for near-miss matching.

    * ``stats`` — coarse counts; used as a fast pre-filter (two
      functions with very different block counts can't be a structural
      match).
    """

    fingerprint: str
    block_token_hashes: Tuple[str, ...]
    stats: Tuple[int, ...]  # (n_blocks, n_edges, n_calls, n_indirect_calls,
                            #  n_mem_reads, n_mem_writes, n_returns)


def _hash16(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:16]


def build_va_table(data: bytes) -> Tuple[List[Tuple[int, int, int]], int]:
    """Parse PE section headers to build a sorted VA-range → file-offset
    table. Returns ``([], 0)`` for non-PE inputs; callers fall back to
    the slower path-based ``glaurung.analysis.va_to_file_offset_path``.

    The table is a list of ``(va_start, va_end, file_offset_start)``
    sorted by ``va_start`` for ``bisect``-style lookup.
    """
    import struct

    if len(data) < 0x40 or data[:2] != b"MZ":
        return [], 0
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return [], 0
        coff = pe_off + 4
        n_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        magic = struct.unpack_from("<H", data, coff + 20)[0]
        opt_off = coff + 20
        if magic == 0x20B:  # PE32+
            image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        else:  # PE32
            image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        sec_off = opt_off + opt_size
        table: List[Tuple[int, int, int]] = []
        for i in range(n_sections):
            s = sec_off + i * 40
            vsize = struct.unpack_from("<I", data, s + 8)[0]
            vaddr = struct.unpack_from("<I", data, s + 12)[0]
            rsize = struct.unpack_from("<I", data, s + 16)[0]
            roff = struct.unpack_from("<I", data, s + 20)[0]
            va_start = image_base + vaddr
            va_end = image_base + vaddr + max(vsize, rsize)
            table.append((va_start, va_end, roff))
        table.sort()
        return table, image_base
    except Exception:
        return [], 0


def va_to_offset(
    table: Sequence[Tuple[int, int, int]], va: int
) -> Optional[int]:
    """Binary-search the section table for ``va`` and return the
    corresponding file offset, or ``None`` if the VA isn't mapped."""
    lo, hi = 0, len(table)
    while lo < hi:
        mid = (lo + hi) // 2
        a, b, _ = table[mid]
        if va < a:
            hi = mid
        elif va >= b:
            lo = mid + 1
        else:
            return table[mid][2] + (va - a)
    return None


def structural_fingerprint(
    *,
    func,
    path: str,
    iat_by_va: Dict[int, str],
    data: Optional[bytes] = None,
    va_table: Optional[Sequence[Tuple[int, int, int]]] = None,
    disassembler=None,
) -> Optional[FunctionStructure]:
    """Compute the structural fingerprint for one ``Function``.

    The fast path requires ``data`` (the mmap'd binary), ``va_table``
    (from :func:`build_va_table`), and ``disassembler`` (the result
    of ``glaurung.disasm.disassembler_for_path``). When any of these
    is omitted we fall back to ``disassemble_window_at(path, ...)``
    per block — correct but ~100× slower on big binaries.

    Returns ``None`` when the function has no basic blocks (a pure
    thunk discovered without bodies) or when disassembly of every
    block fails. Empty functions can't be meaningfully diffed.
    """
    import glaurung as g

    blocks = list(func.basic_blocks or [])
    if not blocks:
        return None

    # Sort blocks by entry VA → stable index assignment regardless of
    # linker block order in the source binary.
    blocks.sort(key=lambda b: int(b.start_address.value))
    id_to_idx: Dict[str, int] = {b.id: i for i, b in enumerate(blocks)}
    block_starts = [int(b.start_address.value) for b in blocks]
    block_insn_caps = [max(int(b.instruction_count) * 2, 4) for b in blocks]

    block_hashes: List[str] = []
    n_edges = 0
    n_calls = 0
    n_indirect_calls = 0
    n_mem_reads = 0
    n_mem_writes = 0
    n_returns = 0
    edges: List[Tuple[int, int]] = []

    fast_path = (
        data is not None and va_table is not None and disassembler is not None
    )

    # Disassembly cache: VA -> [insns]. On the fast path we issue ONE
    # disassemble_bytes call per function (covering all blocks in the
    # function's range) instead of one per block. That cuts the per-
    # function disasm cost by ~5-10x on average. The result is bucketed
    # back into blocks by start VA.
    insns_by_block: Dict[int, List] = {}
    if fast_path:
        rng = func.range
        if rng is not None and rng.size:
            fn_start = int(rng.start.value)
            fn_size = int(rng.size)
            off = va_to_offset(va_table, fn_start)
            if off is not None and 0 <= off < len(data):
                buf = data[off : off + fn_size]
                if buf:
                    try:
                        # Bound instructions generously; ``max_time_ms``
                        # protects against pathological data-in-code
                        # regions where Capstone walks forever.
                        cap = max(sum(block_insn_caps), 32) * 2
                        all_insns = disassembler.disassemble_bytes(
                            rng.start, buf,
                            max_instructions=cap,
                            max_time_ms=500,
                        )
                    except Exception:
                        all_insns = []
                    # Bucket by block. Each instruction belongs to the
                    # block whose start_address is the largest <= the
                    # instruction's address.
                    cur_idx = -1
                    for ins in all_insns:
                        va = int(ins.address.value)
                        # Advance cur_idx to the block containing this va.
                        while cur_idx + 1 < len(block_starts) and block_starts[cur_idx + 1] <= va:
                            cur_idx += 1
                        if cur_idx >= 0:
                            insns_by_block.setdefault(cur_idx, []).append(ins)

    for idx, bb in enumerate(blocks):
        start = int(bb.start_address.value)
        try:
            size = int(bb.size_bytes())
        except (TypeError, AttributeError):
            try:
                size = int(bb.size_bytes)
            except Exception:
                size = max(1, int(bb.end_address.value) - start)
        if size <= 0:
            size = max(1, int(bb.end_address.value) - start)

        insns: List = insns_by_block.get(idx, [])
        if not insns and not fast_path:
            try:
                insns = g.disasm.disassemble_window_at(
                    str(path), start, max(size, 1), block_insn_caps[idx],
                )
            except Exception:
                insns = []

        tokens: List[str] = []
        for insn in insns:
            tokens.append(_instr_token(insn, iat_by_va=iat_by_va))
            if insn.is_call():
                n_calls += 1
                if not any(str(o.kind) == "Immediate" for o in insn.operands):
                    n_indirect_calls += 1
            if insn.is_return():
                n_returns += 1
            for op in insn.operands:
                if str(op.kind) == "Memory":
                    if op.access and "Write" in str(op.access):
                        n_mem_writes += 1
                    else:
                        n_mem_reads += 1

        block_hashes.append(_hash16("|".join(tokens)))

        # CFG edges: bb.successor_ids → block index. Successor outside
        # the function (tail-call landing in another function) gets
        # mapped to a sentinel ``-1`` so it still contributes to the
        # edge multiset without referring to a foreign block index.
        for succ in bb.successor_ids or []:
            dst = id_to_idx.get(succ, -1)
            edges.append((idx, dst))
            n_edges += 1

    # Final fingerprint = hash(blocks-in-order || edges-sorted).
    # We intentionally do NOT sort block_hashes for the final digest —
    # the entry-VA ordering of blocks IS the canonical ordering — but
    # we DO sort the edges, since the per-block emission order of
    # successors is meaningless.
    edges_sorted = sorted(edges)
    digest_input = "B:" + "|".join(block_hashes) + ";E:" + ",".join(
        f"{a}>{b}" for a, b in edges_sorted
    )
    fingerprint = _hash16(digest_input)

    return FunctionStructure(
        fingerprint=fingerprint,
        block_token_hashes=tuple(sorted(block_hashes)),
        stats=(
            len(blocks),
            n_edges,
            n_calls,
            n_indirect_calls,
            n_mem_reads,
            n_mem_writes,
            n_returns,
        ),
    )


def similarity_score(a: FunctionStructure, b: FunctionStructure) -> float:
    """Jaccard similarity over per-block token-hash multisets, in [0,1].

    ``1.0`` means every block hash matches; ``0.0`` means none do.
    This is the "near-miss" metric — two functions with one changed
    block out of ten score ~0.9, which is the patch-detection signal
    we want to surface in the diff output.
    """
    if not a.block_token_hashes and not b.block_token_hashes:
        return 1.0
    # Multiset Jaccard: treat each (hash, count_in_function) bucket.
    from collections import Counter

    ca, cb = Counter(a.block_token_hashes), Counter(b.block_token_hashes)
    if not ca and not cb:
        return 1.0
    intersect = sum((ca & cb).values())
    union = sum((ca | cb).values())
    if union == 0:
        return 1.0
    return intersect / union


def resolve_iat_map(binary_path: str) -> Dict[int, str]:
    """Best-effort PE IAT map: VA → import name. Empty dict on ELF /
    Mach-O / non-PE / parse failure. Used as a fingerprint-time lookup
    so ``call qword ptr [rip+disp]`` resolves identically across builds
    where the IAT slot moved."""
    try:
        import glaurung as g

        return {int(va): str(name) for (va, name) in g.analysis.pe_iat_map_path(str(binary_path))}
    except Exception:
        return {}
