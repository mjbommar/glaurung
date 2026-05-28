"""ASB-contributed tail-call augmentation for Glaurung function discovery.

Adds entry VAs discovered via capstone tail-call analysis to the
analyze_functions_path_with_stats output. Sits beside Glaurung's
existing tail_call_seeds_inserted pass and catches the discoveries
that pass misses (jumps to non-pdata-head addresses that have no
fallthrough caller).

Called by scripts/windows_ghidra_parity.py to produce the augmented
entry_vas list reported in parity-output JSON.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import capstone  # type: ignore


# Borrowed from the ASB extractor; PE section walk for VA->file-offset.
import struct as _struct


def _read_pe_section_map(pe_bytes: bytes):
    e_lfanew = _struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    fh_off = e_lfanew + 4
    num_sections = _struct.unpack_from("<H", pe_bytes, fh_off + 2)[0]
    opt_hdr_size = _struct.unpack_from("<H", pe_bytes, fh_off + 16)[0]
    opt_off = fh_off + 20
    magic = _struct.unpack_from("<H", pe_bytes, opt_off)[0]
    image_base = (_struct.unpack_from("<Q", pe_bytes, opt_off + 24)[0]
                  if magic == 0x20b else
                  _struct.unpack_from("<I", pe_bytes, opt_off + 28)[0])
    sect_off = opt_off + opt_hdr_size
    sections = []
    for i in range(num_sections):
        s = sect_off + i * 40
        virt_size = _struct.unpack_from("<I", pe_bytes, s + 8)[0]
        virt_addr = _struct.unpack_from("<I", pe_bytes, s + 12)[0]
        raw_size = _struct.unpack_from("<I", pe_bytes, s + 16)[0]
        raw_off = _struct.unpack_from("<I", pe_bytes, s + 20)[0]
        sections.append((virt_addr, virt_size, raw_off, raw_size))
    return image_base, sections


def _va_to_file_offset(image_base, sections, va):
    rva = va - image_base
    for virt_addr, virt_size, raw_off, raw_size in sections:
        if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
            return raw_off + (rva - virt_addr)
    return None


def augment_entries(pe_path: Path, baseline_entries: Iterable[int],
                    max_fn_bytes: int = 4096) -> set[int]:
    """Return augmented entry set = baseline ∪ {tail-call targets}."""
    pe_bytes = Path(pe_path).read_bytes()
    image_base, sections = _read_pe_section_map(pe_bytes)
    sorted_entries = sorted(set(baseline_entries))
    fn_ranges: dict[int, tuple[int, int]] = {}
    for i, va in enumerate(sorted_entries):
        nxt = sorted_entries[i + 1] if i + 1 < len(sorted_entries) else va + max_fn_bytes
        end = min(nxt - 1, va + max_fn_bytes - 1)
        fn_ranges[va] = (va, end)
    known = set(sorted_entries)
    discoveries: set[int] = set()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    for fn_va in sorted_entries:
        lo, hi = fn_ranges[fn_va]
        off = _va_to_file_offset(image_base, sections, fn_va)
        if off is None:
            continue
        body_size = min(hi - lo + 1, max_fn_bytes)
        body = pe_bytes[off:off + body_size]
        for ins in md.disasm(body, fn_va):
            if ins.mnemonic.lower() != "jmp":
                continue
            try:
                ops = ins.operands
            except Exception:
                continue
            if not ops or ops[0].type != capstone.x86.X86_OP_IMM:
                continue
            target = ops[0].imm
            if lo <= target <= hi:
                continue
            if target in known or target in discoveries:
                continue
            # Validate target is in an executable-ish section
            tgt_off = _va_to_file_offset(image_base, sections, target)
            if tgt_off is None:
                continue
            discoveries.add(target)
            break
    return set(sorted_entries) | discoveries
