"""Cross-binary / module-group reasoning for driver families.

A single ``.glaurung`` is per-binary, but real bug hypotheses cross modules:
during the dxgmms2 investigation the live secondary theory was "dxgmms1
overflows into a pool block owned by dxgmms2" -- the two share the GPU
scheduler pool. There was no way to express "these N modules share a pool".

This module answers that concretely via POOL TAGS. Two drivers that allocate
with the same tag draw from the same pooled lookaside/segment, so an
out-of-bounds write in one can corrupt an adjacent allocation owned by the
other -- exactly the cross-module corruption-at-free signature. We extract,
per module, the set of pool tags it allocates with (the ``Tag`` argument to
``ExAllocatePoolWithTag`` / ``ExAllocatePool2``) and report the tags shared
across members of a group.

Tag extraction reads the ``mov r8d, <imm32>`` that sets the Tag arg before
the allocator call (this immediate IS rendered by the disassembler, unlike
add/and immediates -- see the analyst-ergonomics DIFF, Finding A). Calls
whose tag we cannot resolve are counted so coverage stays honest.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from glaurung.llm.coverage import CoverageFooter

_ABS = re.compile(r"0x[0-9a-fA-F]+")
_ALLOC_NAMES = ("ExAllocatePoolWithTag", "ExAllocatePool2", "ExAllocatePool3",
                "ExAllocatePoolZero", "ExAllocatePoolPriorityZero",
                "ExAllocatePoolQuotaZero")


def _tag_str(imm: int) -> Optional[str]:
    """0x66616956 -> 'Viaf' (4 little-endian ASCII chars), else None."""
    b = struct.pack("<I", imm & 0xFFFFFFFF)
    s = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    # require mostly-printable to avoid treating sizes/flags as tags
    if sum(1 for c in b if 32 <= c < 127) >= 3:
        return s
    return None


def _text_range(binary_path: str) -> Tuple[int, int, int]:
    """(image_base, text_va, text_size) via a minimal PE parse (stdlib)."""
    data = Path(binary_path).read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32_plus = magic == 0x20B
    image_base = struct.unpack_from("<Q" if is_pe32_plus else "<I", data,
                                    opt + (24 if is_pe32_plus else 28))[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    sec_off = opt + opt_size
    best = None
    for i in range(num_sections):
        s = sec_off + i * 40
        name = data[s:s + 8].rstrip(b"\0")
        vsz, va = struct.unpack_from("<II", data, s + 8)
        if name == b".text":
            return image_base, image_base + va, vsz
        if best is None:
            best = (image_base + va, vsz)
    return (image_base, best[0], best[1]) if best else (image_base, image_base, 0)


@dataclass
class ModulePoolFacts:
    name: str
    binary: str
    tags: Dict[str, List[int]] = field(default_factory=dict)  # tag -> alloc site VAs
    alloc_calls: int = 0
    tag_unresolved: int = 0


def pool_tags(binary_path: str, name: Optional[str] = None) -> ModulePoolFacts:
    """Extract pool tags this module allocates with, by VA of the call site."""
    from glaurung.disasm import disassemble_window_at
    from glaurung.llm.kb.structural_fingerprint import resolve_iat_map

    iat = resolve_iat_map(binary_path)
    alloc_slots = {va for va, n in iat.items() if n in _ALLOC_NAMES}
    facts = ModulePoolFacts(name=name or Path(binary_path).name, binary=binary_path)
    if not alloc_slots:
        return facts

    _base, tva, tsz = _text_range(binary_path)
    insns = disassemble_window_at(binary_path, int(tva), window_bytes=int(tsz),
                                  max_instructions=5_000_000, max_time_ms=120_000)
    last_tag: Optional[str] = None
    for i in insns:
        ops = ", ".join(str(o) for o in i.operands)
        mnem = i.mnemonic
        # Tag arg: `mov r8d, 0x........` (or r8). Immediate is rendered.
        if mnem == "mov" and ops.split(",")[0].strip() in ("r8d", "r8"):
            m = _ABS.findall(ops)
            if m:
                last_tag = _tag_str(int(m[-1], 16))
            else:
                last_tag = None
        try:
            is_call = bool(i.is_call())
        except Exception:
            is_call = False
        if is_call and "rip" in ops:
            m = _ABS.findall(ops)
            if m and int(m[-1], 16) in alloc_slots:
                facts.alloc_calls += 1
                if last_tag:
                    facts.tags.setdefault(last_tag, []).append(int(i.address.value))
                else:
                    facts.tag_unresolved += 1
    return facts


@dataclass
class ModuleGroup:
    members: List[ModulePoolFacts] = field(default_factory=list)
    coverage: Optional[CoverageFooter] = None

    @classmethod
    def from_binaries(cls, named_binaries: List[Tuple[str, str]]) -> "ModuleGroup":
        """named_binaries: list of (display_name, binary_path)."""
        grp = cls(members=[pool_tags(b, name=n) for n, b in named_binaries])
        cov = CoverageFooter("module-group/pool-tags")
        cov.fact("members", [m.name for m in grp.members])
        cov.fact("alloc call sites", {m.name: m.alloc_calls for m in grp.members})
        cov.fact("distinct tags", {m.name: len(m.tags) for m in grp.members})
        unresolved = {m.name: m.tag_unresolved for m in grp.members if m.tag_unresolved}
        if unresolved:
            cov.caveat(
                "alloc sites with an unresolved tag (tag in a register / "
                "computed, not a literal mov r8d,imm): "
                + ", ".join(f"{k}={v}" for k, v in unresolved.items())
            )
        cov.caveat(
            "shared TAG implies a shared pool surface, NOT a proven overflow "
            "path; it scopes where a cross-module corruption COULD land"
        )
        cov.caveat(
            "only ExAllocatePool* tag args are modeled; lookaside lists, "
            "ExInitializeNPagedLookasideList, and segment-heap buckets are not"
        )
        grp.coverage = cov
        return grp

    def shared_tags(self) -> Dict[str, Dict[str, int]]:
        """tag -> {member_name: alloc_site_count} for tags used by >1 member."""
        by_tag: Dict[str, Dict[str, int]] = {}
        for m in self.members:
            for tag, vas in m.tags.items():
                by_tag.setdefault(tag, {})[m.name] = len(vas)
        return {t: d for t, d in by_tag.items() if len(d) > 1}

    def render(self) -> str:
        out = ["; module-group pool-tag analysis"]
        for m in self.members:
            out.append(f";   {m.name}: {len(m.tags)} tags, {m.alloc_calls} alloc sites")
        shared = self.shared_tags()
        out.append(f"; SHARED pool tags ({len(shared)}) -- cross-module corruption surface:")
        for tag in sorted(shared):
            members = ", ".join(f"{k}({v})" for k, v in sorted(shared[tag].items()))
            out.append(f"  '{tag}': {members}")
        if not shared:
            out.append("  (none shared)")
        if self.coverage is not None:
            out.append("")
            out.append(self.coverage.render())
        return "\n".join(out)

    def to_dict(self) -> dict:
        return {
            "members": [
                {"name": m.name, "binary": m.binary, "alloc_calls": m.alloc_calls,
                 "tag_unresolved": m.tag_unresolved,
                 "tags": {t: vs for t, vs in m.tags.items()}}
                for m in self.members
            ],
            "shared_tags": self.shared_tags(),
            "coverage": self.coverage.to_dict() if self.coverage else None,
        }
