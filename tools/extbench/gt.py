#!/usr/bin/env python3
"""Extract ground truth from a sample ELF: DWARF subprograms, .eh_frame FDEs, PLT map.

Run with the DecBench venv python (has pyelftools).

    gt.py <binary> > gt.json

Two independent references, deliberately kept apart:

* ``dwarf`` — only present on the handful of Alpine binaries that shipped
  unstripped. Gives names, entry VAs, and parameter types, so it is the only
  thing here that can score *prototype* recovery.
* ``fde`` — .eh_frame FDE start addresses. Present on essentially every sample.
  It is a SOUND but INCOMPLETE reference: every FDE start is a real function
  entry, but hand-written asm and some PLT-adjacent stubs have no FDE. So it
  supports a recall claim and never a false-positive claim.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


def elf_min_vaddr(elf: ELFFile) -> int:
    """Lowest PT_LOAD vaddr — the file-image base a PIE is linked against."""
    loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    return min((s["p_vaddr"] for s in loads), default=0)


def dwarf_functions(elf: ELFFile) -> list[dict]:
    """Subprograms with code: name, entry VA, parameter type names, return type."""
    if not elf.has_dwarf_info():
        return []
    dw = elf.get_dwarf_info()
    out: list[dict] = []

    def type_name(die, depth: int = 0) -> str:
        if die is None or depth > 8:
            return "?"
        ref = die.attributes.get("DW_AT_type")
        if ref is None:
            return "void"
        try:
            t = die.get_DIE_from_attribute("DW_AT_type")
        except Exception:
            return "?"
        tag = t.tag
        if tag == "DW_TAG_pointer_type":
            return type_name(t, depth + 1) + "*"
        if tag in ("DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_typedef"):
            nm = t.attributes.get("DW_AT_name")
            if tag == "DW_TAG_typedef" and nm:
                return nm.value.decode()
            return type_name(t, depth + 1)
        nm = t.attributes.get("DW_AT_name")
        if nm:
            return nm.value.decode()
        return tag.replace("DW_TAG_", "")

    for cu in dw.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram":
                continue
            low = die.attributes.get("DW_AT_low_pc")
            name = die.attributes.get("DW_AT_name")
            if low is None or name is None:
                continue
            high = die.attributes.get("DW_AT_high_pc")
            size = None
            if high is not None:
                # DWARF4+ encodes high_pc as an offset when its form is a
                # constant class, and as an address when it is addr class.
                size = (
                    high.value
                    if high.form not in ("DW_FORM_addr",)
                    else high.value - low.value
                )
            params = []
            for child in die.iter_children():
                if child.tag == "DW_TAG_formal_parameter":
                    params.append(type_name(child))
            out.append(
                {
                    "name": name.value.decode(),
                    "va": low.value,
                    "size": size,
                    "params": params,
                    "ret": type_name(die),
                }
            )
    # Same function can appear per-CU; keep one entry per VA.
    dedup: dict[int, dict] = {}
    for f in out:
        dedup.setdefault(f["va"], f)
    return sorted(dedup.values(), key=lambda f: f["va"])


def fde_starts(elf: ELFFile) -> list[dict]:
    """(start, size) for every .eh_frame FDE — a sound, incomplete function set."""
    if not elf.has_dwarf_info():
        return []
    dw = elf.get_dwarf_info()
    out = []
    try:
        eh = dw.EH_CFI_entries()
    except Exception:
        return []
    from elftools.dwarf.callframe import FDE

    for entry in eh:
        if isinstance(entry, FDE):
            out.append(
                {
                    "va": entry.header["initial_location"],
                    "size": entry.header["address_range"],
                }
            )
    return sorted(out, key=lambda e: e["va"])


def plt_imports(elf: ELFFile) -> dict:
    """Names of dynamically imported functions — used to sanity-check naming."""
    names = []
    sec = elf.get_section_by_name(".dynsym")
    if sec is not None:
        for sym in sec.iter_symbols():
            if sym["st_info"]["type"] == "STT_FUNC" and sym["st_shndx"] == "SHN_UNDEF":
                names.append(sym.name)
    return sorted({n for n in names if n})


def main(argv: list[str]) -> int:
    path = Path(argv[1])
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        payload = {
            "binary": str(path),
            "arch": elf.get_machine_arch(),
            "bits": elf.elfclass,
            "pie": elf.header["e_type"] == "ET_DYN",
            "min_vaddr": elf_min_vaddr(elf),
            "entry": elf.header["e_entry"],
            "size": path.stat().st_size,
            "dwarf": dwarf_functions(elf),
            "fde": fde_starts(elf),
            "imports": plt_imports(elf),
        }
    json.dump(payload, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
