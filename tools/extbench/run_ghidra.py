#!/usr/bin/env python3
"""Ghidra runner: discover functions and decompile them, emitting the common JSON.

    run_ghidra.py <ghidra_dir> <binary> <out.json> [--vas 0x..,0x..] [--timeout S]

Addresses are normalised to *file* VAs. Ghidra relocates a PIE to 0x100000, so
every address it reports is shifted by (image_base - lowest PT_LOAD vaddr); that
delta is subtracted before anything is written out, otherwise no address here
would line up with DWARF or with the other three tools.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time

ghidra_dir, binary, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
vas: list[int] = []
per_func_timeout = 60
argv = sys.argv[4:]
for i, a in enumerate(argv):
    if a == "--vas" and i + 1 < len(argv):
        vas = [int(x, 0) for x in argv[i + 1].split(",") if x]
    if a == "--timeout" and i + 1 < len(argv):
        per_func_timeout = int(argv[i + 1])

os.environ.setdefault("GHIDRA_INSTALL_DIR", ghidra_dir)

from elftools.elf.elffile import ELFFile

with open(binary, "rb") as fh:
    elf = ELFFile(fh)
    min_vaddr = min(
        (s["p_vaddr"] for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"),
        default=0,
    )

import pyghidra

pyghidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

result = {
    "tool": "ghidra",
    "binary": binary,
    "functions": [],
    "error": None,
    "analyze_s": None,
    "decompile_s": None,
}

project_dir = tempfile.mkdtemp(prefix="ghidra-bench-")

t0 = time.time()
try:
    # An explicit project location, for two reasons. pyghidra defaults it to the
    # binary's own directory, which (a) writes a `<name>_ghidra` project into
    # whatever tree the sample came from — here, the user's read-only-by-intent
    # data share — and (b) is REUSED on the next run, so a second measurement of
    # the same binary skips auto-analysis entirely and reports Ghidra as several
    # times faster than it is. A fresh directory per run keeps the timing honest
    # and keeps the sample tree clean.
    with pyghidra.open_program(
        binary, analyze=True, project_location=project_dir, project_name="bench"
    ) as api:
        prog = api.getCurrentProgram()
        result["analyze_s"] = time.time() - t0
        result["version"] = str(prog.getMetadata().get("Created With Ghidra Version"))
        delta = prog.getImageBase().getOffset() - min_vaddr

        fm = prog.getFunctionManager()
        # Discovery set: every function Ghidra believes exists in the image.
        discovered = []
        for f in fm.getFunctions(True):
            discovered.append(
                {
                    "va": f.getEntryPoint().getOffset() - delta,
                    "name": f.getName(),
                    "thunk": bool(f.isThunk()),
                    "external": bool(f.isExternal()),
                }
            )
        result["discovered"] = discovered

        d = DecompInterface()
        d.openProgram(prog)
        mon = ConsoleTaskMonitor()

        if vas:
            targets = []
            space = prog.getAddressFactory().getDefaultAddressSpace()
            for va in vas:
                addr = space.getAddress(va + delta)
                fn = fm.getFunctionAt(addr)
                if fn is None:
                    fn = fm.getFunctionContaining(addr)
                    # Only accept a containing function when it starts here.
                    if fn is not None and fn.getEntryPoint().getOffset() != va + delta:
                        fn = None
                targets.append((va, fn))
        else:
            targets = [
                (f.getEntryPoint().getOffset() - delta, f)
                for f in fm.getFunctions(True)
                if not f.isExternal()
            ]

        t1 = time.time()
        for va, fn in targets:
            if fn is None:
                result["functions"].append(
                    {"va": va, "name": None, "code": None, "status": "not_found"}
                )
                continue
            try:
                r = d.decompileFunction(fn, per_func_timeout, mon)
                if r.decompileCompleted():
                    result["functions"].append(
                        {
                            "va": va,
                            "name": fn.getName(),
                            "code": r.getDecompiledFunction().getC(),
                            "status": "ok",
                        }
                    )
                else:
                    result["functions"].append(
                        {
                            "va": va,
                            "name": fn.getName(),
                            "code": None,
                            "status": "failed:" + str(r.getErrorMessage()),
                        }
                    )
            except Exception as exc:
                result["functions"].append(
                    {
                        "va": va,
                        "name": fn.getName(),
                        "code": None,
                        "status": f"exc:{exc}",
                    }
                )
        result["decompile_s"] = time.time() - t1
except Exception as exc:
    result["error"] = f"{type(exc).__name__}: {exc}"

result["total_s"] = time.time() - t0
shutil.rmtree(project_dir, ignore_errors=True)
with open(out_path, "w") as fh:
    json.dump(result, fh)
print(f"ghidra: {len(result['functions'])} functions in {result['total_s']:.1f}s")
