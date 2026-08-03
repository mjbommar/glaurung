#!/usr/bin/env python3
"""angr runner: CFGFast discovery + Decompiler, emitting the common JSON.

    run_angr.py <binary> <out.json> [--vas 0x..,0x..] [--timeout S]

cle maps a PIE at 0x400000, so addresses are shifted back by ``mapped_base``
before being written, matching the file VAs the other runners emit.

A per-function failure is recorded, never swallowed: a decompiler that skips the
functions it cannot handle would otherwise score a perfect success rate.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import time

for name in ("angr", "cle", "pyvex", "claripy", "ailment"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

binary, out_path = sys.argv[1], sys.argv[2]
vas: list[int] = []
per_func_timeout = 60
argv = sys.argv[3:]
for i, a in enumerate(argv):
    if a == "--vas" and i + 1 < len(argv):
        vas = [int(x, 0) for x in argv[i + 1].split(",") if x]
    if a == "--timeout" and i + 1 < len(argv):
        per_func_timeout = int(argv[i + 1])


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)

import angr
from elftools.elf.elffile import ELFFile

# On 32-bit ARM, angr follows the Thumb convention and reports a Thumb function
# at `entry | 1`, while DWARF's DW_AT_low_pc is the even address. Comparing the
# two literally scores a tool that found 19 of 22 functions as having found one.
# Bit 0 is an instruction-set flag there, not an address bit, so it is cleared
# on that architecture only — doing it everywhere would silently merge two
# genuinely distinct x86 addresses.
with open(binary, "rb") as _fh:
    _is_arm32 = ELFFile(_fh).get_machine_arch() == "ARM"


def norm(addr: int) -> int:
    return (addr & ~1) if _is_arm32 else addr


result = {
    "tool": "angr",
    "binary": binary,
    "version": angr.__version__,
    "functions": [],
    "error": None,
    "analyze_s": None,
    "decompile_s": None,
}

t0 = time.time()
try:
    proj = angr.Project(binary, auto_load_libs=False)
    base = proj.loader.main_object.mapped_base
    cfg = proj.analyses.CFGFast(normalize=True)
    result["analyze_s"] = time.time() - t0

    all_funcs = {norm(f.addr - base): f for f in proj.kb.functions.values()}
    result["discovered"] = [
        {
            "va": va,
            "name": f.name,
            "thunk": bool(f.is_plt),
            "external": bool(f.is_simprocedure),
        }
        for va, f in sorted(all_funcs.items())
    ]

    targets = (
        [(va, all_funcs.get(va)) for va in vas]
        if vas
        else [
            (va, f)
            for va, f in sorted(all_funcs.items())
            if not (f.is_plt or f.is_simprocedure or f.is_alignment)
        ]
    )

    t1 = time.time()
    for va, func in targets:
        if func is None:
            result["functions"].append(
                {"va": va, "name": None, "code": None, "status": "not_found"}
            )
            continue
        signal.alarm(per_func_timeout)
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            code = getattr(dec, "codegen", None)
            if code is None or not getattr(code, "text", None):
                result["functions"].append(
                    {"va": va, "name": func.name, "code": None, "status": "no_codegen"}
                )
            else:
                result["functions"].append(
                    {"va": va, "name": func.name, "code": code.text, "status": "ok"}
                )
        except Timeout:
            result["functions"].append(
                {"va": va, "name": func.name, "code": None, "status": "timeout"}
            )
        except Exception as exc:
            result["functions"].append(
                {
                    "va": va,
                    "name": func.name,
                    "code": None,
                    "status": f"exc:{type(exc).__name__}: {exc}"[:300],
                }
            )
        finally:
            signal.alarm(0)
    result["decompile_s"] = time.time() - t1
except Exception as exc:
    result["error"] = f"{type(exc).__name__}: {exc}"

result["total_s"] = time.time() - t0
with open(out_path, "w") as fh:
    json.dump(result, fh)
print(f"angr: {len(result['functions'])} functions in {result['total_s']:.1f}s")
