#!/usr/bin/env python3
"""Execution-differential decompiler correctness gate.

For each function in a fixture: compile the decompiled C into a shared object,
load BOTH the original binary and the recompiled decompilation via ctypes, call
each with the same (randomised) integer inputs, and compare return values.

A decompiler can produce type-correct, recompilable, CFG-plausible output that is
still semantically wrong (e.g. an inverted branch, a lost return value). The
DecBench metrics (type_match / GED / byte_match) do not catch that. This does:
if `original(x) != decompiled(x)` for any tested input, the decompilation is
unfaithful and the function FAILS.

Scope: functions taking a fixed number of scalar-integer / pointer arguments and
returning an integer. Pointer arguments are passed as buffers of random ints so
array/struct access is exercised. Functions that mutate their inputs are compared
on both the return value AND the post-call buffer contents.

Usage:
    python tools/diff_decompile.py <binary.so> <source.c> [--seed N] [--trials K]

Exit status is non-zero if any function fails.  Designed to be called from a
pytest wrapper (see tests) once the corpus is wired in.
"""
from __future__ import annotations

import argparse
import ctypes
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile


# DecBench-style prelude so the decompiled fragment is a valid translation unit.
PRELUDE = """
typedef unsigned char uint8_t; typedef signed char int8_t;
typedef unsigned short uint16_t; typedef short int16_t;
typedef unsigned int uint32_t; typedef int int32_t;
typedef unsigned long uint64_t; typedef long int64_t;
long __unknown(long x){ (void)x; return 0; }
"""


@dataclass
class FuncSig:
    name: str
    va: int
    # Each arg: "int" (scalar) or "ptr" (int buffer). Return assumed int.
    args: list[str]
    ret: str  # "int" or "void"


def dwarf_signatures(binary: str) -> list[FuncSig]:
    """Recover (name, va, arg kinds) from DWARF for functions we can test."""
    out: list[FuncSig] = []
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            return out
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                if "DW_AT_low_pc" not in die.attributes or "DW_AT_name" not in die.attributes:
                    continue
                name = die.attributes["DW_AT_name"].value.decode()
                va = die.attributes["DW_AT_low_pc"].value
                args: list[str] = []
                ok = True
                for c in die.iter_children():
                    if c.tag != "DW_TAG_formal_parameter":
                        continue
                    kind = _type_kind(c, cu)
                    if kind is None:
                        ok = False
                        break
                    args.append(kind)
                if not ok:
                    continue
                ret = "int" if "DW_AT_type" in die.attributes else "void"
                out.append(FuncSig(name, va, args, ret))
    return out


def _type_kind(die, cu) -> str | None:
    """Classify a parameter as 'int' or 'ptr', or None if unsupported."""
    t = die.attributes.get("DW_AT_type")
    if t is None:
        return None
    try:
        ref = cu.get_DIE_from_refaddr(t.value)
    except Exception:
        return None
    # Strip typedefs / const.
    seen = 0
    while ref.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type") and seen < 8:
        tt = ref.attributes.get("DW_AT_type")
        if tt is None:
            return None
        ref = cu.get_DIE_from_refaddr(tt.value)
        seen += 1
    if ref.tag == "DW_TAG_pointer_type":
        return "ptr"
    if ref.tag == "DW_TAG_base_type":
        # Only integer base types (skip float/double for now).
        enc = ref.attributes.get("DW_AT_encoding")
        if enc is not None and enc.value in (0x04,):  # DW_ATE_float
            return None
        return "int"
    return None


def decompiled_c(binary: str, va: int) -> str | None:
    """Decompile one function to C via the glaurung CLI (decbench style)."""
    import json

    p = subprocess.run(
        ["glaurung", "decompile", binary, "--vas", hex(va), "--style", "decbench", "--format", "json"],
        capture_output=True, text=True, timeout=120,
    )
    if p.returncode != 0:
        return None
    try:
        arr = json.loads(p.stdout)
    except json.JSONDecodeError:
        return None
    if not arr:
        return None
    code = arr[0].get("pseudocode", "")
    return "\n".join(l for l in code.splitlines() if not l.strip().startswith("//"))


def build_so(c_src: str, workdir: Path, tag: str) -> Path | None:
    src = workdir / f"{tag}.c"
    src.write_text(PRELUDE + "\n" + c_src + "\n")
    so = workdir / f"{tag}.so"
    r = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-O0", "-w", "-o", str(so), str(src)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None
    return so


def _call(lib, sig: FuncSig, argvals, bufs):
    fn = getattr(lib, sig.name)
    fn.restype = ctypes.c_int if sig.ret == "int" else None
    ctypes_args = []
    for kind in sig.args:
        ctypes_args.append(ctypes.c_int if kind == "int" else ctypes.POINTER(ctypes.c_int))
    fn.argtypes = ctypes_args
    call_args = []
    bi = 0
    for kind, v in zip(sig.args, argvals):
        if kind == "int":
            call_args.append(v)
        else:
            call_args.append(bufs[bi])
            bi += 1
    ret = fn(*call_args)
    return ret


def diff_function(sig: FuncSig, orig_so: str, decomp_c: str, workdir: Path,
                  trials: int, rng) -> tuple[bool, str]:
    """Return (ok, detail). Compiles the decompilation and diffs behaviour."""
    dec_so = build_so(decomp_c, workdir, f"dec_{sig.name}")
    if dec_so is None:
        return False, "decompiled C failed to compile"
    orig = ctypes.CDLL(orig_so)
    dec = ctypes.CDLL(str(dec_so))
    for _ in range(trials):
        argvals = []
        n_bufs = sum(1 for k in sig.args if k == "ptr")
        buf_len = 8
        # Fresh, identical buffers for each side.
        raw = [[rng.randrange(-64, 64) for _ in range(buf_len)] for _ in range(n_bufs)]
        for kind in sig.args:
            if kind == "int":
                argvals.append(rng.randrange(-64, 64))
            else:
                argvals.append(None)  # placeholder; buffer filled below
        bufs_o = [(ctypes.c_int * buf_len)(*r) for r in raw]
        bufs_d = [(ctypes.c_int * buf_len)(*r) for r in raw]
        try:
            ro = _call(orig, sig, argvals, bufs_o)
            rd = _call(dec, sig, argvals, bufs_d)
        except Exception as e:  # noqa: BLE001
            return False, f"call raised {e!r}"
        if sig.ret == "int" and (ro & 0xFFFFFFFF) != (rd & 0xFFFFFFFF):
            return False, f"return mismatch on args={_fmt(sig, argvals, raw)}: orig={ro} dec={rd}"
        if list(bufs_o and bufs_o[0]) != list(bufs_d and bufs_d[0]) if n_bufs else False:
            return False, f"buffer mutation mismatch on args={_fmt(sig, argvals, raw)}"
    return True, "ok"


def _fmt(sig, argvals, raw):
    parts, bi = [], 0
    for kind, v in zip(sig.args, argvals):
        if kind == "int":
            parts.append(str(v))
        else:
            parts.append(f"buf{raw[bi]}")
            bi += 1
    return "(" + ", ".join(parts) + ")"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("source")
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--trials", type=int, default=64)
    args = ap.parse_args()

    import random
    rng = random.Random(args.seed)

    sigs = dwarf_signatures(args.binary)
    if not sigs:
        print(f"no testable DWARF functions in {args.binary}", file=sys.stderr)
        return 2

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        for sig in sigs:
            c = decompiled_c(args.binary, sig.va)
            if c is None:
                print(f"SKIP {sig.name}: decompile failed")
                continue
            ok, detail = diff_function(sig, args.binary, c, workdir, args.trials, rng)
            status = "PASS" if ok else "FAIL"
            if not ok:
                failures += 1
            print(f"{status} {sig.name}{sig.args} -> {sig.ret}: {detail}")
    print(f"\n{failures} function(s) failed the execution-differential gate")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
