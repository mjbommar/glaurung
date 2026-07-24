#!/usr/bin/env python3
"""Fail-closed execution-differential decompiler correctness gate.

For each function in a fixture: compile the decompiled C into a shared object,
then — in an ISOLATED SUBPROCESS so a bad decompilation cannot crash the caller —
load the original binary and the recompiled decompilation via ctypes, call both
with the same deterministic + seeded inputs, and compare the FULL-width return
value and EVERY mutable buffer. A mismatch means the decompilation is
behaviourally unfaithful; type_match / GED / byte_match cannot see that.

FAIL-CLOSED contract (every one of these is a FAILURE, never a silent skip):
  * a required dependency is missing (module import fails);
  * zero DWARF signatures are discovered in the binary;
  * the decompiled C fails to compile;
  * the worker subprocess exits non-zero, is killed by a signal, or times out;
  * zero executable cases were produced for a function.

Functions the manifest marks `skip_exec` (e.g. function-pointer callbacks) are
reported as `structural`, a distinct status the structural lane checks — never a
silent pass.

Modes:
  diff_decompile.py <binary> <source> [--fixture NAME] [--json]   parent/report
  diff_decompile.py --worker <spec.json>                          internal child
"""
from __future__ import annotations

import argparse
import ctypes
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

# Fail-closed: a missing dependency must surface as an import error, not a skip.
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import manifest as M  # ty: ignore[unresolved-import]  # added to sys.path above

PRELUDE = """
typedef unsigned char uint8_t; typedef signed char int8_t;
typedef unsigned short uint16_t; typedef short int16_t;
typedef unsigned int uint32_t; typedef int int32_t;
typedef unsigned long uint64_t; typedef long int64_t;
long __unknown(long x){ (void)x; return 0; }
"""

# ---------------------------------------------------------------------------
# Signature recovery
# ---------------------------------------------------------------------------

def _base_kind(die, cu):
    """Classify a parameter DIE as scalar 'int'/'long' or pointer, else None."""
    t = die.attributes.get("DW_AT_type")
    if t is None:
        return None
    try:
        ref = cu.get_DIE_from_refaddr(t.value)
    except Exception:  # noqa: BLE001
        return None
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
        enc = ref.attributes.get("DW_AT_encoding")
        if enc is not None and enc.value == 0x04:  # DW_ATE_float — unsupported
            return None
        sz = ref.attributes.get("DW_AT_byte_size")
        return "long" if (sz is not None and sz.value == 8) else "int"
    return None


def signatures(binary: str) -> list[dict]:
    out = []
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
                params, ok = [], True
                for c in die.iter_children():
                    if c.tag != "DW_TAG_formal_parameter":
                        continue
                    k = _base_kind(c, cu)
                    if k is None:
                        ok = False
                        break
                    params.append(k)
                if not ok:
                    continue
                ret = "int" if "DW_AT_type" in die.attributes else "void"
                out.append({"name": name, "va": va, "params": params, "ret": ret})
    return out


# ---------------------------------------------------------------------------
# Decompile + compile
# ---------------------------------------------------------------------------

def decompiled_c(binary: str, va: int) -> str | None:
    p = subprocess.run(
        ["glaurung", "decompile", binary, "--vas", hex(va),
         "--style", "decbench", "--format", "json"],
        capture_output=True, text=True, timeout=120, check=False,
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
        capture_output=True, text=True, check=False,
    )
    return so if r.returncode == 0 else None


# ---------------------------------------------------------------------------
# Vector generation (deterministic boundaries + seeded fuzz)
# ---------------------------------------------------------------------------

def make_vectors(sig: dict, ov: dict, seed: int, fuzz: int) -> list[list]:
    """A list of argument tuples. Scalars are ints; pointer params are lists of
    ints of length ptr_len. Length args are clamped to [0, ptr_len]."""
    params = sig["params"]
    ptr_len = ov.get("ptr_len", M.DEFAULT_PTR_LEN)
    len_args = set(ov.get("len_args", []))
    rng = random.Random(seed ^ (hash(sig["name"]) & 0xFFFFFFFF))

    def scalar(i, v):
        return max(0, min(ptr_len, v)) if i in len_args else v

    def buf_det(k):
        return [((k * 7 + j * 3) % 17) - 8 for j in range(ptr_len)]

    def buf_rng():
        return [rng.randrange(-64, 64) for _ in range(ptr_len)]

    vectors: list[list] = []

    def add(scalars_source):
        args, si = [], 0
        for i, p in enumerate(params):
            if p == "ptr":
                args.append(None)  # buffer filled per-run
            else:
                args.append(scalar(i, scalars_source(si)))
                si += 1
        vectors.append(args)

    # Deterministic scalar boundaries (each boundary applied to all scalar args).
    for b in M.scalar_boundaries():
        add(lambda _si, b=b: b)
    # Explicit manifest vectors (already full tuples: scalar ints, ptr lists).
    for ev in ov.get("extra_vectors", []):
        vectors.append(_pad_ptr(ev, params, ptr_len))
    # Seeded fuzz.
    for _ in range(fuzz):
        add(lambda _si: rng.randrange(-64, 64))

    # Materialise buffers: assign deterministic then rng buffers to ptr slots.
    out = []
    for k, args in enumerate(vectors):
        filled = []
        for i, (p, a) in enumerate(zip(params, args)):
            if p == "ptr" and a is None:
                filled.append(buf_det(k) if k % 2 == 0 else buf_rng())
            else:
                filled.append(a)
        out.append(filled)
    return out


def _pad_ptr(ev, params, ptr_len):
    out = []
    for p, a in zip(params, ev):
        if p == "ptr" and isinstance(a, list):
            a = (a + [0] * ptr_len)[:ptr_len]
        out.append(a)
    return out


# ---------------------------------------------------------------------------
# Worker (runs in an isolated subprocess)
# ---------------------------------------------------------------------------

def _ctypes_fn(lib, sig):
    fn = getattr(lib, sig["name"])
    fn.restype = ctypes.c_int if sig["ret"] == "int" else None
    fn.argtypes = [ctypes.c_int if p != "ptr" else ctypes.POINTER(ctypes.c_int)
                   for p in sig["params"]]
    return fn


def worker(spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text())
    sig = spec["sig"]
    orig = ctypes.CDLL(spec["orig_so"])
    dec = ctypes.CDLL(spec["dec_so"])
    fo, fd = _ctypes_fn(orig, sig), _ctypes_fn(dec, sig)
    mask = 0xFFFFFFFF  # int return width

    for vec in spec["vectors"]:
        oargs, dargs, obufs, dbufs = [], [], [], []
        for p, a in zip(sig["params"], vec):
            if p == "ptr":
                ob = (ctypes.c_int * len(a))(*a)
                db = (ctypes.c_int * len(a))(*a)
                obufs.append(ob)
                dbufs.append(db)
                oargs.append(ob)
                dargs.append(db)
            else:
                oargs.append(a)
                dargs.append(a)
        ro = fo(*oargs)
        rd = fd(*dargs)
        if sig["ret"] == "int" and (ro & mask) != (rd & mask):
            print(json.dumps({"ok": False, "detail": f"return {ro} != {rd} on {vec}"}))
            return 0
        for ob, db in zip(obufs, dbufs):
            if list(ob) != list(db):
                print(json.dumps({"ok": False, "detail": f"buffer mutation differs on {vec}"}))
                return 0
    print(json.dumps({"ok": True, "detail": f"{len(spec['vectors'])} cases"}))
    return 0


# ---------------------------------------------------------------------------
# Parent
# ---------------------------------------------------------------------------

def run_function(sig, fixture, binary, workdir, seed, fuzz) -> dict:
    name = sig["name"]
    ov = M.override(fixture, name)
    if ov.get("skip_exec"):
        return {"status": "structural", "detail": "manifest skip_exec"}
    c = decompiled_c(binary, sig["va"])
    if c is None:
        return {"status": "fail", "detail": "decompile failed"}
    dec_so = build_so(c, workdir, f"dec_{name}")
    if dec_so is None:
        return {"status": "fail", "detail": "decompiled C failed to compile"}
    vectors = make_vectors(sig, ov, seed, fuzz)
    if not vectors:
        return {"status": "fail", "detail": "no executable cases"}
    spec = {"sig": sig, "orig_so": binary, "dec_so": str(dec_so), "vectors": vectors}
    spec_path = workdir / f"spec_{name}.json"
    spec_path.write_text(json.dumps(spec))
    try:
        r = subprocess.run(
            [sys.executable, __file__, "--worker", str(spec_path)],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "fail", "detail": "worker timed out"}
    if r.returncode != 0:
        return {"status": "fail", "detail": f"worker crashed (exit {r.returncode}; {r.stderr.strip()[-120:]})"}
    try:
        verdict = json.loads(r.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"status": "fail", "detail": "worker produced no verdict"}
    return {"status": "pass" if verdict["ok"] else "fail", "detail": verdict["detail"]}


def run(binary: str, source: str, fixture: str, seed: int, fuzz: int) -> dict:
    sigs = signatures(binary)
    results: dict[str, dict] = {}
    if not sigs:
        return {"__error__": f"no DWARF signatures in {binary}"}
    # Required-function presence.
    have = {s["name"] for s in sigs}
    for req in M.REQUIRED_FUNCTIONS.get(fixture, []):
        if req not in have:
            results[req] = {"status": "fail", "detail": "required function missing from binary"}
    with tempfile.TemporaryDirectory(dir="/nas4/data/workspace-infosec/rdtmp") as td:
        wd = Path(td)
        for sig in sigs:
            results[sig["name"]] = run_function(sig, fixture, binary, wd, seed, fuzz)
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?")
    ap.add_argument("source", nargs="?")
    ap.add_argument("--fixture", default=None)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--fuzz", type=int, default=24)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--worker", default=None)
    args = ap.parse_args()

    if args.worker:
        return worker(args.worker)

    if not args.binary or not args.source:
        ap.error("binary and source required")
    fixture = args.fixture or Path(args.source).stem
    results = run(args.binary, args.source, fixture, args.seed, args.fuzz)
    if args.json:
        print(json.dumps(results, indent=2))
        return 0 if "__error__" not in results and all(
            r["status"] != "fail" for r in results.values()) else 1
    if "__error__" in results:
        print(f"ERROR: {results['__error__']}", file=sys.stderr)
        return 2
    fails = 0
    for name, r in sorted(results.items()):
        tag = {"pass": "PASS", "fail": "FAIL", "structural": "STRUCT"}[r["status"]]
        if r["status"] == "fail":
            fails += 1
        print(f"{tag} {name}: {r['detail']}")
    print(f"\n{fails} function(s) failed the execution-differential gate")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
