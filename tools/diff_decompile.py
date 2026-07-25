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
import hashlib
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
sys.path.insert(0, str(ROOT / "tools"))
import fixture_toolchain as TC  # ty: ignore[unresolved-import]  # added to sys.path above
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

# Encodings we accept as integer scalars (float/complex are unsupported).
_SIGNED_ENC = {0x05, 0x06, 0x0D}          # signed, signed_char, signed_fixed
_UNSIGNED_ENC = {0x02, 0x07, 0x08, 0x0E}  # boolean, unsigned, unsigned_char, unsigned_fixed


def _resolve(ref, cu, drop_cv: bool):
    """Peel typedef (and optionally const/volatile) wrappers; report const seen."""
    const = False
    for _ in range(16):
        tag = ref.tag
        if tag == "DW_TAG_const_type":
            const = True
        elif tag not in ("DW_TAG_typedef", "DW_TAG_volatile_type") or not drop_cv and tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
            break
        tt = ref.attributes.get("DW_AT_type")
        if tt is None:
            return None, const  # e.g. `const void`
        ref = cu.get_DIE_from_refaddr(tt.value)
    return ref, const


def _scalar_desc(ref):
    """{'k':'int','w':width,'s':signed} for a base integer type, else None."""
    if ref is None or ref.tag != "DW_TAG_base_type":
        return None
    enc = ref.attributes.get("DW_AT_encoding")
    if enc is None or enc.value not in (_SIGNED_ENC | _UNSIGNED_ENC):
        return None
    sz = ref.attributes.get("DW_AT_byte_size")
    w = sz.value if sz is not None else 4
    if w not in (1, 2, 4, 8):
        return None
    return {"k": "int", "w": w, "s": enc.value in _SIGNED_ENC}


def _type_desc(type_attr, cu):
    """Full descriptor for a DWARF type reference, or None if unsupported.

      scalar : {'k':'int','w':1|2|4|8,'s':bool}
      pointer: {'k':'ptr','pw':pointee_width,'ps':pointee_signed,'const':bool}
    """
    if type_attr is None:
        return {"k": "void"}
    try:
        ref = cu.get_DIE_from_refaddr(type_attr.value)
    except Exception:  # noqa: BLE001
        return None
    ref, _ = _resolve(ref, cu, drop_cv=True)
    if ref is None:
        return None
    if ref.tag == "DW_TAG_pointer_type":
        pt = ref.attributes.get("DW_AT_type")
        if pt is None:
            return {"k": "ptr", "pw": 1, "ps": False, "const": False}  # void*
        try:
            pref = cu.get_DIE_from_refaddr(pt.value)
        except Exception:  # noqa: BLE001
            return None
        pref2, const = _resolve(pref, cu, drop_cv=True)
        sd = _scalar_desc(pref2)
        if sd is None:
            return None  # pointer to struct/func/etc — not int-differential
        return {"k": "ptr", "pw": sd["w"], "ps": sd["s"], "const": const}
    return _scalar_desc(ref)


def exported_functions(binary: str) -> dict[str, int]:
    """Dynamically-exported function symbols -> virtual address (what ctypes can
    load). This is the authoritative function list at ANY optimization level: at
    O2 the DWARF is fragmented (ranges/abstract-origin, no direct low_pc), but the
    dynamic symbol table always carries name->address. Static/internal functions
    are absent, so we never call one and never record a bogus load failure."""
    out: dict[str, int] = {}
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        dyn = elf.get_section_by_name(".dynsym")
        if dyn is None:
            return out
        for sym in dyn.iter_symbols():  # ty: ignore[unresolved-attribute]  # SymbolTableSection
            info = sym["st_info"]
            if (info["type"] in ("STT_FUNC", "STT_GNU_IFUNC")
                    and info["bind"] in ("STB_GLOBAL", "STB_WEAK")
                    and sym["st_shndx"] != "SHN_UNDEF"):
                out[sym.name] = sym["st_value"]
    return out


def exported_symbols(binary: str) -> set[str]:
    return set(exported_functions(binary))


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
                    d = _type_desc(c.attributes.get("DW_AT_type"), cu)
                    if d is None or d.get("k") == "void":
                        ok = False
                        break
                    params.append(d)
                if not ok:
                    continue
                ret = _type_desc(die.attributes.get("DW_AT_type"), cu)
                if ret is None:
                    continue  # unsupported return type
                out.append({"name": name, "va": va, "params": params, "ret": ret})
    return out


# String shorthands accepted in hand-written sigs (tests) -> full descriptors.
_STR_DESC = {
    "int": {"k": "int", "w": 4, "s": True},
    "uint": {"k": "int", "w": 4, "s": False},
    "long": {"k": "int", "w": 8, "s": True},
    "ulong": {"k": "int", "w": 8, "s": False},
    "ptr": {"k": "ptr", "pw": 4, "ps": True, "const": False},
    "void": {"k": "void"},
}


def _as_desc(x):
    return dict(_STR_DESC[x]) if isinstance(x, str) else x


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
    """Rebuild our decompiled C. Compiled under the PINNED toolchain: whether a
    given rendering compiles at all is compiler-version dependent (gcc >= 14 turns
    implicit declarations and int/pointer conversions into hard errors that gcc 11
    only warns about), so a host gcc would make the `decompiled C failed to
    compile` verdict — and therefore the baseline — host-specific."""
    src = workdir / f"{tag}.c"
    src.write_text(PRELUDE + "\n" + c_src + "\n")
    so = workdir / f"{tag}.so"
    r = TC.run(["gcc", "-shared", "-fPIC", "-O0", "-w", "-o", str(so), str(src)])
    return so if r.returncode == 0 else None


# ---------------------------------------------------------------------------
# Vector generation (deterministic boundaries + seeded fuzz)
# ---------------------------------------------------------------------------

def _stable_seed(name: str, seed: int) -> int:
    """A per-function seed that is IDENTICAL across processes. Python's built-in
    hash() of a str is randomized by PYTHONHASHSEED, so `hash(name)` produced
    different fuzz vectors in every fresh interpreter — the fuzz was not
    reproducible. A SHA-256 digest is stable, so re-running the gate (or a CI
    lane on another machine) exercises exactly the same inputs."""
    digest = hashlib.sha256(name.encode()).digest()
    return (seed ^ int.from_bytes(digest[:8], "big")) & 0xFFFFFFFFFFFFFFFF


def make_vectors(sig: dict, ov: dict, seed: int, fuzz: int) -> list[list]:
    """A list of argument tuples. Scalars are ints; pointer params are lists of
    element values of length ptr_len. Length args are clamped to [0, ptr_len].
    Pointer element type/range follow the DWARF pointee width (1B -> 0..255,
    else signed 4B fuzz); ov["ptr_elem"] may force "u8". Scalar boundaries are
    width- and signedness-aware so a 64-bit return's high half and a signed
    extension are actually exercised."""
    params = [_as_desc(p) for p in sig["params"]]
    ptr_len = ov.get("ptr_len", M.DEFAULT_PTR_LEN)
    len_args = set(ov.get("len_args", []))
    forced_u8 = ov.get("ptr_elem") == "u8"
    rng = random.Random(_stable_seed(sig["name"], seed))

    def is_u8(d):
        return forced_u8 or d.get("pw") == 1

    def scalar(i, v, d):
        v = _wrap(v, d["w"], d["s"])
        return max(0, min(ptr_len, v)) if i in len_args else v

    def buf_det(k, d):
        if is_u8(d):
            return [(k * 7 + j * 3) % 256 for j in range(ptr_len)]
        return [((k * 7 + j * 3) % 17) - 8 for j in range(ptr_len)]

    def buf_rng(d):
        lo, hi = (0, 256) if is_u8(d) else (-64, 64)
        return [rng.randrange(lo, hi) for _ in range(ptr_len)]

    vectors: list[list] = []

    def add(scalars_source):
        args, si = [], 0
        for i, d in enumerate(params):
            if d["k"] == "ptr":
                args.append(None)  # buffer filled per-run
            else:
                args.append(scalar(i, scalars_source(si), d))
                si += 1
        vectors.append(args)

    # Deterministic scalar boundaries, per scalar arg's own width/signedness.
    scalar_ws = [(d["w"], d["s"]) for d in params if d["k"] != "ptr"]
    n_bounds = max((len(M.scalar_boundaries(w, s)) for w, s in scalar_ws), default=0)
    for bi in range(n_bounds):
        def src(si, bi=bi):
            w, s = scalar_ws[si]
            b = M.scalar_boundaries(w, s)
            return b[bi % len(b)]
        add(src)
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
        for _i, (d, a) in enumerate(zip(params, args)):
            if d["k"] == "ptr" and a is None:
                filled.append(buf_det(k, d) if k % 2 == 0 else buf_rng(d))
            else:
                filled.append(a)
        out.append(filled)
    return out


def _wrap(v: int, width: int, signed: bool) -> int:
    """Reduce v into the value a C variable of this width/signedness holds."""
    bits = 8 * width
    v &= (1 << bits) - 1
    if signed and v >= (1 << (bits - 1)):
        v -= 1 << bits
    return v


def _pad_ptr(ev, params, ptr_len):
    out = []
    for d, a in zip(params, ev):
        if d["k"] == "ptr" and isinstance(a, list):
            a = (a + [0] * ptr_len)[:ptr_len]
        out.append(a)
    return out


# ---------------------------------------------------------------------------
# Worker (runs in an isolated subprocess)
# ---------------------------------------------------------------------------

_CTYPE = {
    (1, True): ctypes.c_int8, (1, False): ctypes.c_uint8,
    (2, True): ctypes.c_int16, (2, False): ctypes.c_uint16,
    (4, True): ctypes.c_int32, (4, False): ctypes.c_uint32,
    (8, True): ctypes.c_int64, (8, False): ctypes.c_uint64,
}


def _scalar_ctype(d):
    return _CTYPE[(d["w"], d["s"])]


def _pointee_ctype(d, forced_u8):
    if forced_u8:
        return ctypes.c_uint8
    return _CTYPE[(d["pw"], d["ps"])]


def _ctypes_fn(lib, sig, forced_u8):
    params = [_as_desc(p) for p in sig["params"]]
    ret = _as_desc(sig["ret"])
    fn = getattr(lib, sig["name"])
    fn.restype = None if ret["k"] == "void" else _scalar_ctype(ret)
    fn.argtypes = [
        ctypes.POINTER(_pointee_ctype(d, forced_u8)) if d["k"] == "ptr" else _scalar_ctype(d)
        for d in params
    ]
    return fn


def worker(spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text())
    sig = spec["sig"]
    forced_u8 = spec.get("ptr_elem") == "u8"
    params = [_as_desc(p) for p in sig["params"]]
    ret = _as_desc(sig["ret"])
    orig = ctypes.CDLL(spec["orig_so"])
    dec = ctypes.CDLL(spec["dec_so"])
    fo, fd = _ctypes_fn(orig, sig, forced_u8), _ctypes_fn(dec, sig, forced_u8)

    for vec in spec["vectors"]:
        oargs, dargs, obufs, dbufs = [], [], [], []
        for d, a in zip(params, vec):
            if d["k"] == "ptr":
                ct = _pointee_ctype(d, forced_u8)
                ob = (ct * len(a))(*a)
                db = (ct * len(a))(*a)
                obufs.append(ob)
                dbufs.append(db)
                oargs.append(ob)
                dargs.append(db)
            else:
                oargs.append(a)
                dargs.append(a)
        ro = fo(*oargs)
        rd = fd(*dargs)
        # restype is set to the exact DWARF width/signedness, so equality is a
        # FULL-width comparison (a dropped high 32 bits or a wrong sign extension
        # diverges here).
        if ret["k"] != "void" and ro != rd:
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

def exec_class(sig, fixture) -> tuple[str, str]:
    """Whether a function is execution-differential or structural-only, and why.
    Shared with the structural lane so it knows which functions MUST carry a
    structural assertion (a structural result with no assertion is a gap)."""
    ov = M.override(fixture, sig["name"])
    if ov.get("skip_exec"):
        return "structural", "manifest skip_exec"
    ret = _as_desc(sig["ret"])
    has_ptr = any(_as_desc(p)["k"] == "ptr" for p in sig["params"])
    if ret["k"] == "ptr":
        return "structural", "pointer return — addresses not comparable"
    if ret["k"] == "void" and not has_ptr:
        return "structural", "void return, no buffer — not execution-differential"
    return "exec", ""


def run_function(sig, fixture, binary, workdir, seed, fuzz) -> dict:
    name = sig["name"]
    ov = M.override(fixture, name)
    # Structural-only functions (function-pointer callbacks, void-no-buffer,
    # pointer returns) have no observable int value to diff — never a silent
    # pass; the structural lane asserts on them instead.
    cls, why = exec_class(sig, fixture)
    if cls == "structural":
        return {"status": "structural", "detail": why}
    c = decompiled_c(binary, sig["va"])
    if c is None:
        return {"status": "fail", "detail": "decompile failed"}
    dec_so = build_so(c, workdir, f"dec_{name}")
    if dec_so is None:
        return {"status": "fail", "detail": "decompiled C failed to compile"}
    vectors = make_vectors(sig, ov, seed, fuzz)
    if not vectors:
        # An infra/manifest problem (no inputs generated), NOT a decompiler
        # result — a distinct status so --write-baseline can refuse it.
        return {"status": "nocases", "detail": "no executable cases"}
    spec = {"sig": sig, "orig_so": binary, "dec_so": str(dec_so), "vectors": vectors,
            "ptr_elem": ov.get("ptr_elem", "int")}
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


INFRA_STATUSES = {"missing", "nocases"}


def exit_code(results: dict) -> int:
    """0 = all good; 1 = semantic fail(s); 2 = infra/lane failure (must never be
    baked into a baseline). Distinguishing lets CI and --write-baseline treat
    infrastructure breakage differently from known decompiler bugs."""
    if "__error__" in results:
        return 2
    statuses = {r["status"] for r in results.values()}
    if statuses & INFRA_STATUSES:
        return 2
    return 1 if "fail" in statuses else 0


def run(binary: str, source: str, fixture: str, seed: int, fuzz: int) -> dict:
    results: dict[str, dict] = {}
    # A truly stripped (no-.debug_info) binary must ERROR — never a green all-
    # structural run. (has_dwarf_info() also counts .eh_frame, so check the
    # .debug_info section directly.) O2 *fragmentation* — .debug_info present but
    # ranges/abstract-origin — is different: unrecoverable functions fall to
    # `structural` below.
    with open(binary, "rb") as fh:
        di = ELFFile(fh).get_section_by_name(".debug_info")
        if di is None or di["sh_size"] == 0:
            return {"__error__": f"no DWARF debug info in {binary}"}
    # The dynamic symbol table is the authoritative function list (reliable at
    # O2, where DWARF fragments). DWARF supplies types where recoverable.
    exported = exported_functions(binary)
    if not exported:
        return {"__error__": f"no exported functions in {binary}"}
    sig_by_name = {s["name"]: s for s in signatures(binary)}
    # Required-function presence = present in the symbol table. (A dropped/renamed
    # export is a real infra failure; an unparseable signature is not.)
    for req in M.REQUIRED_FUNCTIONS.get(fixture, []):
        if req not in exported:
            results[req] = {"status": "missing", "detail": "required function missing from binary"}
    with tempfile.TemporaryDirectory(dir=M.tmpdir()) as td:
        wd = Path(td)
        for name in sorted(exported):
            sig = sig_by_name.get(name)
            if sig is None:
                # Exported but no recoverable DWARF signature (function-pointer
                # param, or O2 ranges/abstract-origin form) — not execution-
                # differential; report structural, never a silent pass or a
                # baseline-blocking infra status.
                results[name] = {"status": "structural",
                                 "detail": "signature not recoverable from DWARF"}
                continue
            results[name] = run_function(sig, fixture, binary, wd, seed, fuzz)
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
        return exit_code(results)
    if "__error__" in results:
        print(f"ERROR: {results['__error__']}", file=sys.stderr)
        return 2
    tags = {"pass": "PASS", "fail": "FAIL", "structural": "STRUCT",
            "missing": "MISSING", "nocases": "NOCASES"}
    counts = {k: 0 for k in tags}
    for name, r in sorted(results.items()):
        counts[r["status"]] += 1
        print(f"{tags[r['status']]} {name}: {r['detail']}")
    print(f"\n{counts['pass']} pass, {counts['fail']} fail, {counts['structural']} structural, "
          f"{counts['missing']} missing, {counts['nocases']} no-cases")
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
