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
  * the worker subprocess exits non-zero or is killed by a signal;
  * zero executable cases were produced for a function.

A worker that exceeds its wall clock is reported `timeout`, an INFRASTRUCTURE
status — not `fail`. Being too slow is not evidence that a decompilation is wrong,
and recording it as a semantic verdict would bake machine speed into the baseline
(it did: `guarded_spin` passed on a 24-core workstation and "failed" on a 4-vCPU
runner). `--write-baseline` refuses it and the gate reports it distinctly.

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
import math
import random
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
from itertools import pairwise
from pathlib import Path

# Import the native API once per fixture lane.  The lane itself is already an
# isolated subprocess (fixture_harness.py owns that boundary), so this keeps a
# native crash contained without paying Python + extension startup for every
# individual function.
import glaurung as g

# Fail-closed: a missing dependency must surface as an import error, not a skip.
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))
import build_guard as BG
import fixture_toolchain as TC
import manifest as M  # ty: ignore[unresolved-import]  # added to sys.path above

# Resolved once: the CLI whose output every verdict here is a judgement of. Bare
# `glaurung` only works from an activated venv, which is how a fresh shell used
# to fail the whole gate with `FileNotFoundError: 'glaurung'`.
_glaurung = BG.glaurung_bin

PRELUDE = """
typedef unsigned char uint8_t; typedef signed char int8_t;
typedef unsigned short uint16_t; typedef short int16_t;
typedef unsigned int uint32_t; typedef int int32_t;
typedef unsigned long uint64_t; typedef long int64_t;
typedef unsigned char byte; typedef signed char sbyte;
typedef unsigned short ushort; typedef short shortint;
typedef unsigned int uint; typedef unsigned long ulong;
typedef unsigned long long ulonglong; typedef long long longlong;
typedef uint8_t undefined1; typedef uint16_t undefined2;
typedef uint32_t undefined4; typedef uint64_t undefined8;
/* A 128-bit integer is a 64-bit-target extension. Guarded rather than assumed so
   this scaffolding builds for a 32-bit target too — `native_rebuild_diagnostic`
   compiles the SAME translation unit there, and an unguarded typedef would make
   the harness's own prelude look like a decompiler defect. If the RECOVERY names
   `undefined16` on such a target, that is a real defect and still fails. */
#ifdef __SIZEOF_INT128__
typedef __uint128_t undefined16;
#endif
typedef uint8_t uint1; typedef int8_t int1;
typedef uint16_t uint2; typedef int16_t int2;
typedef uint32_t uint4; typedef int32_t int4;
typedef uint64_t uint8; typedef int64_t int8;
/* `bool` became a keyword in C23, which gcc >= 15 defaults to. */
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)
typedef _Bool bool;
#define true 1
#define false 0
#endif
/* Variadic to match the declaration the renderer emits
 * (`extern long __unknown(long, ...);`, decbench_render.rs:509). A fixed
 * arity here is a `conflicting types` compile error the moment a function
 * contains BOTH an unmodelled intrinsic with arguments and one without --
 * which is why it only surfaced when intrinsics started assigning their
 * declared destination. */
long __unknown(long x, ...){ (void)x; return 0; }
/* Scrub the stack the measured call is about to use, to a fixed pattern.

   A recovered function that reads an UNINITIALISED local returns whatever the
   stack happened to hold, so without this its verdict is not a property of the
   decompilation at all. `09_memory_effects:armv7:O2:read_counter` (recovered as
   `*(int *)(*(int *)(var1 + 4) + var1)`) and
   `04_switch_shapes:armv7:O0:dense_compute` (a switch whose compare temporary is
   never assigned) each flipped pass/fail with address randomization, with the
   size of the caller's environment block, and — after both of those were pinned —
   with the LENGTH OF THE SCRATCH DIRECTORY'S NAME, because the dynamic loader's
   own stack use scales with the path it is handed. Chasing each channel is
   endless; removing the dependence is not.

   Scrubbed, the read yields 0xA5A5... every time: a value comparison then fails
   deterministically and a pointer built from it faults deterministically, which
   is the correct verdict for a function that reads uninitialised memory rather
   than a coin flip. Called before BOTH sides so neither is privileged. */
void glaurung_scrub_stack(void);
void glaurung_scrub_stack(void) {
    volatile unsigned char scrub[1 << 16];
    for (unsigned long i = 0; i < sizeof(scrub); i++) scrub[i] = 0xA5;
}
"""

#: `PRELUDE` spells its 64-bit typedefs with `long`, which is 8 bytes only on an
#: LP64 host. `native_rebuild_diagnostic` compiles the SAME recovered C for the
#: architecture it was recovered FROM, where `long` is 4 bytes on i386/ARM32, so
#: the scaffolding has to say `long long` there or the probe would blame the
#: decompiler for the harness's own typedef. Nothing else in the prelude has a
#: width that moves.
_HOST_WIDTH_TYPEDEFS = "typedef unsigned long uint64_t; typedef long int64_t;"
_PORTABLE_WIDTH_TYPEDEFS = (
    "typedef unsigned long long uint64_t; typedef long long int64_t;"
)
NATIVE_PRELUDE = PRELUDE.replace(_HOST_WIDTH_TYPEDEFS, _PORTABLE_WIDTH_TYPEDEFS)
assert NATIVE_PRELUDE != PRELUDE, "PRELUDE no longer spells int64_t as `long`"

# ---------------------------------------------------------------------------
# Signature recovery
# ---------------------------------------------------------------------------

# The pyelftools DWARF type walker that used to live here — roughly 300 lines
# of DIE resolution, wrapper peeling and descriptor building — has been
# deleted. `signatures()` below reads the same information through Glaurung's
# own `gimli` reader (`debug::dwarf_signatures`), so this harness no longer
# carries a second, independently-buggy DWARF parser. See that module's header
# for what it refuses and why refusing is the point.


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
            if (
                info["type"] in ("STT_FUNC", "STT_GNU_IFUNC")
                and info["bind"] in ("STB_GLOBAL", "STB_WEAK")
                and sym["st_shndx"] != "SHN_UNDEF"
            ):
                out[sym.name] = sym["st_value"]
    return out


def exported_symbols(binary: str) -> set[str]:
    return set(exported_functions(binary))


def defined_functions(binary: str) -> dict[str, int]:
    """Every named, defined ELF function in ``.symtab``.

    Unlike ``exported_functions``, this includes local/static functions. A
    stripped binary may have no full symbol table; returning an empty map keeps
    local-callee completion fail-closed and lets the existing unresolved-symbol
    verdict describe the limitation.
    """
    out: dict[str, int] = {}
    with open(binary, "rb") as fh:
        symtab = ELFFile(fh).get_section_by_name(".symtab")
        if symtab is None:
            return out
        for symbol in symtab.iter_symbols():  # ty: ignore[unresolved-attribute]
            if (
                symbol.name
                and symbol["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC")
                and symbol["st_shndx"] != "SHN_UNDEF"
            ):
                out.setdefault(symbol.name, symbol["st_value"])
    return out


def signatures(binary: str) -> list[dict]:
    """Executable signatures for every function this harness can call.

    Read through Glaurung's own `gimli` DWARF reader
    (`debug::dwarf_signatures`), not a second parser. This used to be ~200 lines
    of pyelftools DIE walking used by nothing but this harness, and it was the
    source of every DWARF crash chased on 2026-08-12 — cross-CU references
    resolved against the wrong compilation unit, `DW_FORM_strp` offsets
    reporting `value=None`, abbrev tables decoded lazily with the wrong CU. A
    Rust `cdylib` under test carries 13 compilation units and turned up all of
    them; not one was a defect in the product.

    Reading the same bytes through the same code the product uses means a DWARF
    failure here is now evidence about Glaurung rather than about the harness.

    The address still comes from the dynamic symbol table when the DIE has no
    `DW_AT_low_pc`: at -O2 a function can be described entirely by
    `DW_AT_ranges`, and the export table is the authoritative name->address map
    this harness loads through anyway.
    """
    exported = exported_functions(binary)
    out = []
    for signature in g.debug.extract_dwarf_signatures_path(  # ty: ignore[unresolved-attribute]
        binary
    ):
        name = signature["name"]
        va = signature["va"] or exported.get(name)
        if not va:
            continue
        out.append(
            {
                "name": name,
                "va": va,
                "params": signature["params"],
                "ret": signature["ret"],
            }
        )
    return out


# String shorthands accepted in hand-written sigs (tests) -> full descriptors.
_STR_DESC = {
    "int": {"k": "int", "w": 4, "s": True},
    "uint": {"k": "int", "w": 4, "s": False},
    "long": {"k": "int", "w": 8, "s": True},
    "ulong": {"k": "int", "w": 8, "s": False},
    "float": {"k": "float", "w": 4},
    "double": {"k": "float", "w": 8},
    "ptr": {"k": "ptr", "pw": 4, "ps": True, "const": False},
    "fptr": {"k": "ptr", "p": {"k": "float", "w": 4}, "const": False},
    "dptr": {"k": "ptr", "p": {"k": "float", "w": 8}, "const": False},
    "void": {"k": "void"},
}


def _as_desc(x):
    return dict(_STR_DESC[x]) if isinstance(x, str) else x


def _pointee_desc(d):
    """Return a pointer's full pointee descriptor, including legacy shorthands."""
    if "p" in d:
        return d["p"]
    return {"k": "int", "w": d.get("pw", 1), "s": d.get("ps", False)}


def abi_incomparable(sig: dict, reference_sig: dict | None) -> str | None:
    """Why one ctypes prototype cannot describe BOTH sides of the differential.

    A cross-architecture lane executes the recovery against the same source built
    for the host, and marshals the call through ONE signature — the one recovered
    from the object being decompiled. That is sound only while both builds agree
    on the ABI type of every parameter and the return.

    They do not always agree. `long` is 4 bytes on i386/ARM32 and 8 on the LP64
    host, so `long count_up(int)` in `12_loop_rotation` is `w:4` in the 32-bit
    object's DWARF and `w:8` in the reference's. The worker then hands the host
    function a 32-bit argument where it expects 64, and truncates the reference's
    64-bit return to 32 before comparing. The resulting verdict is a statement
    about that truncation, not about the lifter — and it lands on `pass` for every
    input small enough not to notice, which is the silent-green shape this whole
    lane exists to remove.

    Returns `None` when the two sides are comparable, else the reason. `None` for
    a missing `reference_sig` is deliberate: same-architecture lanes pass the very
    same object as both sides and have nothing to compare.
    """
    if reference_sig is None:
        return None
    mine, theirs = _as_desc(sig["ret"]), _as_desc(reference_sig["ret"])
    if mine != theirs:
        return (
            f"return type differs between the target build and the host "
            f"reference ({mine} vs {theirs}) — one ctypes prototype cannot "
            f"describe both sides, so no execution verdict is meaningful"
        )
    mine_params = [_as_desc(p) for p in sig["params"]]
    their_params = [_as_desc(p) for p in reference_sig["params"]]
    if len(mine_params) != len(their_params):
        return (
            f"parameter count differs between the target build and the host "
            f"reference ({len(mine_params)} vs {len(their_params)})"
        )
    for index, (a, b) in enumerate(zip(mine_params, their_params)):
        if a != b:
            return (
                f"parameter {index} differs between the target build and the "
                f"host reference ({a} vs {b}) — one ctypes prototype cannot "
                f"describe both sides, so no execution verdict is meaningful"
            )
    return None


#: What the native probe must hold FIXED so it measures the architecture and only
#: the architecture.
#:
#: The host rebuild runs under the pinned image's gcc 11; the target drivers are
#: whatever this host ships (gcc 15 here). Two differences between those have
#: nothing to do with 32 vs 64 bits and would otherwise be reported as decompiler
#: defects:
#:
#: * the default C standard moved to gnu23, where `bool` is a keyword;
#: * gcc 14 promoted five long-standing warnings to errors. The recovery does
#:   pass a machine word where a pointer is expected (`read_be32(local_28)` in
#:   `07_packet_parser`) — that is worth fixing, and `-Wint-conversion` is
#:   exactly the right diagnostic for it — but it is a TYPE-RECOVERY defect that
#:   is equally present at 64 bits, not evidence the target cannot compile this.
#:   Letting it fail here would attribute an architecture-independent bug to the
#:   32-bit lanes and make the probe's headline number wrong.
_NATIVE_PARITY_FLAGS = (
    "-std=gnu17",
    "-Wno-error=implicit-function-declaration",
    "-Wno-error=implicit-int",
    "-Wno-error=int-conversion",
    "-Wno-error=incompatible-pointer-types",
    "-Wno-error=return-mismatch",
    "-Wno-error=declaration-missing-parameter-type",
)
_NATIVE_PARITY_FLAGS_CXX = ("-std=gnu++17", "-fpermissive")


def native_rebuild_diagnostic(
    c_src: str, workdir: Path, tag: str, native_cc: list[str]
) -> str:
    """Compile the recovered C for the architecture it was recovered FROM.

    The execution differential rebuilds the recovery for the HOST, because that is
    where it can be run. That rebuild accepts C the target could never compile —
    most importantly `__int128`, which does not exist on any 32-bit target and
    which the renderer emitted for every 32-bit multiply-high until
    `double_width_ctype` derived the intermediate from the operand width. DecBench
    caught that; four green lanes here did not, and could not.

    So compile the same translation unit with the target's own driver, object only
    (`-c`): no link, no execution, nothing about behaviour. It answers exactly one
    question — is what we emitted valid C for the machine we read it off — and a
    `no` is a decompiler defect no host rebuild can see.

    Returns `""` when it builds, else the compiler's diagnostic.
    """
    uses_cpp = bool(re.search(r"\b(?:try\s*\{|catch\s*\(|throw\b)", c_src))
    translation_unit = NATIVE_PRELUDE + "\n" + c_src + "\n"
    if uses_cpp:
        translation_unit = 'extern "C" {\n' + translation_unit + "}\n"
    src = workdir / f"native_{tag}.{'cpp' if uses_cpp else 'c'}"
    src.write_text(translation_unit)
    compiler = re.sub(r"gcc$", "g++", native_cc[0]) if uses_cpp else native_cc[0]
    if shutil.which(compiler) is None:
        # NOT a `nonportable` verdict. "We could not check" and "the target
        # rejects our C" are opposite claims, and reporting the first as the
        # second invents a decompiler defect out of a missing package. Callers
        # reach here only for a target whose fixture already cross-built, so this
        # is a broken environment and must fail the lane, not the function.
        raise FileNotFoundError(
            f"native rebuild probe wanted {compiler}, which is not on PATH"
        )
    r = subprocess.run(
        [
            compiler,
            *native_cc[1:],
            *(_NATIVE_PARITY_FLAGS_CXX if uses_cpp else _NATIVE_PARITY_FLAGS),
            "-c",
            "-fPIC",
            "-O0",
            "-w",
            "-o",
            str(workdir / f"native_{tag}.o"),
            str(src),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode == 0:
        return ""
    return " ".join((r.stderr or r.stdout or "no compiler output").split())


#: Types whose size changes between ILP32 and LP64. A recovered fragment naming
#: none of them computes the same values at either width, so a host rebuild of it
#: is a faithful stand-in for the 32-bit one — see `width_sensitive`.
_WIDTH_VARYING = re.compile(
    r"\blong\b|\b(?:size_t|ssize_t|intptr_t|uintptr_t|ptrdiff_t"
    r"|__int128|__uint128_t|__int128_t)\b"
)

#: `long long` is 8 bytes at both widths, so it must be removed before looking for
#: a bare `long` — a negative lookahead cannot do it, because in `long long f(...)`
#: it is the SECOND `long` that is not followed by another.
_FIXED_WIDTH_LONG_LONG = re.compile(r"\blong\s+long\b")


def width_sensitive(c_src: str) -> bool:
    """Whether rebuilding this recovered C at the host's pointer width can change
    what it computes.

    Conservative in the direction that matters: `False` means every type named is
    fixed-width (`int`, `short`, `char`, `long long`, explicit `intN_t`), so the
    64-bit rebuild the 32-bit lanes execute is value-identical to a 32-bit one and
    a `fail` there is a real semantic defect rather than a portability artifact.
    `True` only means "cannot be ruled out".

    Pointers themselves are not listed. Their width does change, but the recovery
    only ever dereferences pointers the harness allocated, at offsets it computed
    itself, so the arithmetic stays self-consistent at either width; what breaks is
    an integer type that silently changes size underneath a value.
    """
    return bool(_WIDTH_VARYING.search(_FIXED_WIDTH_LONG_LONG.sub(" ", c_src)))


_NATIVE_INTEGER_TYPE = {
    (1, True): "int8_t",
    (1, False): "uint8_t",
    (2, True): "int16_t",
    (2, False): "uint16_t",
    (4, True): "int32_t",
    (4, False): "uint32_t",
    (8, True): "int64_t",
    (8, False): "uint64_t",
}


def _native_flat_struct_layout(
    desc: dict, fallback_name: str
) -> tuple[str, str, list[tuple[str, str]]] | None:
    """Render one binary-derived flat integer struct for a target worker.

    The target comparator only needs object layout, not source spelling. Refuse
    nested aggregates, links, overlaps, and unrepresentable scalar widths; a
    partial declaration would turn an execution oracle into a false authority.
    """
    if desc.get("k") != "struct" or not 1 <= desc.get("w", 0) <= 256:
        return None
    name = desc.get("name", fallback_name)
    if re.fullmatch(r"[A-Za-z_]\w*", name) is None:
        name = fallback_name

    declarations: list[str] = []
    initializer_fields: list[tuple[str, str]] = []
    offset_assertions: list[str] = []
    cursor = 0
    for index, field in enumerate(desc.get("fields", [])):
        offset = field.get("off")
        field_type = field.get("t", {})
        if (
            not isinstance(offset, int)
            or offset < cursor
            or field_type.get("k") != "int"
        ):
            return None
        ctype = _NATIVE_INTEGER_TYPE.get((field_type.get("w"), field_type.get("s")))
        if ctype is None:
            return None
        if offset > cursor:
            declarations.append(f"uint8_t _dwarf_pad_{index}[{offset - cursor}];")
        field_name = field.get("name", f"field_{index}")
        if re.fullmatch(r"[A-Za-z_]\w*", field_name) is None:
            field_name = f"field_{index}"
        declarations.append(f"{ctype} {field_name};")
        initializer_fields.append((field_name, ctype))
        offset_assertions.append(
            f"_Static_assert(offsetof({name}, {field_name}) == {offset}, "
            f'"DWARF field offset");'
        )
        cursor = offset + field_type["w"]
    if not initializer_fields or cursor > desc["w"]:
        return None
    if cursor < desc["w"]:
        declarations.append(f"uint8_t _dwarf_tail_pad[{desc['w'] - cursor}];")
    body = " ".join(declarations)
    declaration = (
        f"typedef struct {name} {{ {body} }} {name};\n"
        f'_Static_assert(sizeof({name}) == {desc["w"]}, "DWARF layout");\n'
        + "\n".join(offset_assertions)
    )
    return name, declaration, initializer_fields


def _native_worker_source(sig: dict, vectors: list[list], ptr_elem: str) -> str | None:
    """Generate a dependency-free target worker for scalar/pointer C ABIs.

    ``None`` means the signature needs the richer ctypes materializer (aggregate
    values, self-linked graphs, or pointer returns).  The generated subset is
    deliberately type-directed rather than fixture-directed and covers plain
    integer scalars plus pointers to integer arrays, including byte buffers.
    """
    params = [_as_desc(raw) for raw in sig["params"]]
    ret = _as_desc(sig["ret"])
    if ret["k"] not in {"int", "void"}:
        return None
    if any(
        not isinstance(vector, list) or len(vector) != len(params) for vector in vectors
    ):
        return None

    param_types: list[str] = []
    pointee_types: dict[int, tuple[str, str, list[tuple[str, str]]]] = {}
    struct_declarations: dict[str, tuple[dict, str]] = {}
    for index, desc in enumerate(params):
        if desc["k"] == "int":
            ctype = _NATIVE_INTEGER_TYPE.get((desc["w"], desc["s"]))
            if ctype is None:
                return None
            param_types.append(ctype)
            continue
        if desc["k"] != "ptr":
            return None
        pointee = _pointee_desc(desc)
        if pointee["k"] == "int":
            ctype = (
                "uint8_t"
                if ptr_elem in {"u8", "cstr"}
                else _NATIVE_INTEGER_TYPE.get((pointee["w"], pointee["s"]))
            )
            if ctype is None:
                return None
            pointee_types[index] = ("int", ctype, [])
        elif pointee["k"] == "struct":
            layout = _native_flat_struct_layout(pointee, f"GlaurungStruct{index}")
            if layout is None:
                return None
            ctype, declaration, initializer_fields = layout
            existing = struct_declarations.get(ctype)
            if existing is not None and existing[0] != pointee:
                return None
            struct_declarations[ctype] = (pointee, declaration)
            pointee_types[index] = ("struct", ctype, initializer_fields)
        else:
            return None
        qualifier = "const " if desc.get("const") else ""
        param_types.append(f"{qualifier}{pointee_types[index][1]} *")

    return_type = (
        "void" if ret["k"] == "void" else _NATIVE_INTEGER_TYPE.get((ret["w"], ret["s"]))
    )
    if return_type is None:
        return None
    prototype = ", ".join(param_types) if param_types else "void"
    lines = [
        "#include <dlfcn.h>",
        "#include <signal.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#include <stdio.h>",
        "#include <string.h>",
        "#include <unistd.h>",
        *(declaration for _, declaration in struct_declarations.values()),
        f"typedef {return_type} (*measured_fn)({prototype});",
        "typedef void (*scrub_fn)(void);",
        "int main(void) {",
        '  void *original = dlopen("./target_reference.so", RTLD_NOW | RTLD_LOCAL);',
        '  if (!original) { fprintf(stderr, "original dlopen: %s\\n", dlerror()); return 70; }',
        '  void *recovered = dlopen("./target_recovered.so", RTLD_NOW | RTLD_LOCAL);',
        '  if (!recovered) { fprintf(stderr, "recovered dlopen: %s\\n", dlerror()); return 71; }',
        f'  measured_fn fo = (measured_fn)dlsym(original, "{sig["name"]}");',
        f'  measured_fn fd = (measured_fn)dlsym(recovered, "{sig["name"]}");',
        '  scrub_fn scrub = (scrub_fn)dlsym(recovered, "glaurung_scrub_stack");',
        '  if (!fo || !fd) { fprintf(stderr, "measured symbol missing\\n"); return 72; }',
        "  signal(SIGALRM, SIG_DFL);",
    ]
    for case_index, vector in enumerate(vectors):
        call_original: list[str] = []
        call_recovered: list[str] = []
        buffers: list[tuple[str, str, int]] = []
        for param_index, (desc, value) in enumerate(zip(params, vector)):
            if desc["k"] == "int":
                literal = str(int(value))
                ctype = param_types[param_index]
                call_original.append(f"({ctype})({literal})")
                call_recovered.append(f"({ctype})({literal})")
                continue
            if not isinstance(value, list) or not value:
                return None
            pointee_kind, ctype, initializer_fields = pointee_types[param_index]
            if pointee_kind == "int":
                try:
                    initializer = ", ".join(str(int(item)) for item in value)
                except TypeError, ValueError:
                    return None
            else:
                aggregates: list[str] = []
                for item in value:
                    if not isinstance(item, list) or len(item) != len(
                        initializer_fields
                    ):
                        return None
                    try:
                        fields = ", ".join(
                            f".{field_name} = ({field_type})({int(field_value)})"
                            for (field_name, field_type), field_value in zip(
                                initializer_fields, item
                            )
                        )
                    except TypeError, ValueError:
                        return None
                    aggregates.append("{" + fields + "}")
                initializer = ", ".join(aggregates)
            original_name = f"o_{case_index}_{param_index}"
            recovered_name = f"d_{case_index}_{param_index}"
            lines.extend(
                [
                    f"  {ctype} {original_name}[{len(value)}] = {{{initializer}}};",
                    f"  {ctype} {recovered_name}[{len(value)}] = {{{initializer}}};",
                ]
            )
            call_original.append(original_name)
            call_recovered.append(recovered_name)
            buffers.append((original_name, recovered_name, len(value)))
        original_args = ", ".join(call_original)
        recovered_args = ", ".join(call_recovered)
        lines.append("  if (scrub) scrub();")
        if ret["k"] == "void":
            lines.append(f"  fo({original_args});")
        else:
            lines.append(f"  {return_type} ro_{case_index} = fo({original_args});")
        lines.extend(["  if (scrub) scrub();", "  alarm(5);"])
        if ret["k"] == "void":
            lines.append(f"  fd({recovered_args});")
        else:
            lines.append(f"  {return_type} rd_{case_index} = fd({recovered_args});")
        lines.append("  alarm(0);")
        if ret["k"] != "void":
            lines.extend(
                [
                    f"  if (ro_{case_index} != rd_{case_index}) {{",
                    f'    printf("return differs on case {case_index}\\n"); return 10;',
                    "  }",
                ]
            )
        for original_name, recovered_name, length in buffers:
            lines.extend(
                [
                    f"  if (memcmp({original_name}, {recovered_name}, sizeof({original_name}[0]) * {length}) != 0) {{",
                    f'    printf("buffer differs on case {case_index}\\n"); return 11;',
                    "  }",
                ]
            )
    lines.extend([f'  printf("pass {len(vectors)} cases\\n");', "  return 0;", "}"])
    return "\n".join(lines) + "\n"


def native_execution_differential(
    c_src: str,
    binary: str | Path,
    sig: dict,
    vectors: list[list],
    workdir: Path,
    native_cc: list[str],
    runner_prefix: list[str],
    ptr_elem: str,
) -> dict | None:
    """Execute both sides at the target ABI using a generated C worker.

    This closes the ILP32/LP64 object-layout confound without loading a foreign
    ELF into CPython.  The original target object supplies exported sibling C++
    helpers to the target rebuild, exactly as the host differential does.
    """
    worker_source = _native_worker_source(sig, vectors, ptr_elem)
    if worker_source is None:
        return None
    for command in (native_cc[0], runner_prefix[0]):
        if shutil.which(command) is None:
            raise FileNotFoundError(f"native execution wanted {command}, not on PATH")

    uses_cpp = bool(re.search(r"\b(?:try\s*\{|catch\s*\(|throw\b)", c_src))
    translation_unit = NATIVE_PRELUDE + "\n" + c_src + "\n"
    if uses_cpp:
        translation_unit = 'extern "C" {\n' + translation_unit + "}\n"
    recovered_source = workdir / f"target_recovered.{'cpp' if uses_cpp else 'c'}"
    recovered_source.write_text(translation_unit)
    recovered_so = workdir / "target_recovered.so"
    target_reference = workdir / "target_reference.so"
    shutil.copy2(Path(binary).resolve(), target_reference)
    compiler = re.sub(r"gcc$", "g++", native_cc[0]) if uses_cpp else native_cc[0]
    runtime_args = _inherited_cxx_runtime_args(str(binary))
    compile_recovered = subprocess.run(
        [
            compiler,
            *native_cc[1:],
            *(_NATIVE_PARITY_FLAGS_CXX if uses_cpp else _NATIVE_PARITY_FLAGS),
            "-shared",
            "-fPIC",
            "-O0",
            "-w",
            "-Wl,-Bsymbolic",
            "-Wl,--no-as-needed",
            "-Wl,-rpath,$ORIGIN",
            "-o",
            recovered_so.name,
            recovered_source.name,
            target_reference.name,
            *runtime_args,
        ],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )
    if compile_recovered.returncode != 0:
        diagnostic = " ".join(
            (
                compile_recovered.stderr
                or compile_recovered.stdout
                or "no compiler output"
            ).split()
        )
        return {
            "status": "nonportable",
            "detail": f"native target recovery failed to link: {diagnostic[-400:]}",
        }

    worker_path = workdir / "target_worker.c"
    worker_path.write_text(worker_source)
    worker_exe = workdir / "target_worker"
    compile_worker = subprocess.run(
        [
            native_cc[0],
            *native_cc[1:],
            "-std=gnu17",
            "-O0",
            "-w",
            "-o",
            worker_exe.name,
            worker_path.name,
            "-ldl",
        ],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )
    if compile_worker.returncode != 0:
        diagnostic = " ".join(
            (
                compile_worker.stderr or compile_worker.stdout or "no compiler output"
            ).split()
        )
        raise RuntimeError(
            f"native target worker failed to compile: {diagnostic[-400:]}"
        )
    try:
        run = subprocess.run(
            [*runner_prefix, f"./{worker_exe.name}"],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=WORKER_TIMEOUT_S,
            check=False,
            env=BG.worker_env(),
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "detail": f"native target worker exceeded {WORKER_TIMEOUT_S}s",
        }
    output = (run.stdout or run.stderr or "no worker output").strip().splitlines()[-1]
    if run.returncode == 0:
        return {
            "status": "pass",
            "detail": f"{len(vectors)} cases (native target ABI)",
        }
    if run.returncode in {-signal.SIGALRM, 128 + signal.SIGALRM}:
        return {
            "status": "fail",
            "detail": "native target decompiled function did not terminate",
        }
    return {
        "status": "fail",
        "detail": f"native target {output} (exit {run.returncode})",
    }


# ---------------------------------------------------------------------------
# Decompile + compile
# ---------------------------------------------------------------------------


def decompiled_c(binary: str, va: int) -> str | None:
    p = subprocess.run(
        [
            _glaurung(),
            "decompile",
            binary,
            "--vas",
            hex(va),
            "--style",
            "decbench",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
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


def decompiled_many_c(binary: str, vas: list[int]) -> dict[int, str]:
    """Decompile requested entry VAs in one native analysis pass.

    Missing rows stay missing in the returned map so the caller reports the
    same fail-closed ``decompile failed`` verdict as the old per-function CLI
    path.  De-duplicate while retaining request order: the native function
    budget is intentionally the exact number of unique authoritative seeds.
    """
    requested = list(dict.fromkeys(vas))
    if not requested:
        return {}
    try:
        rows = g.ir.decompile_many(  # ty: ignore[unresolved-attribute]
            binary,
            requested,
            style="decbench",
            max_functions=max(1, len(requested)),
        )
    except OSError, RuntimeError, ValueError:
        return {}
    recovered: dict[int, str] = {}
    for _name, va, code in rows:
        recovered[int(va)] = "\n".join(
            line for line in code.splitlines() if not line.strip().startswith("//")
        )
    return recovered


_EXTERN_FUNCTION_DECL = re.compile(
    r"(?m)^[ \t]*extern[ \t]+[^;\n{}()]*?\b"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*\([^;\n{}]*\)[ \t]*;[ \t]*\n?"
)
#: A definition may lead with GNU attributes — the stack-protector suppression
#: is spelled bare, because a `#define` above the signature is discarded by
#: DecBench's per-function split. The prefix class below is identifier-only, so
#: the parentheses of `__attribute__((...))` would end the match and the
#: definition would be invisible to this harness. Consume them up front.
_FUNCTION_DEFINITION = re.compile(
    r"(?m)^(?!extern\b)(?P<attrs>(?:__attribute__[ \t]*\(\(.*?\)\)[ \t\r\n]*)*)"
    r"(?P<prefix>[A-Za-z_][A-Za-z0-9_ \t*]*[ \t]+)"
    r"(?P<name>[A-Za-z_]\w*)(?P<suffix>[ \t]*\([^;\n{}]*\)[ \t\r\n]*\{)"
)
_FUNCTION_CALL = re.compile(r"\b(?P<name>[A-Za-z_]\w*)[ \t]*\(")


def _c_identifier(symbol: str) -> str:
    """Return the identifier emitted when an ELF symbol is rendered as C."""
    identifier = re.sub(r"[^A-Za-z0-9_]", "_", symbol)
    if identifier and identifier[0].isdigit():
        identifier = f"_{identifier}"
    return identifier


def _rebind_function_definition(code: str, target: str) -> str | None:
    """Rename one decompiled definition and its direct self-call tokens.

    The readable name chosen for a helper definition is not necessarily the
    exact mangled identifier retained at its caller. Returning ``None`` when a
    unique top-level definition cannot be identified keeps closure fail-closed.
    """
    definition = _FUNCTION_DEFINITION.search(code)
    if definition is None:
        return None
    current = definition.group("name")
    if current == target:
        return code
    function_token = re.compile(rf"\b{re.escape(current)}\b(?=[ \t]*\()")
    return function_token.sub(target, code)


#: Upper bound on helper bodies pulled into one differential translation unit.
_MAX_HELPERS = 32

#: Above this many local symbols, decompiling all of them up front would cost
#: more than the CLI spawns it saves, so the walk falls back to fetching bodies
#: one at a time. Fixtures sit an order of magnitude below it (6-11 locals);
#: the bound exists so this stays sane on a real binary.
_MAX_PREFETCH_LOCALS = 64

#: Decompiled local-helper bodies per binary. `include_referenced_local_callees`
#: is called once per function under test, and every one of those calls walks
#: into the SAME pool of local helpers, so without this the pool is re-derived
#: for each function.
_LOCAL_BODY_CACHE: dict[str, dict[int, str]] = {}


def _local_helper_bodies(
    binary: str, local: dict[str, tuple[str, int]]
) -> dict[int, str]:
    """Decompile every local helper in `binary` once, in a single native pass.

    The transitive walk below cannot know a helper's own callees until it has
    decompiled it, so fetching on demand costs one CLI startup per helper —
    measured at 4 for `164_nested_tlv_walker` and 5 for `95_function_pointer_table`
    per lane, each paying full interpreter and import cost for one function.

    Fetching by depth instead would still cost one native analysis pass per
    level. The candidate set is known up front and small, so the whole pool goes
    in one pass and every later question is answered from memory. Bodies the
    walk never asks for are the price, and it is a much lower one.

    This warms a cache and decides nothing: `visit` is unchanged, so which
    snippets are included, and in what order, is exactly what it was.
    """
    cached = _LOCAL_BODY_CACHE.get(binary)
    if cached is not None:
        return cached
    vas = sorted({va for _symbol, va in local.values()})
    bodies = (
        decompiled_many_c(binary, vas) if 0 < len(vas) <= _MAX_PREFETCH_LOCALS else {}
    )
    _LOCAL_BODY_CACHE[binary] = bodies
    return bodies


def include_referenced_local_callees(
    binary: str,
    root_c: str,
    decompiled_by_va: dict[int, str] | None = None,
    allow_native_fallback: bool = False,
) -> str:
    """Prepend decompiled definitions for local callees named by ``root_c``.

    A standalone decompiled function is normally linked against the original
    fixture so calls to exported siblings retain their real behavior. ELF local
    symbols cannot be resolved by that dynamic link. Glaurung already recovered
    their exact symbol names and call targets, so recursively include those
    referenced local functions and compile them into the differential object.
    When a comparator supplied ``decompiled_by_va``, helper bodies must come
    from that same comparator. Falling back to Glaurung would produce a hybrid
    translation unit and falsely credit the comparator for Glaurung's work.
    ``allow_native_fallback`` is therefore only set by the canonical Glaurung
    batch path: it lets that path fetch exact local dependencies omitted from
    the batch of exported roots without weakening comparator isolation.

    Resolution is exact and bounded: only direct call identifiers whose name is
    present uniquely in the original ``.symtab`` are considered, and at most 32
    helpers are included. Missing/stripped/ambiguous cases remain unresolved and
    fail as before rather than substituting guessed behavior.
    """
    if not Path(binary).is_file():
        return root_c
    exports = exported_functions(binary)
    alias_candidates: dict[str, list[tuple[str, int]]] = {}
    for symbol, va in defined_functions(binary).items():
        if symbol in exports:
            continue
        for alias in {symbol, _c_identifier(symbol)}:
            if not alias or re.fullmatch(r"[A-Za-z_]\w*", alias) is None:
                continue
            alias_candidates.setdefault(alias, []).append((symbol, va))
    # A sanitized name can collide (for example ``a$b`` and ``a_b``). Refuse to
    # guess which body a call denotes; leaving the declaration unresolved is the
    # accurate fail-closed result.
    local = {
        alias: candidates[0]
        for alias, candidates in alias_candidates.items()
        if len(set(candidates)) == 1
    }
    if not local:
        return root_c

    snippets: dict[str, str] = {}
    visiting: set[str] = set()

    def references(code: str) -> list[str]:
        # Glaurung emits explicit extern prototypes. Raw comparator backends
        # commonly emit only a direct call token. Both are exact because the
        # candidate must also resolve to a unique local symbol in this ELF.
        return list(
            dict.fromkeys(
                match.group("name")
                for match in _FUNCTION_CALL.finditer(code)
                if match.group("name") in local
            )
        )

    may_fall_back = decompiled_by_va is None or allow_native_fallback
    #: Filled on the first genuine miss, never before. Most functions resolve
    #: every callee out of the batch they arrived with and must not pay for a
    #: pool they will not read — measured: prefetching unconditionally cost more
    #: across `@region`/`@calls` than the spawns it saved.
    native_by_va: dict[int, str] | None = None

    def helper_body(va: int) -> str | None:
        nonlocal native_by_va
        if decompiled_by_va is not None:
            hit = decompiled_by_va.get(va)
            if hit is not None or not allow_native_fallback:
                return hit
        if not may_fall_back:
            return None
        if native_by_va is None:
            native_by_va = _local_helper_bodies(binary, local)
        return native_by_va.get(va)

    def visit(name: str) -> None:
        if (
            name in snippets
            or name in visiting
            or len(snippets) + len(visiting) >= _MAX_HELPERS
        ):
            return
        visiting.add(name)
        _symbol, va = local[name]
        helper = helper_body(va)
        if helper is None and may_fall_back:
            # A body the warming pass could not reach (it stops at the cap).
            helper = decompiled_c(binary, va)
        if helper is not None:
            for dependency in references(helper):
                visit(dependency)
            rebound = _rebind_function_definition(helper, name)
            if rebound is not None:
                snippets[name] = rebound
        visiting.remove(name)

    for name in references(root_c):
        visit(name)
    if not snippets:
        return root_c

    included = set(snippets)

    def remove_included_declaration(match: re.Match[str]) -> str:
        return "" if match.group("name") in included else match.group(0)

    ordered = [
        _EXTERN_FUNCTION_DECL.sub(remove_included_declaration, code)
        for code in [*snippets.values(), root_c]
    ]
    return "\n".join(ordered)


_C_INTEGER_TYPE = {
    (1, True): "int8_t",
    (1, False): "uint8_t",
    (2, True): "int16_t",
    (2, False): "uint16_t",
    (4, True): "int32_t",
    (4, False): "uint32_t",
    (8, True): "int64_t",
    (8, False): "uint64_t",
}


def dwarf_c_type_declarations(sig: dict, c_src: str) -> str:
    """Render named plain-data structs required by one backend function.

    Raw decompiler APIs return function bodies but commonly omit their data-type
    archive. The execution harness already relies on DWARF to materialize exact
    aggregate inputs. Use that same binary-derived layout to make named types in
    comparator output compilable; never copy declarations from ground-truth C.
    Unsupported nested aggregates remain a compile failure rather than receiving
    a guessed layout.
    """
    structs: dict[str, dict] = {}
    for raw_desc in [*sig["params"], sig["ret"]]:
        desc = _as_desc(raw_desc)
        if desc["k"] == "ptr":
            desc = _pointee_desc(desc)
        if desc["k"] != "struct" or "name" not in desc:
            continue
        name = desc["name"]
        if re.search(rf"\b{re.escape(name)}\b", c_src) is None:
            continue
        existing = structs.get(name)
        if existing is not None and existing != desc:
            continue
        structs[name] = desc

    declarations: list[str] = []
    for name, desc in structs.items():
        already_defined = re.search(
            rf"(?:\bstruct\s+{re.escape(name)}\s*\{{|"
            rf"\btypedef\b[^;]*\b{re.escape(name)}\s*;)",
            c_src,
            re.DOTALL,
        )
        if already_defined is not None:
            continue
        fields: list[str] = []
        cursor = 0
        supported = True
        for index, field in enumerate(desc["fields"]):
            offset = field["off"]
            if offset < cursor:
                supported = False
                break
            if offset > cursor:
                fields.append(f"uint8_t _dwarf_pad_{index}[{offset - cursor}];")
            field_type = field["t"]
            if field_type["k"] == "self_ptr":
                field_name = field["name"]
                if re.fullmatch(r"[A-Za-z_]\w*", field_name) is None:
                    field_name = f"field_{index}"
                fields.append(f"struct {name} *{field_name};")
                cursor = offset + field_type["w"]
                continue
            if field_type["k"] != "int":
                supported = False
                break
            type_name = _C_INTEGER_TYPE[(field_type["w"], field_type["s"])]
            field_name = field["name"]
            if re.fullmatch(r"[A-Za-z_]\w*", field_name) is None:
                field_name = f"field_{index}"
            fields.append(f"{type_name} {field_name};")
            cursor = offset + field_type["w"]
        if not supported or cursor > desc["w"]:
            continue
        if cursor < desc["w"]:
            fields.append(f"uint8_t _dwarf_tail_pad[{desc['w'] - cursor}];")
        body = " ".join(fields)
        declarations.append(
            f"typedef struct __attribute__((packed)) {name} {{ {body} }} {name};\n"
            f'_Static_assert(sizeof({name}) == {desc["w"]}, "DWARF layout");'
        )
    return "\n".join(declarations)


def _inherited_cxx_runtime_args(binary: str) -> list[str]:
    """Link flags for a C++ runtime already required by ``binary``.

    Decompiled output is emitted as C, so the C compiler driver does not add a
    C++ runtime automatically.  Included local C++ callees can nevertheless
    retain direct Itanium ABI calls such as ``__cxa_throw``.  Preserve only a
    runtime dependency proven by the original ELF instead of guessing from a
    symbol spelling or linking every fixture against libstdc++.
    """
    with open(binary, "rb") as fh:
        dynamic = ELFFile(fh).get_section_by_name(".dynamic")
        if dynamic is None:
            return []
        needed = {
            tag.needed
            for tag in dynamic.iter_tags("DT_NEEDED")
            if hasattr(tag, "needed")
        }

    args: list[str] = []
    if any(name.startswith("libstdc++.") for name in needed):
        args.append("-lstdc++")
    if any(name.startswith("libc++.") for name in needed):
        args.append("-lc++")
    if any(name.startswith("libc++abi.") for name in needed):
        args.append("-lc++abi")
    return args


#: Name the reference object is linked/loaded under inside a worker's scratch
#: directory. Fixed, and short, so what the dynamic loader sees does not vary
#: with where the gate happens to be run from — see `build_so_with_diagnostic`.
REFERENCE_LINK_NAME = "reference.so"


def _fixed_name_sibling(target: Path, workdir: Path) -> Path:
    """A COPY of `target` at `workdir/reference.so`. Idempotent.

    A copy rather than a symlink: the pinned toolchain compiles inside a
    container that mounts only the directories the command line names, so a
    symlink pointing outside `workdir` dangles there, the link step fails, and
    `build_so_with_diagnostic` falls back to an unlinked object whose calls to
    exported siblings then die with `undefined symbol` at load time. Copying is a
    few tens of kilobytes per lane and cannot dangle.
    """
    copy = workdir / REFERENCE_LINK_NAME
    resolved = target.resolve()
    if not copy.exists() or copy.stat().st_mtime_ns != resolved.stat().st_mtime_ns:
        shutil.copy2(resolved, copy)
    return copy


def build_so_with_diagnostic(
    c_src: str, workdir: Path, tag: str, link_against: str | None = None
) -> tuple[Path | None, str]:
    """Rebuild our decompiled C. Compiled under the PINNED toolchain: whether a
    given rendering compiles at all is compiler-version dependent (gcc >= 14 turns
    implicit declarations and int/pointer conversions into hard errors that gcc 11
    only warns about), so a host gcc would make the `decompiled C failed to
    compile` verdict — and therefore the baseline — host-specific.

    `link_against` is the ORIGINAL fixture object. A decompiled function that calls
    a sibling (`forward_sum6` -> `sum_arg6`) has an undefined symbol on its own, and
    loading it failed with `undefined symbol: sum_arg6` — a harness gap that only
    became visible once argument reconstruction started emitting those calls at all.
    Linking against the original supplies the callee's real behaviour, which is what
    a differential test of THIS function wants.

    The original ELF's C++ runtime dependency is also preserved explicitly. The
    rebuilt source is C, so the C compiler driver will not add libstdc++/libc++
    even when an included local callee still calls the Itanium ABI directly.

    A self-recursive call still binds locally: `dlopen` searches the object itself
    before its dependencies, so the decompiled `fib` recurses into itself rather
    than delegating to the original — otherwise the recursion would go untested.

    The dependency is recorded as a BARE NAME resolved through `$ORIGIN`, not as
    an absolute path. The dynamic loader's own stack use scales with the path it
    is handed, so a recovery that reads an uninitialised local saw different
    residue depending on how long the scratch directory happened to be: the same
    build of `04_switch_shapes:armv7:O0:dense_compute` reported `fail` under
    `/tmp/aa` and `pass` under a 65-character sibling. `run_function` links a
    fixed-name sibling into `workdir` for this to point at, so what the loader
    sees is the same length wherever the gate is run from."""
    uses_cpp_exceptions = bool(re.search(r"\b(?:try\s*\{|catch\s*\(|throw\b)", c_src))
    src = workdir / f"{tag}.{'cpp' if uses_cpp_exceptions else 'c'}"
    translation_unit = PRELUDE + "\n" + c_src + "\n"
    if uses_cpp_exceptions:
        # DecBench functions are loaded by their DWARF/export spelling through
        # ctypes.  C++ is required for the recovered exception semantics, while
        # an outer language-linkage block keeps those exact C identifiers.
        translation_unit = 'extern "C" {\n' + translation_unit + "}\n"
    src.write_text(translation_unit)
    so = workdir / f"{tag}.so"
    compiler = "g++" if uses_cpp_exceptions else "gcc"
    base = [compiler, "-shared", "-fPIC", "-O0", "-w", "-o", so.name, src.name]
    runtime_args = (
        _inherited_cxx_runtime_args(link_against)
        if link_against and Path(link_against).is_file()
        else []
    )
    if link_against and Path(link_against).is_file():
        sibling = _fixed_name_sibling(Path(link_against), workdir)
        r = TC.run(
            base + [sibling.name, "-Wl,-rpath,$ORIGIN", *runtime_args],
            cwd=workdir,
        )
        if r.returncode == 0:
            return so, ""
        # Linking is an ENHANCEMENT, so its failure must not be reported as
        # "decompiled C failed to compile" — that verdict belongs to the
        # decompiler. Retry without: a function that calls no sibling links fine,
        # and one that does will say `undefined symbol` at load time, which is a
        # different and accurate message.
    r = TC.run(base + runtime_args, cwd=workdir)
    if r.returncode == 0:
        return so, ""
    diagnostic = " ".join((r.stderr or r.stdout or "no compiler output").split())
    return None, diagnostic


def build_so(
    c_src: str, workdir: Path, tag: str, link_against: str | None = None
) -> Path | None:
    """Compatibility wrapper returning only the rebuilt object, if any."""
    rebuilt, _diagnostic = build_so_with_diagnostic(
        c_src,
        workdir,
        tag,
        link_against=link_against,
    )
    return rebuilt


# ---------------------------------------------------------------------------
# Vector generation (deterministic boundaries + seeded fuzz)
# ---------------------------------------------------------------------------


#: `struct` codes for the two IEEE formats we marshal. Little-endian is spelled
#: explicitly rather than left native: the byte ORDER is irrelevant to an equality
#: test, but `<` also pins standard size, and the native codes would silently
#: follow the host's alignment padding rules.
_FLOAT_PACK = {4: "<f", 8: "<d"}


def float_bits(width: int, value) -> int:
    """The exact IEEE-754 bit pattern of `value` at `width` bytes.

    This is the ONLY way a floating-point result is compared. `==` on Python
    floats is the wrong predicate twice over: it calls `-0.0` equal to `0.0`,
    hiding a lost sign that a `signbit`/divide-by-zero path will later act on,
    and it calls a NaN unequal to ITSELF, so a function that correctly returns
    NaN on both sides would be reported as a behavioural divergence. A tolerance
    would be worse still — it is precisely the near-miss (a `float` temporary
    recovered as a `double`, a fused multiply-add that should not have been
    contracted) this gate exists to catch, and any epsilon large enough to be
    called "close" swallows it.
    """
    return int.from_bytes(struct.pack(_FLOAT_PACK[width], float(value)), "little")


def _round_to_float_width(value: float, width: int) -> float:
    """`value` as the nearest number the target format can hold.

    Vectors are generated as Python floats (binary64) and JSON-serialised; a
    binary32 parameter would have them rounded by ctypes at the call. Rounding
    HERE instead makes the recorded vector the value actually passed, so a
    reported counter-example is the literal input to reproduce with.
    """
    return struct.unpack(_FLOAT_PACK[width], struct.pack(_FLOAT_PACK[width], value))[0]


#: Deterministic floating-point boundaries, the FP counterpart of
#: `manifest.scalar_boundaries`. Every entry is exactly representable in binary32,
#: so the same list means the same values at either width and a float-vs-double
#: disagreement is the function's, not the vector's.
#:
#: NaN and the infinities are DELIBERATELY ABSENT. Comparison handles them
#: correctly (`float_bits` is exact, and a NaN produced by either side is
#: compared by pattern), but generating them as INPUTS is a different question:
#: nearly every arithmetic fixture would then be asked to compare NaN payload
#: propagation through the x87/SSE mix a compiler may choose, and a payload the
#: hardware is permitted to alter is not a decompiler property. They stay out of
#: the input set until a fixture exists whose contract is specifically about them.
_FLOAT_BOUNDARIES = [
    0.0,
    -0.0,  # a distinct bit pattern, and the only input that can expose a lost sign
    1.0,
    -1.0,
    0.5,
    -0.5,
    2.0,
    -2.0,
    3.5,
    100.0,
    -100.0,
    65536.0,
    0.0000152587890625,  # 2^-16
    1048576.0,  # 2^20
    -1048576.0,
    1.1754943508222875e-38,  # smallest normal binary32
    3.4028234663852886e38,  # largest finite binary32
]


def float_boundaries(width: int) -> list[float]:
    """`_FLOAT_BOUNDARIES` canonicalised to one format's representable values."""
    return [_round_to_float_width(v, width) for v in _FLOAT_BOUNDARIES]


def _float_fuzz(rng: random.Random, width: int) -> float:
    """One seeded random float, spread across MAGNITUDES rather than uniform.

    A uniform draw over a fixed interval only ever exercises one exponent range;
    scaling a mantissa by a random power of two reaches the small and large ends
    where a wrong exponent width or a spilled/reloaded value shows up. The range
    is bounded well inside binary32 so no draw silently becomes an infinity.
    """
    return _round_to_float_width(
        math.ldexp(rng.uniform(-2.0, 2.0), rng.randrange(-20, 21)), width
    )


def _self_linked_pointer_params(params: list[dict]) -> list[int]:
    """Indices of the pointer parameters whose pointee links back to itself.

    This is the LINKED-STRUCTURE argument kind: a caller-owned array of nodes
    whose `next` field is a real address into that same array. It is the one
    aggregate pointer the differential can build without inventing object
    ownership, which is why `DwarfType::SelfPointer` exists at all.
    """
    found = []
    for index, desc in enumerate(params):
        if desc["k"] != "ptr":
            continue
        pointee = _pointee_desc(desc)
        if pointee["k"] != "struct":
            continue
        if any(field["t"]["k"] == "self_ptr" for field in pointee["fields"]):
            found.append(index)
    return found


def _validated_link_chains(
    sig: dict, ov: dict, params: list[dict], ptr_len: int
) -> list[list[int]] | None:
    """The manifest's declared node chains, or None when it declares none.

    `link_chains` is a LIST OF CHAINS, each an element-index walk through one
    self-linked node buffer: `chain[0] -> chain[1] -> ... -> NULL`, with every
    node the chain does not name left NULL-linked. The chains are cycled by
    vector index, so one function still sees several graph shapes.

    Why it is needed at all: the only chain this harness can synthesise on its
    own is the IDENTITY SUCCESSOR (`nodes[i].next = &nodes[i+1]`), and a
    recovery that turns a dependent load `p = p->next` into affine arithmetic
    `p += 1` walks that chain identically. A pointer-chase fixture built on the
    identity successor therefore passes whatever the decompiler did with the
    load — it measures nothing. A scrambled, proper-subset chain separates the
    two on the first vector.

    Validated fail-closed, because every failure mode here is silent. A chain
    that does not start at element 0 is unreachable (the callee is handed
    `&buffer[0]`), so the function under test would walk nothing and pass
    trivially. A repeated index is a CYCLE, and a cyclic input does not
    terminate — the original would burn the worker's whole wall clock and the
    verdict would be a timeout attributed to the decompiler. An out-of-range
    index cannot be relocated into the buffer at all.
    """
    raw = ov.get("link_chains")
    if raw is None:
        return None
    linked = _self_linked_pointer_params(params)
    if not linked:
        raise ValueError(
            f"{sig['name']}: link_chains is declared, but no parameter is a "
            f"pointer to a struct with a self-referential field — the manifest "
            f"describes a function this is not"
        )
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ValueError(f"{sig['name']}: link_chains must be a non-empty list")
    chains: list[list[int]] = []
    for position, chain in enumerate(raw):
        if not isinstance(chain, (list, tuple)) or not chain:
            # A bare `[0, 3, 1]` is the likely mistake, and reading it as three
            # one-element chains would quietly test three single-node graphs.
            raise ValueError(
                f"{sig['name']}: link_chains[{position}] must be a non-empty list "
                f"of element indices — link_chains is a LIST OF CHAINS, so a "
                f"single chain is spelled [[0, 3, 1]]"
            )
        nodes = [int(node) for node in chain]
        if nodes[0] != 0:
            raise ValueError(
                f"{sig['name']}: link_chains[{position}] starts at {nodes[0]}, but "
                f"the callee is handed &buffer[0] — a chain that does not start at "
                f"element 0 is unreachable and the walk would test nothing"
            )
        if len(set(nodes)) != len(nodes):
            raise ValueError(
                f"{sig['name']}: link_chains[{position}] repeats an element index, "
                f"which is a cycle — the ORIGINAL would not terminate on it"
            )
        out_of_range = [node for node in nodes if not 0 <= node < ptr_len]
        if out_of_range:
            raise ValueError(
                f"{sig['name']}: link_chains[{position}] names element(s) "
                f"{out_of_range} outside the {ptr_len}-element buffer; they cannot "
                f"be relocated"
            )
        chains.append(nodes)
    return chains


def _stable_seed(name: str, seed: int) -> int:
    """A per-function seed that is IDENTICAL across processes. Python's built-in
    hash() of a str is randomized by PYTHONHASHSEED, so `hash(name)` produced
    different fuzz vectors in every fresh interpreter — the fuzz was not
    reproducible. A SHA-256 digest is stable, so re-running the gate (or a CI
    lane on another machine) exercises exactly the same inputs."""
    digest = hashlib.sha256(name.encode()).digest()
    return (seed ^ int.from_bytes(digest[:8], "big")) & 0xFFFFFFFFFFFFFFFF


def make_vectors(sig: dict, ov: dict, seed: int, fuzz: int) -> list[list]:
    """A list of argument tuples. Scalars are ints (floats for a `float`
    descriptor); pointer params are lists of element values of length ptr_len.
    Length args are clamped to [0, ptr_len]. Pointer element type/range follow the
    DWARF pointee width (1B -> 0..255, else signed 4B fuzz); ov["ptr_elem"] may
    force "u8" or "cstr". Scalar boundaries are width- and signedness-aware so a
    64-bit return's high half and a signed extension are actually exercised;
    floating-point parameters and buffers draw from `float_boundaries` and
    `_float_fuzz` instead."""
    params = [_as_desc(p) for p in sig["params"]]
    ptr_len = ov.get("ptr_len", M.DEFAULT_PTR_LEN)
    len_args = set(ov.get("len_args", []))
    # A parameter restricted to declared values: used for a guard that would
    # otherwise send execution down an unbounded/very long path, where the verdict
    # would depend on machine speed instead of on the decompilation. Validated
    # fail-closed: an empty or non-scalar restriction would silently produce vectors
    # that do not exercise what the manifest claims (or divide by zero below), and a
    # manifest that lies is worse than no manifest.
    arg_values: dict[int, list[int]] = {}
    for k, v in ov.get("arg_values", {}).items():
        i = int(k)
        vals = list(v)
        if not vals:
            raise ValueError(
                f"{sig['name']}: arg_values[{i}] is empty — a pinned parameter must "
                f"declare at least one value"
            )
        if i < 0 or i >= len(params):
            raise ValueError(
                f"{sig['name']}: arg_values[{i}] is out of range for "
                f"{len(params)} parameter(s)"
            )
        if params[i]["k"] != "int":
            # Integer-only, and floating point stays out deliberately: the pinned
            # values are `_wrap`ped to a width and signedness a float does not
            # have, and a manifest cannot spell a bit pattern as a JSON number.
            # `extra_vectors` states exact floating inputs and is the way to do it.
            raise ValueError(
                f"{sig['name']}: arg_values[{i}] pins a parameter that is not an "
                f"integer ({params[i]['k']}); use extra_vectors for pointer "
                f"contents and for exact floating-point inputs"
            )
        arg_values[i] = vals
    # The linked-structure argument kind. Absent -> every self link keeps the
    # historical identity-successor chain, bit for bit, so no existing lane moves.
    link_chains = _validated_link_chains(sig, ov, params, ptr_len)

    def chain_for(k: int) -> list[int] | None:
        """The declared chain this vector uses, cycled by vector index."""
        return None if link_chains is None else link_chains[k % len(link_chains)]

    # "cstr" is "u8" plus the one invariant a string function needs: a NUL inside the
    # buffer. Without it `str_len` walks off the end, and the two libraries then agree
    # only because they read the SAME heap in the SAME process — luck that breaks the
    # moment an allocation lands differently between the two calls. `sum_array` showed
    # what that looks like when the luck runs out: a DIFFERENT wrong value every run.
    elem = ov.get("ptr_elem")
    forced_u8 = elem in ("u8", "cstr")
    is_cstr = elem == "cstr"
    # A byte-element override reinterprets the buffer as `uint8_t`. Over a float
    # buffer that is not a narrowing but a type pun: the harness would fill and
    # compare raw bytes while the function reads them as IEEE values, and every
    # verdict would be about the pun. A manifest that says this is wrong, so say so.
    if forced_u8:
        for d in params:
            if d["k"] == "ptr" and _pointee_desc(d)["k"] == "float":
                raise ValueError(
                    f"{sig['name']}: ptr_elem={elem!r} forces byte elements over a "
                    f"floating-point buffer — the two descriptions disagree"
                )
    rng = random.Random(_stable_seed(sig["name"], seed))

    def is_u8(d):
        pointee = _pointee_desc(d)
        return forced_u8 or (pointee["k"] == "int" and pointee["w"] == 1)

    def aggregate(v, d):
        """Turn one reproducible scalar seed into every scalar aggregate field."""
        values = []
        for field_index, field in enumerate(d["fields"]):
            field_type = field["t"]
            field_seed = v if field_index == 0 else -v + field_index * 3
            if field_type["k"] == "struct":
                values.append(aggregate(field_seed, field_type))
            elif field_type["k"] == "self_ptr":
                values.append(-1)
            else:
                values.append(_wrap(field_seed, field_type["w"], field_type["s"]))
        return values

    def chain(values, d, length, order=None):
        """Populate self links as a bounded acyclic prefix of one struct array.

        `order` is a declared element-index walk (see `_validated_link_chains`).
        With it, node `order[i]` links to `order[i + 1]`, the last node and every
        node the walk does not name link to NULL, and `length` is ignored — the
        chain is exactly what the manifest declared. Without it the successor is
        `index + 1`, which is what every existing fixture records.
        """
        if d["k"] != "struct":
            return values
        link_fields = [
            index
            for index, field in enumerate(d["fields"])
            if field["t"]["k"] == "self_ptr"
        ]
        if order is not None:
            successor = dict(pairwise(order))
            for field_index in link_fields:
                for index, value in enumerate(values):
                    value[field_index] = successor.get(index, -1)
            return values
        for field_index in link_fields:
            for index, value in enumerate(values):
                value[field_index] = index + 1 if index + 1 < length else -1
        return values

    def _terminate(vals, n):
        """vals[:n] mapped into 1..255 (no interior NUL), a NUL, then zero fill."""
        body = [(v % 255) + 1 for v in vals[:n]]
        return (body + [0] * (ptr_len - n))[:ptr_len]

    def scalar(i, v, d):
        if i in arg_values:
            # Deterministic cycle through the declared values, seed-independent.
            allowed = arg_values[i]
            return _wrap(allowed[abs(v) % len(allowed)], d["w"], d["s"])
        if d["k"] == "struct":
            return aggregate(v, d)
        if d["k"] == "float":
            # A float cannot be a length: clamping it would hand the callee a
            # fractional bound, and silently rounding one would invent an index
            # the manifest never declared. Refuse rather than guess.
            if i in len_args:
                raise ValueError(
                    f"{sig['name']}: len_args names parameter {i}, which is "
                    f"floating point — a length must be an integer parameter"
                )
            return _round_to_float_width(v, d["w"])
        v = _wrap(v, d["w"], d["s"])
        return max(0, min(ptr_len, v)) if i in len_args else v

    def buf_det(k, d):
        pointee = _pointee_desc(d)
        if pointee["k"] == "struct":
            values = [aggregate(k * 7 + j * 3, pointee) for j in range(ptr_len)]
            return chain(values, pointee, 1 + k % ptr_len, chain_for(k))
        if is_cstr:
            # Vary the length with k so a string loop is exercised at 0, 1, and full.
            return _terminate([(k * 7 + j * 3) for j in range(ptr_len)], k % ptr_len)
        if is_u8(d):
            return [(k * 7 + j * 3) % 256 for j in range(ptr_len)]
        if pointee["k"] == "float":
            # The same small signed spread the integer case uses, in eighths, so a
            # buffer element is a value with a fraction (a decompilation that
            # truncates through an integer temporary cannot survive it) and every
            # element is exact in binary32.
            return [
                _round_to_float_width((((k * 7 + j * 3) % 17) - 8) / 8.0, pointee["w"])
                for j in range(ptr_len)
            ]
        return [((k * 7 + j * 3) % 17) - 8 for j in range(ptr_len)]

    def buf_rng(k, d):
        pointee = _pointee_desc(d)
        if pointee["k"] == "struct":
            values = [
                aggregate(rng.randrange(-64, 64), pointee) for _ in range(ptr_len)
            ]
            # The length draw is kept even when a chain is declared, so adding
            # `link_chains` to an existing function changes the LINKS and nothing
            # else about that function's seeded stream.
            return chain(values, pointee, rng.randrange(1, ptr_len + 1), chain_for(k))
        if is_cstr:
            n = rng.randrange(0, ptr_len)
            return _terminate([rng.randrange(0, 255) for _ in range(n)], n)
        if pointee["k"] == "float":
            return [_float_fuzz(rng, pointee["w"]) for _ in range(ptr_len)]
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

    # Deterministic scalar boundaries, per scalar arg's own width/signedness — or,
    # for a floating-point parameter, its own format's boundaries. Resolved once
    # per slot rather than per sweep step so the two families stay side by side and
    # an integer parameter's sequence is bit-for-bit what it always was.
    scalar_descs = [d for d in params if d["k"] != "ptr"]
    boundaries = [
        float_boundaries(d["w"])
        if d["k"] == "float"
        else M.scalar_boundaries(d["w"], d.get("s", False))
        for d in scalar_descs
    ]
    n_bounds = max((len(b) for b in boundaries), default=0)
    for bi in range(n_bounds):

        def src(si, bi=bi):
            b = boundaries[si]
            return b[bi % len(b)]

        add(src)
    # Explicit manifest vectors (already full tuples: scalar ints, ptr lists).
    for ev in ov.get("extra_vectors", []):
        vectors.append(_pad_ptr(ev, params, ptr_len))

    # Seeded fuzz. The draw is per-slot because a float slot needs a float: handing
    # `randrange(-64, 64)` to a binary32 parameter would only ever test integers.
    def fuzz_src(si):
        d = scalar_descs[si]
        if d["k"] == "float":
            return _float_fuzz(rng, d["w"])
        return rng.randrange(-64, 64)

    for _ in range(fuzz):
        add(fuzz_src)

    # Materialise buffers: assign deterministic then rng buffers to ptr slots.
    out = []
    for k, args in enumerate(vectors):
        filled = []
        for _i, (d, a) in enumerate(zip(params, args)):
            if d["k"] == "ptr" and a is None:
                filled.append(buf_det(k, d) if k % 2 == 0 else buf_rng(k, d))
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
            pointee = _pointee_desc(d)
            zero = _zero_value(pointee)
            a = (a + [zero] * ptr_len)[:ptr_len]
        out.append(a)
    return out


def _zero_value(d):
    if d["k"] == "struct":
        return [_zero_value(field["t"]) for field in d["fields"]]
    if d["k"] == "self_ptr":
        return -1
    # `+0.0`, not the int 0: the padding a manifest vector receives must be a value
    # of the buffer's own type, so a snapshot of an untouched tail is comparable
    # without a coercion that could hide which side wrote what.
    return 0.0 if d["k"] == "float" else 0


# ---------------------------------------------------------------------------
# Worker (runs in an isolated subprocess)
# ---------------------------------------------------------------------------

#: Wall clock for one function's differential worker. Generous: a slow-but-correct
#: function must not be reported as broken because the machine is busy. A function
#: that needs more than this is a fixture-design problem (pin the guard parameter
#: with the manifest's `arg_values`), not something to paper over with a bigger
#: number.
#:
#: It MUST also exceed `vectors x DECOMPILED_CALL_BUDGET_S`, or a recovery that
#: fails to terminate on every input gets its determinate `fail` converted into a
#: machine-speed-dependent `timeout` — which blocks `--write-baseline` outright.
#: At 60s and the default 12 vectors the two were exactly equal, and
#: `18_binary_heap:aarch64:O0:heap_pop` (which does not terminate on any input)
#: landed on whichever side the load average put it.
WORKER_TIMEOUT_S = 300

#: Wall clock for ONE call into the recompiled decompilation, once the original has
#: already returned for the same input. Generous by three orders of magnitude for
#: this corpus (the slowest correct fixture call measured ~0.9s), so exceeding it
#: means our version does not terminate on an input where the original does.
DECOMPILED_CALL_BUDGET_S = 5.0


_CTYPE = {
    (1, True): ctypes.c_int8,
    (1, False): ctypes.c_uint8,
    (2, True): ctypes.c_int16,
    (2, False): ctypes.c_uint16,
    (4, True): ctypes.c_int32,
    (4, False): ctypes.c_uint32,
    (8, True): ctypes.c_int64,
    (8, False): ctypes.c_uint64,
}


#: The FP calling convention is ctypes' to implement: `c_float`/`c_double` as an
#: argtype or a restype is what puts the value in xmm0..7 and reads it back out of
#: xmm0, which is exactly the ABI edge these fixtures exist to exercise.
_FLOAT_CTYPE = {4: ctypes.c_float, 8: ctypes.c_double}


def _scalar_ctype(d):
    if d["k"] == "float":
        return _FLOAT_CTYPE[d["w"]]
    return _CTYPE[(d["w"], d["s"])]


def _pointee_ctype(d, forced_u8):
    if forced_u8:
        return ctypes.c_uint8
    return _value_ctype(_pointee_desc(d))


_STRUCT_CTYPES: dict[str, type[ctypes.Structure]] = {}


def _struct_return_is_comparable(d):
    """Whether an aggregate return can be marshalled back through ctypes.

    `_struct_ctype` needs every member's offset and a size; a struct whose
    fields DWARF did not describe would build an empty layout and compare equal
    to anything, which is worse than declining it.
    """
    fields = d.get("fields")
    width = d.get("w")
    if not fields or not width:
        return False
    # MEMORY-class returns (over two eightbytes) go through a hidden pointer the
    # caller allocates. `_struct_ctype` builds a `_pack_ = 1` layout, and libffi
    # marshals that differently from the ABI's own hidden-pointer contract --
    # measured: `bv195_make_big` (32 bytes) and `agr198_make_five` (20) both
    # SIGSEGV the worker. Register-returned aggregates are exactly the ones
    # libffi and the ABI agree about, so they are the ones we execute; the
    # larger classes stay `structural` and are still covered by their wrappers.
    if width > 16:
        return False
    try:
        _struct_ctype(d)
    except Exception:
        return False
    return True


def _struct_ctype(d):
    """Build an exact packed ctypes layout from DWARF offsets and size."""
    key = json.dumps(d, sort_keys=True)
    if key in _STRUCT_CTYPES:
        return _STRUCT_CTYPES[key]
    cls = type(
        f"DwarfStruct_{len(_STRUCT_CTYPES)}",
        (ctypes.Structure,),
        {"_pack_": 1},
    )
    # Cache the incomplete class before resolving fields so a self pointer can
    # refer to it without recursively constructing the descriptor forever.
    _STRUCT_CTYPES[key] = cls
    fields, cursor = [], 0
    try:
        for index, field in enumerate(sorted(d["fields"], key=lambda f: f["off"])):
            offset = field["off"]
            if offset < cursor:
                raise ValueError(f"overlapping DWARF struct field at {offset}")
            if offset > cursor:
                fields.append((f"_pad{index}", ctypes.c_uint8 * (offset - cursor)))
            field_type = field["t"]
            ctype = (
                ctypes.POINTER(cls)
                if field_type["k"] == "self_ptr"
                else _value_ctype(field_type)
            )
            fields.append((f"f{index}", ctype))
            cursor = offset + ctypes.sizeof(ctype)
        if cursor > d["w"]:
            raise ValueError("DWARF struct fields exceed declared size")
        if cursor < d["w"]:
            fields.append(("_tail_pad", ctypes.c_uint8 * (d["w"] - cursor)))
        cls._fields_ = fields
    except Exception:
        _STRUCT_CTYPES.pop(key, None)
        raise
    if ctypes.sizeof(cls) != d["w"]:
        raise ValueError(
            f"ctypes struct size {ctypes.sizeof(cls)} != DWARF size {d['w']}"
        )
    _STRUCT_CTYPES[key] = cls
    return cls


def _value_ctype(d):
    if d["k"] in ("int", "float"):
        return _scalar_ctype(d)
    if d["k"] == "struct":
        return _struct_ctype(d)
    raise ValueError(f"unsupported ctypes value descriptor {d['k']}")


def _materialize_value(d, value):
    if d["k"] != "struct":
        return value
    ctype = _struct_ctype(d)
    obj = ctype()
    for index, (field, field_value) in enumerate(zip(d["fields"], value)):
        if field["t"]["k"] != "self_ptr":
            setattr(obj, f"f{index}", _materialize_value(field["t"], field_value))
    return obj


def _snapshot_value(d, value):
    # Bits, not the float: `int(value)` would truncate a buffer element to its
    # integer part (0.5 and 0.4 would compare equal), and keeping the float would
    # compare `-0.0` equal to `0.0` and a NaN unequal to itself. The snapshot is
    # only ever compared and never arithmetic, so the pattern is the right value.
    if d["k"] == "float":
        return float_bits(d["w"], value)
    if d["k"] != "struct":
        return int(value)
    return [
        _snapshot_value(field["t"], getattr(value, f"f{index}"))
        for index, field in enumerate(d["fields"])
    ]


def _materialize_buffer(pointee: dict, values: list):
    """Build one caller-owned buffer, resolving self links after allocation.

    Node contents are stated as ELEMENT INDICES and become real addresses only
    here, once the array exists. Called once per side, so the original and the
    rebuilt object are handed the same graph relocated into their own storage —
    the property the whole linked-structure kind rests on. `_snapshot_buffer`
    reverses it, mapping any surviving link back to an index.

    `-1` is NULL. Any other index outside the buffer is REFUSED rather than
    quietly nulled: nulling it would shorten the chain, both sides would agree
    on the short walk, and the lane would report `pass` for a graph nobody
    declared.
    """
    ctype = _value_ctype(pointee)
    buffer = (ctype * len(values))()
    for index, value in enumerate(values):
        buffer[index] = _materialize_value(pointee, value)
    if pointee["k"] != "struct":
        return buffer
    for element_index, value in enumerate(values):
        for field_index, (field, field_value) in enumerate(
            zip(pointee["fields"], value)
        ):
            if field["t"]["k"] != "self_ptr":
                continue
            target = int(field_value)
            if target == -1:
                pointer = ctypes.POINTER(ctype)()
            elif 0 <= target < len(buffer):
                pointer = ctypes.pointer(buffer[target])
            else:
                raise ValueError(
                    f"self link {target} on element {element_index} field "
                    f"{field_index} is neither -1 (NULL) nor an index into the "
                    f"{len(buffer)}-element buffer, so it cannot be relocated"
                )
            setattr(buffer[element_index], f"f{field_index}", pointer)
    return buffer


def _relative_pointer(pointer, buffer) -> int | None | str:
    """Map a pointer into its owning array to a stable element index."""
    address = ctypes.cast(pointer, ctypes.c_void_p).value
    if address is None:
        return None
    base = ctypes.addressof(buffer)
    stride = ctypes.sizeof(buffer._type_)
    delta = address - base
    if delta < 0 or delta % stride != 0 or delta // stride >= len(buffer):
        return f"external@0x{address:x}"
    return delta // stride


def _snapshot_buffer(pointee: dict, buffer) -> list:
    if pointee["k"] != "struct":
        return [_snapshot_value(pointee, value) for value in buffer]
    snapshot = []
    for element in buffer:
        fields = []
        for index, field in enumerate(pointee["fields"]):
            value = getattr(element, f"f{index}")
            fields.append(
                _relative_pointer(value, buffer)
                if field["t"]["k"] == "self_ptr"
                else _snapshot_value(field["t"], value)
            )
        snapshot.append(fields)
    return snapshot


def _ctypes_fn(lib, sig, forced_u8):
    params = [_as_desc(p) for p in sig["params"]]
    ret = _as_desc(sig["ret"])
    fn = getattr(lib, sig["name"])
    if ret["k"] == "void":
        fn.restype = None
    elif ret["k"] == "ptr":
        fn.restype = ctypes.POINTER(_pointee_ctype(ret, forced_u8))
    elif ret["k"] == "struct":
        # An aggregate return IS comparable: `_struct_ctype` already builds the
        # exact packed layout from DWARF offsets, and libffi applies the
        # platform's own return-class rules to it -- which is precisely the
        # thing under test. Before this, `exec_class` declined every struct
        # return, so fixtures 195/197/198 exercised their aggregate returns only
        # through `int32_t`-returning wrappers and every aggregate-return fix
        # was validated one step removed from the thing it fixed.
        fn.restype = _struct_ctype(ret)
    else:
        fn.restype = _scalar_ctype(ret)
    fn.argtypes = [
        ctypes.POINTER(_pointee_ctype(d, forced_u8))
        if d["k"] == "ptr"
        else _value_ctype(d)
        for d in params
    ]
    return fn


def worker(spec_path: str) -> int:
    # Default disposition: SIGALRM terminates the process even inside a C call.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    spec = json.loads(Path(spec_path).read_text())
    sig = spec["sig"]
    forced_u8 = spec.get("ptr_elem") == "u8"
    params = [_as_desc(p) for p in sig["params"]]
    ret = _as_desc(sig["ret"])
    orig = ctypes.CDLL(spec["orig_so"])
    dec = ctypes.CDLL(spec["dec_so"])
    fo, fd = _ctypes_fn(orig, sig, forced_u8), _ctypes_fn(dec, sig, forced_u8)
    # See PRELUDE: without a scrubbed stack, a recovery that reads an
    # uninitialised local has no stable verdict at all. It lives in the REBUILT
    # object because that is the one this harness owns the source of; a
    # comparator artifact rebuilt without the prelude simply keeps the old,
    # residue-dependent behaviour rather than failing to load.
    scrub = getattr(dec, "glaurung_scrub_stack", None)
    if scrub is not None:
        scrub.restype = None
        scrub.argtypes = []
    progress_path = Path(spec["progress_path"])

    for vec in spec["vectors"]:
        # Persist the exact input before entering native code.  If either shared
        # object crashes or the decompiled call is killed for non-termination,
        # the parent can report a directly reproducible vector instead of an
        # opaque worker exit.
        progress_path.write_text(json.dumps(vec))
        oargs, dargs, obufs, dbufs = [], [], [], []
        pointer_buffers: dict[int, tuple[object, object]] = {}
        for param_index, (d, a) in enumerate(zip(params, vec)):
            if d["k"] == "ptr":
                ct = _pointee_ctype(d, forced_u8)
                pointee = _pointee_desc(d)
                if pointee["k"] == "struct":
                    ob = _materialize_buffer(pointee, a)
                    db = _materialize_buffer(pointee, a)
                else:
                    ob = (ct * len(a))(*[_materialize_value(pointee, v) for v in a])
                    db = (ct * len(a))(*[_materialize_value(pointee, v) for v in a])
                obufs.append(ob)
                dbufs.append(db)
                pointer_buffers[param_index] = (ob, db)
                oargs.append(ob)
                dargs.append(db)
            elif d["k"] == "struct":
                oargs.append(_materialize_value(d, a))
                dargs.append(_materialize_value(d, a))
            else:
                oargs.append(a)
                dargs.append(a)
        if scrub is not None:
            scrub()
        ro = fo(*oargs)
        # The ORIGINAL returned, so this input terminates. If our version does not,
        # that is a behavioural divergence — the most severe kind — and it must be
        # reported as such, not as "the machine was too slow". A Python signal
        # handler cannot interrupt a hung C call, so use the default SIGALRM
        # disposition: the kernel kills this worker, and the parent maps that exact
        # signal to non-termination. It also bounds the gate's wall clock, which a
        # per-function timeout does not (a hung call used to burn the whole budget).
        if scrub is not None:
            scrub()
        signal.setitimer(signal.ITIMER_REAL, DECOMPILED_CALL_BUDGET_S)
        try:
            rd = fd(*dargs)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        # Pointer results are comparable only relative to an explicitly declared
        # caller-owned input buffer. Original and rebuilt arrays have unrelated
        # addresses, but a null/head/middle result has the same stable node index.
        if ret["k"] == "ptr":
            return_arg = spec.get("pointer_return_arg")
            buffers = pointer_buffers.get(return_arg)
            if buffers is None:
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "detail": f"invalid pointer_return_arg {return_arg}",
                        }
                    )
                )
                return 0
            r_original = _relative_pointer(ro, buffers[0])
            r_decompiled = _relative_pointer(rd, buffers[1])
            if r_original != r_decompiled:
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "detail": (
                                f"return node {r_original} != {r_decompiled} on {vec}"
                            ),
                        }
                    )
                )
                return 0
        # A floating-point return is compared as an EXACT BIT PATTERN, never with
        # `==` and never with a tolerance — see `float_bits`. The restype is the
        # DWARF width, so a `float` result is read out of xmm0 as a binary32 and
        # re-packed as one; the caveat is that it passes through a Python double on
        # the way, which preserves every finite value and a quiet NaN's payload but
        # is not a promise about a SIGNALLING NaN (which nothing here generates).
        elif ret["k"] == "float" and float_bits(ret["w"], ro) != float_bits(
            ret["w"], rd
        ):
            print(
                json.dumps(
                    {
                        "ok": False,
                        "detail": (
                            f"return {ro!r} != {rd!r} "
                            f"(bits 0x{float_bits(ret['w'], ro):x} != "
                            f"0x{float_bits(ret['w'], rd):x}) on {vec}"
                        ),
                    }
                )
            )
            return 0
        # Scalar restype is the exact DWARF width/signedness, so this is a full-
        # width comparison (including high halves and sign extension).
        elif ret["k"] == "struct":
            # Compare the aggregate's bytes, not the ctypes objects -- two
            # Structure instances never compare equal, and the padding a
            # non-multiple-of-8 return leaves unspecified must not be read.
            ob, db = bytes(memoryview(ro)), bytes(memoryview(rd))
            if ob != db:
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "detail": f"return {ob.hex()} != {db.hex()} on {vec}",
                        }
                    )
                )
                return 0
        elif ret["k"] not in ("void", "float") and ro != rd:
            print(json.dumps({"ok": False, "detail": f"return {ro} != {rd} on {vec}"}))
            return 0
        ptr_params = [d for d in params if d["k"] == "ptr"]
        for d, ob, db in zip(ptr_params, obufs, dbufs):
            pointee = _pointee_desc(d)
            osnapshot = _snapshot_buffer(pointee, ob)
            dsnapshot = _snapshot_buffer(pointee, db)
            if osnapshot != dsnapshot:
                print(
                    json.dumps(
                        {"ok": False, "detail": f"buffer mutation differs on {vec}"}
                    )
                )
                return 0
    print(json.dumps({"ok": True, "detail": f"{len(spec['vectors'])} cases"}))
    return 0


# ---------------------------------------------------------------------------
# Parent
# ---------------------------------------------------------------------------


def exec_class(sig, fixture, lane: str | None = None) -> tuple[str, str]:
    """Whether a function is execution-differential or structural-only, and why.
    Shared with the structural lane so it knows which functions MUST carry a
    structural assertion (a structural result with no assertion is a gap).

    `lane` is `"<compiler>:<opt>"` when known. `skip_exec_lanes` uses it to skip
    only where the shape is unexecutable, which matters because optimisation
    changes the shape: `cpp_ctor_dtor` passes a `this` derived from an
    uninitialised `rbp` at -O0 and is inlined into something correct at -O2.
    Skipping the whole function to make -O0 deterministic would throw away two
    genuine -O2 passes."""
    ov = M.override(fixture, sig["name"])
    if ov.get("skip_exec"):
        return "structural", "manifest skip_exec"
    if lane and lane in ov.get("skip_exec_lanes", ()):
        return "structural", f"manifest skip_exec_lanes ({lane})"
    ret = _as_desc(sig["ret"])
    has_ptr = any(_as_desc(p)["k"] == "ptr" for p in sig["params"])
    if ret["k"] == "ptr" and "pointer_return_arg" not in ov:
        return "structural", "pointer return — addresses not comparable"
    if ret["k"] == "struct" and not _struct_return_is_comparable(ret):
        return "structural", "aggregate return — layout not describable from DWARF"
    if any(
        _as_desc(param)["k"] == "struct" and _as_desc(param)["w"] > 8
        for param in sig["params"]
    ):
        return "structural", "multi-eightbyte aggregate parameter — unsupported ABI"
    if ret["k"] == "void" and not has_ptr:
        return "structural", "void return, no buffer — not execution-differential"
    return "exec", ""


def run_function(
    sig,
    fixture,
    binary,
    workdir,
    seed,
    fuzz,
    lane=None,
    decompiled_by_va: dict[int, str] | None = None,
    allow_native_helper_fallback: bool = False,
    reference_so: str | None = None,
    reference_sig: dict | None = None,
    native_cc: list[str] | None = None,
    native_runner: list[str] | None = None,
) -> dict:
    """Run one function's execution differential.

    `binary` is the object being *decompiled*. `reference_so` is the object the
    recovery is executed against, and defaults to `binary` — which is the right
    thing whenever the binary is host-loadable.

    They differ only for cross-architecture lanes (`tools/arch_roundtrip.py`):
    an AArch64, ARM32 or i386 object cannot be `dlopen`ed here, so the reference
    is the same source built for the host. The question being asked is unchanged
    — does the C recovered from that object behave like the source it came from —
    and keeping an emulator out of the loop means a qemu bug can never be
    mistaken for a decompiler bug.

    `reference_so` is also what the rebuilt decompilation LINKS against. Linking
    against a foreign-architecture object silently fails and every recovered body
    that calls an exported sibling then dies at load time with `undefined symbol`
    — a harness artifact indistinguishable from a decompiler bug (it accounted
    for 44 of the first ARM run's "failures"). The host-side reference supplies
    exactly the sibling behaviour the same-architecture lanes get.

    `reference_sig` is that host object's DWARF signature for the same function,
    used by `abi_incomparable` to refuse a verdict where the two builds do not
    agree on the ABI types. `native_cc` is the target's own compiler driver and
    flags: when given, the recovered body is additionally compiled FOR ITS OWN
    ARCHITECTURE (see `native_rebuild_diagnostic`), which is the only build that
    can reject C the target cannot spell. ``native_runner`` selects a genuine
    target-ABI worker for signatures the generated C comparator supports.
    """
    name = sig["name"]
    reference_so = reference_so or binary
    ov = M.override(fixture, name)
    # Structural-only functions (function-pointer callbacks, void-no-buffer,
    # pointer returns) have no observable int value to diff — never a silent
    # pass; the structural lane asserts on them instead.
    cls, why = exec_class(sig, fixture, lane)
    if cls == "structural":
        return {"status": "structural", "detail": why}
    c = (
        decompiled_c(binary, sig["va"])
        if decompiled_by_va is None
        else decompiled_by_va.get(sig["va"])
    )
    if c is None:
        return {"status": "fail", "detail": "decompile failed"}
    c = include_referenced_local_callees(
        binary,
        c,
        decompiled_by_va,
        allow_native_fallback=allow_native_helper_fallback,
    )
    declarations = dwarf_c_type_declarations(sig, c)
    if declarations:
        c = declarations + "\n" + c
    width_dependent = width_sensitive(c)
    dec_so, diagnostic = build_so_with_diagnostic(
        c,
        workdir,
        f"dec_{name}",
        link_against=reference_so,
    )
    if dec_so is None:
        return {
            "status": "fail",
            "detail": f"decompiled C failed to compile: {diagnostic[-500:]}",
        }
    # Checked BEFORE the ABI refusal below and before any execution: C the target
    # cannot compile is a decompiler defect outright, and it must not be hidden
    # behind a function whose two sides happen to be incomparable.
    if native_cc is not None:
        native = native_rebuild_diagnostic(c, workdir, name, native_cc)
        if native:
            return {
                "status": "nonportable",
                "detail": (
                    f"recovered C does not compile for the architecture it was "
                    f"recovered from ({' '.join(native_cc)}): {native[-400:]}"
                ),
            }
    vectors = make_vectors(sig, ov, seed, fuzz)
    if not vectors:
        # An infra/manifest problem (no inputs generated), NOT a decompiler
        # result — a distinct status so --write-baseline can refuse it.
        return {"status": "nocases", "detail": "no executable cases"}
    if native_cc is not None and native_runner is not None:
        target_verdict = native_execution_differential(
            c,
            binary,
            sig,
            vectors,
            workdir,
            native_cc,
            native_runner,
            ov.get("ptr_elem", "int"),
        )
        if target_verdict is not None:
            return target_verdict
    why_incomparable = abi_incomparable(sig, reference_sig)
    if why_incomparable is not None:
        return {"status": "incomparable", "detail": why_incomparable}
    progress_path = workdir / f"progress_{name}.json"
    progress_path.unlink(missing_ok=True)
    # Every path the worker hands to `dlopen`/`open` is RELATIVE to `workdir`
    # (it runs with `cwd=workdir`). The loader's own stack use scales with the
    # path it is given, so absolute paths made a recovery that reads an
    # uninitialised local report `fail` from `/tmp/aa` and `pass` from a
    # 65-character sibling directory — the verdict was a property of where the
    # gate was run from. Relative, fixed-length names remove the channel.
    spec = {
        "sig": sig,
        "orig_so": f"./{_fixed_name_sibling(Path(reference_so), workdir).name}",
        "dec_so": f"./{dec_so.name}",
        "vectors": vectors,
        "ptr_elem": ov.get("ptr_elem", "int"),
        "pointer_return_arg": ov.get("pointer_return_arg"),
        "progress_path": progress_path.name,
    }
    spec_path = workdir / f"spec_{name}.json"
    spec_path.write_text(json.dumps(spec))

    def invoke_worker() -> subprocess.CompletedProcess | None:
        """Run the differential worker once. `None` means it blew the wall clock."""
        try:
            return _spawn_worker(spec_path, workdir)
        except subprocess.TimeoutExpired:
            return None

    r = invoke_worker()
    if r is not None and r.returncode == -signal.SIGALRM:
        # The per-call budget fired. That is NOT yet evidence of a defect: this
        # file already says so for the outer wall clock a few lines below —
        # "exceeding a wall clock is not evidence that the decompilation is
        # wrong, and recording it as a semantic verdict bakes machine speed into
        # the baseline" — and the inner budget deserves the same reading.
        #
        # `DECOMPILED_CALL_BUDGET_S` is 5s against a slowest-correct-call
        # measurement of ~0.9s. That margin is thin enough that a loaded machine
        # can push a correct-but-slow call past it, which is how a lane comes
        # back `fail` under a parallel sweep and `pass` three times in isolation.
        # It is why `default_jobs` is capped well under `cpu_count`.
        #
        # Retrying once keeps BOTH properties the budget exists for. A genuinely
        # non-terminating recovery alarms again and still earns a determinate
        # `fail`, so `--write-baseline` is not blocked (see the note on
        # `WORKER_TIMEOUT_S` and `18_binary_heap:aarch64:O0:heap_pop`). Only the
        # load-sensitive case changes, and the retry costs nothing on the
        # overwhelming majority of functions that never alarm at all.
        retry = invoke_worker()
        if retry is not None:
            r = retry
    if r is None:
        # NOT `fail`: see above.
        return {"status": "timeout", "detail": f"worker exceeded {WORKER_TIMEOUT_S}s"}
    try:
        last_input = json.loads(progress_path.read_text())
        input_detail = f" on {last_input}"
    except OSError, json.JSONDecodeError:
        input_detail = ""
    if r.returncode == -signal.SIGALRM:
        # Alarmed twice, on a loaded machine and again on retry: the original
        # returned and ours did not. See DECOMPILED_CALL_BUDGET_S.
        return {
            "status": "fail",
            "detail": f"decompiled function did not terminate within "
            f"{DECOMPILED_CALL_BUDGET_S}s on an input the original returned on"
            f"{input_detail} (retried once)",
            "width_sensitive": width_dependent,
        }
    if r.returncode != 0:
        return {
            "status": "fail",
            "detail": f"worker crashed{input_detail} "
            f"(exit {r.returncode}; {r.stderr.strip()[-120:]})",
            "width_sensitive": width_dependent,
        }
    try:
        verdict = json.loads(r.stdout.strip().splitlines()[-1])
    except json.JSONDecodeError, IndexError:
        return {
            "status": "fail",
            "detail": "worker produced no verdict",
            "width_sensitive": width_dependent,
        }
    return {
        "status": "pass" if verdict["ok"] else "fail",
        "detail": verdict["detail"],
        # Quantifies the residual 32-bit confound (see `width_sensitive`): a
        # `fail` with this False is a real semantic defect, not a portability
        # artifact of rebuilding at the host's width.
        "width_sensitive": width_dependent,
    }


def _spawn_worker(spec_path: Path, workdir: Path) -> subprocess.CompletedProcess:
    """One differential worker invocation. Raises `TimeoutExpired` on the wall clock."""
    return subprocess.run(
        [
            *BG.worker_launch_prefix(),
            sys.executable,
            __file__,
            "--worker",
            # Relative, from `cwd` below. argv lands on the initial stack
            # next to the environment, so an ABSOLUTE spec path made the
            # frame offset depend on how long the scratch directory's name
            # happened to be — `GLAURUNG_FIXTURE_TMPDIR` alone was enough to
            # flip `04_switch_shapes:armv7:O0:dense_compute`. Relative keeps
            # argv a constant for a given function.
            spec_path.name,
        ],
        capture_output=True,
        text=True,
        timeout=WORKER_TIMEOUT_S,
        check=False,
        cwd=str(workdir),
        # Fixed environment + no address randomization: see
        # `build_guard.worker_env`. Without all three, a recovery that reads
        # an uninitialised local gives a different verdict per shell, per
        # scratch directory, and per run.
        env=BG.worker_env(),
    )


INFRA_STATUSES = {"missing", "nocases", "timeout"}


def exit_code(results: dict) -> int:
    """0 = all good; 1 = semantic fail(s); 2 = infra/lane failure (must never be
    baked into a baseline). Distinguishing lets CI and --write-baseline treat
    infrastructure breakage differently from known decompiler bugs."""
    if "__error__" in results:
        return 2
    statuses = {r["status"] for r in results.values()}
    if statuses & INFRA_STATUSES:
        return 2
    # `nonportable` is a decompiler defect (we emitted C its own target cannot
    # compile), so it is a semantic failure. `incomparable` is not a verdict about
    # the decompiler at all — it is this harness declining to measure — so it
    # neither passes nor fails the run.
    return 1 if statuses & {"fail", "nonportable"} else 0


def run(
    binary: str,
    source: str,
    fixture: str,
    seed: int,
    fuzz: int,
    only: set[str] | None = None,
    decompiled_by_va: dict[int, str] | None = None,
    reference_so: str | None = None,
    lane: str | None = None,
    native_cc: list[str] | None = None,
    native_runner: list[str] | None = None,
) -> dict:
    """`only` restricts which functions are executed and reported.

    Each function's fuzz vectors come from `_stable_seed(name, seed)` — derived
    from the function's own name, not from its position in the run — so a
    filtered run gives a filtered function exactly the verdict a full run would.
    A filter that changed the vectors would make `tools/dectest.py` a different
    measurement from the gate, which is the one thing it must not be.

    `reference_so` (see `run_function`) is the host-loadable object the recovery
    is executed and linked against; it defaults to `binary`. `lane` overrides the
    lane label otherwise inferred from the binary's filename.

    Only DYNAMICALLY EXPORTED functions are executed, at every architecture. A
    file-local `static` helper has no dynamic symbol, so the reference side
    cannot be called through ctypes at all, and — because it is local — the
    round-trip closure in `include_referenced_local_callees` prepends the very
    body being tested and the rebuild dies with `redefinition of ...`. Both are
    harness artifacts; `static` helpers are covered where they belong, inside
    their exported callers.
    """
    # `<fixture>-<compiler>-<opt>.so` — the lane a per-lane skip is keyed on.
    if lane is None:
        stem = Path(binary).stem
        parts = stem.rsplit("-", 2)
        lane = f"{parts[1]}:{parts[2]}" if len(parts) == 3 else None
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
    # Zero recoverable signatures would make EVERY function `structural` — a
    # green, entirely un-executed lane. That is the exact failure mode this gate
    # exists to prevent, so it is an error, not a result. (A single unrecoverable
    # signature still degrades to `structural`; only a wholesale loss is infra.)
    if not sig_by_name:
        return {"__error__": f"no DWARF signatures recoverable from {binary}"}
    # The host reference's own prototypes. Only meaningful when it is a DIFFERENT
    # build from the object being decompiled, which is exactly the cross-
    # architecture case `abi_incomparable` exists for.
    reference_sig_by_name: dict[str, dict] = {}
    if reference_so is not None and str(reference_so) != str(binary):
        reference_sig_by_name = {s["name"]: s for s in signatures(reference_so)}
        if not reference_sig_by_name:
            # Without the reference's prototypes every ABI mismatch is invisible
            # and every verdict silently trusts the target's widths. Fail closed.
            return {
                "__error__": (
                    f"no DWARF signatures recoverable from the reference "
                    f"{reference_so} — ABI comparability cannot be checked"
                )
            }
    # Required-function presence = present in the symbol table. (A dropped/renamed
    # export is a real infra failure; an unparseable signature is not.)
    for req in M.REQUIRED_FUNCTIONS.get(fixture, []):
        if only is not None and req not in only:
            continue
        if req not in exported:
            results[req] = {
                "status": "missing",
                "detail": "required function missing from binary",
            }
    selected_names = [name for name in sorted(exported) if only is None or name in only]
    executable_sigs = [
        sig_by_name[name]
        for name in selected_names
        if name in sig_by_name
        and exec_class(sig_by_name[name], fixture, lane)[0] == "exec"
    ]
    owns_decompilation = decompiled_by_va is None
    if owns_decompilation:
        decompiled_by_va = decompiled_many_c(
            binary, [sig["va"] for sig in executable_sigs]
        )
    with tempfile.TemporaryDirectory(dir=M.tmpdir()) as td:
        wd = Path(td)
        for name in sorted(exported):
            if only is not None and name not in only:
                continue
            sig = sig_by_name.get(name)
            if sig is None:
                # Exported but no recoverable DWARF signature (function-pointer
                # param, or O2 ranges/abstract-origin form) — not execution-
                # differential; report structural, never a silent pass or a
                # baseline-blocking infra status.
                results[name] = {
                    "status": "structural",
                    "detail": "signature not recoverable from DWARF",
                }
                continue
            results[name] = run_function(
                sig,
                fixture,
                binary,
                wd,
                seed,
                fuzz,
                lane=lane,
                decompiled_by_va=decompiled_by_va,
                allow_native_helper_fallback=owns_decompilation,
                reference_so=reference_so,
                reference_sig=reference_sig_by_name.get(name),
                native_cc=native_cc,
                native_runner=native_runner,
            )
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?")
    ap.add_argument("source", nargs="?")
    ap.add_argument("--fixture", default=None)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--fuzz", type=int, default=24)
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--function",
        action="append",
        default=None,
        help="only this function (repeatable); default: every export",
    )
    ap.add_argument(
        "--reference-so",
        default=None,
        help="host-loadable object to execute/link the recovery against "
        "(default: the binary itself; differs only for cross-architecture lanes)",
    )
    ap.add_argument(
        "--lane",
        default=None,
        help="lane label for manifest per-lane skips (default: inferred from the "
        "binary filename)",
    )
    ap.add_argument(
        "--native-cc",
        default=None,
        help="the TARGET's own compiler driver and flags, JSON list. Every "
        "recovered body is additionally compiled for that architecture; C the "
        "target cannot spell is reported `nonportable`.",
    )
    ap.add_argument(
        "--native-runner",
        default=None,
        help="target execution command prefix, JSON list. Supported signatures "
        "are rebuilt and differentially executed at the target ABI.",
    )
    ap.add_argument("--worker", default=None)
    args = ap.parse_args()

    if args.worker:
        return worker(args.worker)

    if not args.binary or not args.source:
        ap.error("binary and source required")
    fixture = args.fixture or Path(args.source).stem
    results = run(
        args.binary,
        args.source,
        fixture,
        args.seed,
        args.fuzz,
        only=set(args.function) if args.function else None,
        reference_so=args.reference_so,
        lane=args.lane,
        native_cc=json.loads(args.native_cc) if args.native_cc else None,
        native_runner=json.loads(args.native_runner) if args.native_runner else None,
    )
    if args.json:
        print(json.dumps(results, indent=2))
        return exit_code(results)
    if "__error__" in results:
        print(f"ERROR: {results['__error__']}", file=sys.stderr)
        return 2
    tags = {
        "pass": "PASS",
        "fail": "FAIL",
        "structural": "STRUCT",
        "missing": "MISSING",
        "nocases": "NOCASES",
        "timeout": "TIMEOUT",
        "incomparable": "INCOMP",
        "nonportable": "NONPORT",
    }
    counts = {k: 0 for k in tags}
    for name, r in sorted(results.items()):
        counts[r["status"]] += 1
        print(f"{tags[r['status']]} {name}: {r['detail']}")
    print(
        f"\n{counts['pass']} pass, {counts['fail']} fail, {counts['structural']} structural, "
        f"{counts['missing']} missing, {counts['nocases']} no-cases, "
        f"{counts['timeout']} timed out, {counts['incomparable']} ABI-incomparable, "
        f"{counts['nonportable']} non-portable"
    )
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
