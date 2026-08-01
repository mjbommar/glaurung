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
import random
import re
import signal
import subprocess
import sys
import tempfile
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
typedef __uint128_t undefined16;
typedef uint8_t uint1; typedef int8_t int1;
typedef uint16_t uint2; typedef int16_t int2;
typedef uint32_t uint4; typedef int32_t int4;
typedef uint64_t uint8; typedef int64_t int8;
#ifndef __cplusplus
typedef _Bool bool;
#define true 1
#define false 0
#endif
long __unknown(long x){ (void)x; return 0; }
"""

# ---------------------------------------------------------------------------
# Signature recovery
# ---------------------------------------------------------------------------

# Encodings we accept as integer scalars (float/complex are unsupported).
_SIGNED_ENC = {0x05, 0x06, 0x0D}  # signed, signed_char, signed_fixed
_UNSIGNED_ENC = {
    0x02,
    0x07,
    0x08,
    0x0E,
}  # boolean, unsigned, unsigned_char, unsigned_fixed


def _resolve(ref, cu, drop_cv: bool):
    """Peel typedef (and optionally const/volatile) wrappers; report const seen."""
    const = False
    for _ in range(16):
        tag = ref.tag
        if tag == "DW_TAG_const_type":
            const = True
        elif (
            tag not in ("DW_TAG_typedef", "DW_TAG_volatile_type")
            or not drop_cv
            and tag in ("DW_TAG_const_type", "DW_TAG_volatile_type")
        ):
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


def _dwarf_typedef_name(ref, cu) -> str | None:
    """Return the first C typedef name on a DWARF wrapper chain, if any."""
    for _ in range(16):
        if ref.tag == "DW_TAG_typedef":
            name_attr = ref.attributes.get("DW_AT_name")
            if name_attr is not None:
                name = name_attr.value.decode(errors="replace")
                if re.fullmatch(r"[A-Za-z_]\w*", name):
                    return name
        if ref.tag not in (
            "DW_TAG_typedef",
            "DW_TAG_const_type",
            "DW_TAG_volatile_type",
        ):
            return None
        type_attr = ref.attributes.get("DW_AT_type")
        if type_attr is None:
            return None
        try:
            ref = cu.get_DIE_from_refaddr(type_attr.value)
        except Exception:  # noqa: BLE001 - malformed debug data is unsupported
            return None
    return None


def _die_desc(ref, cu, seen: set[int] | None = None):
    """Describe one resolved DIE.

    Aggregate execution is deliberately bounded to plain data structs. That is
    enough for the SysV `struct { int x, y; }` eightbyte used by DecBench while
    refusing bit-fields, unions, pointer members, and location expressions whose
    ABI/data layout this harness cannot state exactly.
    """
    ref, _ = _resolve(ref, cu, drop_cv=True)
    if ref is None:
        return None
    scalar = _scalar_desc(ref)
    if scalar is not None:
        return scalar
    if ref.tag != "DW_TAG_structure_type":
        return None
    offset = ref.offset
    seen = set() if seen is None else set(seen)
    if offset in seen:
        return None
    seen.add(offset)
    size_attr = ref.attributes.get("DW_AT_byte_size")
    if size_attr is None or not 1 <= size_attr.value <= 256:
        return None
    fields = []
    for index, child in enumerate(ref.iter_children()):
        if child.tag != "DW_TAG_member":
            continue
        if "DW_AT_bit_size" in child.attributes:
            return None
        loc = child.attributes.get("DW_AT_data_member_location")
        typ = child.attributes.get("DW_AT_type")
        if loc is None or typ is None or not isinstance(loc.value, int):
            return None
        try:
            field_ref = cu.get_DIE_from_refaddr(typ.value)
        except Exception:  # noqa: BLE001
            return None
        field_type = _die_desc(field_ref, cu, seen)
        # Pointer-bearing aggregates need deep allocation/lifetime semantics;
        # keep this first implementation exact by accepting scalar/nested-data
        # fields only.
        if field_type is None or field_type["k"] not in ("int", "struct"):
            return None
        name_attr = child.attributes.get("DW_AT_name")
        name = (
            name_attr.value.decode(errors="replace")
            if name_attr is not None
            else f"field{index}"
        )
        fields.append({"name": name, "off": loc.value, "t": field_type})
    if not fields:
        return None
    fields.sort(key=lambda field: field["off"])
    return {"k": "struct", "w": size_attr.value, "fields": fields}


def _type_desc(type_attr, cu):
    """Full descriptor for a DWARF type reference, or None if unsupported.

    scalar : {'k':'int','w':1|2|4|8,'s':bool}
    struct : {'k':'struct','w':bytes,'fields':[{'off':N,'t':desc}, ...]}
    pointer: {'k':'ptr','p':pointee_descriptor,'const':bool}; scalar pointees
             retain the legacy `pw`/`ps` keys for manifest compatibility.
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
        pointee_name = _dwarf_typedef_name(pref, cu)
        pref2, const = _resolve(pref, cu, drop_cv=True)
        pointee = _die_desc(pref2, cu)
        if pointee is None:
            return None
        if pointee["k"] == "struct" and pointee_name is not None:
            pointee = {**pointee, "name": pointee_name}
        desc = {"k": "ptr", "p": pointee, "const": const}
        if pointee["k"] == "int":
            desc.update({"pw": pointee["w"], "ps": pointee["s"]})
        return desc
    return _die_desc(ref, cu)


def _inherited_attr(die, name: str, cu):
    """Resolve one attribute through a bounded abstract-origin/specification chain."""
    seen: set[int] = set()
    for _ in range(16):
        if die.offset in seen:
            return None
        seen.add(die.offset)
        if value := die.attributes.get(name):
            return value
        origin = die.attributes.get("DW_AT_abstract_origin") or die.attributes.get(
            "DW_AT_specification"
        )
        if origin is None:
            return None
        try:
            die = cu.get_DIE_from_refaddr(origin.value)
        except Exception:  # noqa: BLE001
            return None
    return None


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
                if "DW_AT_low_pc" not in die.attributes:
                    continue
                name_attr = _inherited_attr(die, "DW_AT_name", cu)
                if name_attr is None:
                    continue
                name = name_attr.value.decode()
                va = die.attributes["DW_AT_low_pc"].value
                params, ok = [], True
                for c in die.iter_children():
                    if c.tag != "DW_TAG_formal_parameter":
                        continue
                    d = _type_desc(_inherited_attr(c, "DW_AT_type", cu), cu)
                    if d is None or d.get("k") == "void":
                        ok = False
                        break
                    params.append(d)
                if not ok:
                    continue
                ret = _type_desc(_inherited_attr(die, "DW_AT_type", cu), cu)
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


def _pointee_desc(d):
    """Return a pointer's full pointee descriptor, including legacy shorthands."""
    if "p" in d:
        return d["p"]
    return {"k": "int", "w": d.get("pw", 1), "s": d.get("ps", False)}


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
    except (OSError, RuntimeError, ValueError):
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
_FUNCTION_DEFINITION = re.compile(
    r"(?m)^(?!extern\b)(?P<prefix>[A-Za-z_][A-Za-z0-9_ \t*]*[ \t]+)"
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


def include_referenced_local_callees(
    binary: str,
    root_c: str,
    decompiled_by_va: dict[int, str] | None = None,
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

    def visit(name: str) -> None:
        if (
            name in snippets
            or name in visiting
            or len(snippets) + len(visiting) >= 32
        ):
            return
        visiting.add(name)
        _symbol, va = local[name]
        helper = (
            decompiled_c(binary, va)
            if decompiled_by_va is None
            else decompiled_by_va.get(va)
        )
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
    than delegating to the original — otherwise the recursion would go untested."""
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
    base = [compiler, "-shared", "-fPIC", "-O0", "-w", "-o", str(so), str(src)]
    runtime_args = (
        _inherited_cxx_runtime_args(link_against)
        if link_against and Path(link_against).is_file()
        else []
    )
    if link_against and Path(link_against).is_file():
        orig = Path(link_against).resolve()
        r = TC.run(base + [str(orig), f"-Wl,-rpath,{orig.parent}", *runtime_args])
        if r.returncode == 0:
            return so, ""
        # Linking is an ENHANCEMENT, so its failure must not be reported as
        # "decompiled C failed to compile" — that verdict belongs to the
        # decompiler. Retry without: a function that calls no sibling links fine,
        # and one that does will say `undefined symbol` at load time, which is a
        # different and accurate message.
    r = TC.run(base + runtime_args)
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
    else signed 4B fuzz); ov["ptr_elem"] may force "u8" or "cstr". Scalar boundaries are
    width- and signedness-aware so a 64-bit return's high half and a signed
    extension are actually exercised."""
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
            raise ValueError(
                f"{sig['name']}: arg_values[{i}] pins a non-scalar parameter "
                f"({params[i]['k']}); use extra_vectors for pointer contents"
            )
        arg_values[i] = vals
    # "cstr" is "u8" plus the one invariant a string function needs: a NUL inside the
    # buffer. Without it `str_len` walks off the end, and the two libraries then agree
    # only because they read the SAME heap in the SAME process — luck that breaks the
    # moment an allocation lands differently between the two calls. `sum_array` showed
    # what that looks like when the luck runs out: a DIFFERENT wrong value every run.
    elem = ov.get("ptr_elem")
    forced_u8 = elem in ("u8", "cstr")
    is_cstr = elem == "cstr"
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
            else:
                values.append(
                    _wrap(field_seed, field_type["w"], field_type["s"])
                )
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
        v = _wrap(v, d["w"], d["s"])
        return max(0, min(ptr_len, v)) if i in len_args else v

    def buf_det(k, d):
        pointee = _pointee_desc(d)
        if pointee["k"] == "struct":
            return [aggregate(k * 7 + j * 3, pointee) for j in range(ptr_len)]
        if is_cstr:
            # Vary the length with k so a string loop is exercised at 0, 1, and full.
            return _terminate([(k * 7 + j * 3) for j in range(ptr_len)], k % ptr_len)
        if is_u8(d):
            return [(k * 7 + j * 3) % 256 for j in range(ptr_len)]
        return [((k * 7 + j * 3) % 17) - 8 for j in range(ptr_len)]

    def buf_rng(d):
        pointee = _pointee_desc(d)
        if pointee["k"] == "struct":
            return [aggregate(rng.randrange(-64, 64), pointee) for _ in range(ptr_len)]
        if is_cstr:
            n = rng.randrange(0, ptr_len)
            return _terminate([rng.randrange(0, 255) for _ in range(n)], n)
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
    scalar_ws = [
        (d["w"], d.get("s", False)) for d in params if d["k"] != "ptr"
    ]
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
            pointee = _pointee_desc(d)
            zero = _zero_value(pointee)
            a = (a + [zero] * ptr_len)[:ptr_len]
        out.append(a)
    return out


def _zero_value(d):
    if d["k"] == "struct":
        return [_zero_value(field["t"]) for field in d["fields"]]
    return 0


# ---------------------------------------------------------------------------
# Worker (runs in an isolated subprocess)
# ---------------------------------------------------------------------------

#: Wall clock for one function's differential worker. Generous: a slow-but-correct
#: function must not be reported as broken because the machine is busy. A function
#: that needs more than this is a fixture-design problem (pin the guard parameter
#: with the manifest's `arg_values`), not something to paper over with a bigger
#: number.
WORKER_TIMEOUT_S = 60

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


def _scalar_ctype(d):
    return _CTYPE[(d["w"], d["s"])]


def _pointee_ctype(d, forced_u8):
    if forced_u8:
        return ctypes.c_uint8
    return _value_ctype(_pointee_desc(d))


_STRUCT_CTYPES: dict[str, type[ctypes.Structure]] = {}


def _struct_ctype(d):
    """Build an exact packed ctypes layout from DWARF offsets and size."""
    key = json.dumps(d, sort_keys=True)
    if key in _STRUCT_CTYPES:
        return _STRUCT_CTYPES[key]
    fields, cursor = [], 0
    for index, field in enumerate(sorted(d["fields"], key=lambda f: f["off"])):
        offset = field["off"]
        if offset < cursor:
            raise ValueError(f"overlapping DWARF struct field at {offset}")
        if offset > cursor:
            fields.append((f"_pad{index}", ctypes.c_uint8 * (offset - cursor)))
        ctype = _value_ctype(field["t"])
        fields.append((f"f{index}", ctype))
        cursor = offset + ctypes.sizeof(ctype)
    if cursor > d["w"]:
        raise ValueError("DWARF struct fields exceed declared size")
    if cursor < d["w"]:
        fields.append(("_tail_pad", ctypes.c_uint8 * (d["w"] - cursor)))
    cls = type(
        f"DwarfStruct_{len(_STRUCT_CTYPES)}",
        (ctypes.Structure,),
        {"_pack_": 1, "_fields_": fields},
    )
    if ctypes.sizeof(cls) != d["w"]:
        raise ValueError(
            f"ctypes struct size {ctypes.sizeof(cls)} != DWARF size {d['w']}"
        )
    _STRUCT_CTYPES[key] = cls
    return cls


def _value_ctype(d):
    if d["k"] == "int":
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
        setattr(obj, f"f{index}", _materialize_value(field["t"], field_value))
    return obj


def _snapshot_value(d, value):
    if d["k"] != "struct":
        return int(value)
    return [
        _snapshot_value(field["t"], getattr(value, f"f{index}"))
        for index, field in enumerate(d["fields"])
    ]


def _ctypes_fn(lib, sig, forced_u8):
    params = [_as_desc(p) for p in sig["params"]]
    ret = _as_desc(sig["ret"])
    fn = getattr(lib, sig["name"])
    fn.restype = None if ret["k"] == "void" else _scalar_ctype(ret)
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
    progress_path = Path(spec["progress_path"])

    for vec in spec["vectors"]:
        # Persist the exact input before entering native code.  If either shared
        # object crashes or the decompiled call is killed for non-termination,
        # the parent can report a directly reproducible vector instead of an
        # opaque worker exit.
        progress_path.write_text(json.dumps(vec))
        oargs, dargs, obufs, dbufs = [], [], [], []
        for d, a in zip(params, vec):
            if d["k"] == "ptr":
                ct = _pointee_ctype(d, forced_u8)
                pointee = _pointee_desc(d)
                ob = (ct * len(a))(*[_materialize_value(pointee, v) for v in a])
                db = (ct * len(a))(*[_materialize_value(pointee, v) for v in a])
                obufs.append(ob)
                dbufs.append(db)
                oargs.append(ob)
                dargs.append(db)
            elif d["k"] == "struct":
                oargs.append(_materialize_value(d, a))
                dargs.append(_materialize_value(d, a))
            else:
                oargs.append(a)
                dargs.append(a)
        ro = fo(*oargs)
        # The ORIGINAL returned, so this input terminates. If our version does not,
        # that is a behavioural divergence — the most severe kind — and it must be
        # reported as such, not as "the machine was too slow". A Python signal
        # handler cannot interrupt a hung C call, so use the default SIGALRM
        # disposition: the kernel kills this worker, and the parent maps that exact
        # signal to non-termination. It also bounds the gate's wall clock, which a
        # per-function timeout does not (a hung call used to burn the whole budget).
        signal.setitimer(signal.ITIMER_REAL, DECOMPILED_CALL_BUDGET_S)
        try:
            rd = fd(*dargs)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        # restype is set to the exact DWARF width/signedness, so equality is a
        # FULL-width comparison (a dropped high 32 bits or a wrong sign extension
        # diverges here).
        if ret["k"] != "void" and ro != rd:
            print(json.dumps({"ok": False, "detail": f"return {ro} != {rd} on {vec}"}))
            return 0
        ptr_params = [d for d in params if d["k"] == "ptr"]
        for d, ob, db in zip(ptr_params, obufs, dbufs):
            pointee = _pointee_desc(d)
            osnapshot = [_snapshot_value(pointee, value) for value in ob]
            dsnapshot = [_snapshot_value(pointee, value) for value in db]
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
    if ret["k"] == "ptr":
        return "structural", "pointer return — addresses not comparable"
    if ret["k"] == "struct":
        return "structural", "aggregate return — not execution-differential"
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
) -> dict:
    name = sig["name"]
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
    c = include_referenced_local_callees(binary, c, decompiled_by_va)
    declarations = dwarf_c_type_declarations(sig, c)
    if declarations:
        c = declarations + "\n" + c
    dec_so, diagnostic = build_so_with_diagnostic(
        c,
        workdir,
        f"dec_{name}",
        link_against=binary,
    )
    if dec_so is None:
        return {
            "status": "fail",
            "detail": f"decompiled C failed to compile: {diagnostic[-500:]}",
        }
    vectors = make_vectors(sig, ov, seed, fuzz)
    if not vectors:
        # An infra/manifest problem (no inputs generated), NOT a decompiler
        # result — a distinct status so --write-baseline can refuse it.
        return {"status": "nocases", "detail": "no executable cases"}
    progress_path = workdir / f"progress_{name}.json"
    progress_path.unlink(missing_ok=True)
    spec = {
        "sig": sig,
        "orig_so": binary,
        "dec_so": str(dec_so),
        "vectors": vectors,
        "ptr_elem": ov.get("ptr_elem", "int"),
        "progress_path": str(progress_path),
    }
    spec_path = workdir / f"spec_{name}.json"
    spec_path.write_text(json.dumps(spec))
    try:
        r = subprocess.run(
            [sys.executable, __file__, "--worker", str(spec_path)],
            capture_output=True,
            text=True,
            timeout=WORKER_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # NOT `fail`: exceeding a wall clock is not evidence that the
        # decompilation is wrong, and recording it as a semantic verdict bakes
        # machine speed into the baseline (see `timeout` in the fixture README).
        return {"status": "timeout", "detail": f"worker exceeded {WORKER_TIMEOUT_S}s"}
    try:
        last_input = json.loads(progress_path.read_text())
        input_detail = f" on {last_input}"
    except (OSError, json.JSONDecodeError):
        input_detail = ""
    if r.returncode == -signal.SIGALRM:
        # See DECOMPILED_CALL_BUDGET_S: the original returned, ours did not.
        return {
            "status": "fail",
            "detail": f"decompiled function did not terminate within "
            f"{DECOMPILED_CALL_BUDGET_S}s on an input the original returned on"
            f"{input_detail}",
        }
    if r.returncode != 0:
        return {
            "status": "fail",
            "detail": f"worker crashed{input_detail} "
            f"(exit {r.returncode}; {r.stderr.strip()[-120:]})",
        }
    try:
        verdict = json.loads(r.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"status": "fail", "detail": "worker produced no verdict"}
    return {"status": "pass" if verdict["ok"] else "fail", "detail": verdict["detail"]}


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
    return 1 if "fail" in statuses else 0


def run(
    binary: str,
    source: str,
    fixture: str,
    seed: int,
    fuzz: int,
    only: set[str] | None = None,
    decompiled_by_va: dict[int, str] | None = None,
) -> dict:
    """`only` restricts which functions are executed and reported.

    Each function's fuzz vectors come from `_stable_seed(name, seed)` — derived
    from the function's own name, not from its position in the run — so a
    filtered run gives a filtered function exactly the verdict a full run would.
    A filter that changed the vectors would make `tools/dectest.py` a different
    measurement from the gate, which is the one thing it must not be.
    """
    # `<fixture>-<compiler>-<opt>.so` — the lane a per-lane skip is keyed on.
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
    if decompiled_by_va is None:
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
    }
    counts = {k: 0 for k in tags}
    for name, r in sorted(results.items()):
        counts[r["status"]] += 1
        print(f"{tags[r['status']]} {name}: {r['detail']}")
    print(
        f"\n{counts['pass']} pass, {counts['fail']} fail, {counts['structural']} structural, "
        f"{counts['missing']} missing, {counts['nocases']} no-cases, "
        f"{counts['timeout']} timed out"
    )
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
