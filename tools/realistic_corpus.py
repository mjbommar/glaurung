#!/usr/bin/env python3
"""Build realistic binaries — stripped, lying, self-decrypting, packed — from our own sources.

Every fixture in `tests/decompiler_fixtures/src/` is compiled as a translation
unit with no `main`, which is the right shape for the execution differential but
the wrong shape for whole-binary analysis: there is no entry point, no PLT, no
dynamic segment, and nothing for a packer to pack. This module links a chosen
spread of those fixtures against a *generated* driver to produce a real, running
executable, and then applies the post-processing a real-world binary has already
been through by the time an analyst sees it.

**Nothing here copies a system binary.** The corpus is our own C and our own
assembly, compiled here, and the ground-truth function addresses come from `nm`
on a symbol-bearing build of the same link — a set we constructed, never one the
analysis inferred.

Metadata variants — the code bytes are untouched
------------------------------------------------

``dwarf``
    ``-O2 -g``. Full ``.symtab`` and DWARF. The control.
``strip``
    ``strip --strip-all``. ``.symtab`` and DWARF gone, ``.dynsym`` and the
    section header table remain. This is what `O2strip` in the fixture harness
    already covers.
``sstrip``
    ``strip --strip-all`` then ``sstrip``: the section header table itself is
    removed (``e_shnum`` 30 -> 0). **The executable bytes are unchanged** — only
    metadata that a loader never reads is gone, so anything that regresses here
    regressed because it was reading section headers rather than program
    headers. Routine in real stripped malware.
``rename``
    ``objcopy --rename-section .text=.rsrc --rename-section .rodata=.text`` over
    the stripped build. Only ``.shstrtab`` changes: every program header, every
    byte of every ``PT_LOAD`` and the entry point are identical to ``strip``, so
    the loader cannot tell the two files apart. What moves here moved because it
    matched on a section *name*. Packers and hand-edited samples routinely ship
    a ``.text`` that is not the code.
``patchelf``
    ``patchelf --set-rpath --add-needed`` over the stripped build. patchelf
    cannot grow ``.dynstr`` where it sits, so it appends two fresh ``PT_LOAD``s
    and moves ``.dynstr``, ``.dynsym`` and ``PT_DYNAMIC`` into them — leaving the
    dynamic metadata at a *higher* address than the code, out of the order every
    linker produces. Reads that assume the usual layout, or that find the GOT by
    walking from a section rather than from ``PT_DYNAMIC``, come apart here.

Bytes-are-hostile variants — the code itself fights back
--------------------------------------------------------

``overlap``
    The same fixtures plus ``src/overlap_probe.S``, two hand-written functions
    whose jumps land inside instructions a linear sweep has already consumed.
    Stripped. ``objdump`` does not recover a single one of the real instructions
    in either function; the CPU runs them and gets the right answer. This is the
    only variant where the disagreement is about executable bytes rather than
    about metadata, and it is the classic anti-disassembly shape.
``encfn``
    Our own packer, at function granularity rather than whole-file. Each fixture
    object has its ``.text`` renamed to ``enctext`` before linking, so all the
    corpus functions land in one contiguous output section between the linker's
    ``__start_enctext``/``__stop_enctext``; the driver carries a constructor that
    ``mprotect``s that range writable, XORs it with an eight-byte key and puts it
    back to ``PROT_READ|PROT_EXEC``. After linking we XOR the same range *in the
    file*, so what sits on disk is ciphertext and what runs is the original code.
    It is not UPX and carries no UPX signature, so it exercises the generic path
    rather than a packer fingerprint. A ``glaurung_enc_flag`` byte in ``.data``
    (``0xA5`` plaintext, ``0x5A`` ciphertext) lets the *control* build — same
    link, symbols kept, bytes honest — skip the decryption and still run, which
    is what makes a symbol-derived ground truth available for this shape.
``bare``
    Honest ``-O2`` code, stripped, with the driver's address table left out of
    the link and ``.eh_frame``/``.eh_frame_hdr`` removed with ``objcopy``. It is
    the only lane where discovery has to come out of the instruction stream.
    Everywhere else the file still carries a list of every function: a symbol
    table, or the block of ``R_X86_64_RELATIVE`` relocations the driver's
    address table compiles to in a PIE, or one FDE per function in the unwind
    tables. Measured 2026-08-20, on this corpus, dropping those two took recall
    from 100% to 38.6% — so on every other lane the high number is mostly a
    metadata read, and this lane is the one that says what the sweep can do.
``encfn_bare``
    ``encfn`` with the same two removed: a stripped ELF whose executable section
    is ciphertext and whose surviving metadata is the entry point, the PLT and
    the dynamic symbols. What a real packed sample looks like. It recovers
    nothing, and that is the point of having it.

Whole-file packing
------------------

``upx``
    ``upx -9`` over the stripped build: one compressed blob plus a decompressor
    stub, and ``e_shnum`` is 0 here too.
``upxg``
    ``upx -9`` over the *unstripped* build, which keeps more of the original
    intact and separates "packed" from "stripped" as independent axes.

Ground truth and controls
-------------------------

``overlap``, ``encfn``, ``bare`` and ``encfn_bare`` are separate links, so their
functions are not at the same addresses as ``corpus.dwarf``'s. Each therefore has
its own **control**: an unstripped, honest-bytes build of that same link, from
which the ground-truth addresses are read with ``nm``. Controls are built and
required to execute like any other variant, but they are not measured as lanes of
their own — the `glaurung_enc_flag` byte exists so that the ``encfn`` controls
can be honest and still run.

Build products land in a gitignored cache; the committed artifacts are this
file, ``src/overlap_probe.S``, and the baseline the tests compare against.
Toolchain versions are recorded in the manifest because `upx`, `gcc` and
`objcopy` output move between releases, and a recall number measured under a
different packer is not comparable to one measured under this packer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
CORPUS_SRC = ROOT / "tests" / "realistic_corpus" / "src"
BUILD = ROOT / "tests" / "realistic_corpus" / "build"
MANIFEST = BUILD / "manifest.json"

#: The fixtures linked into the corpus. Chosen for spread rather than size: the
#: obfuscation family (145-150) is the part most likely to interact badly with
#: stripping, and the rest supply ordinary control flow, aggregates and string
#: handling so that a regression in the hostile lanes can be told apart from a
#: regression in everything.
SPEC: tuple[str, ...] = (
    "145_control_flow_flattening",
    "146_opaque_predicates",
    "148_dispatch_obfuscation",
    "150_obfuscation_composite",
    "03_loop_shapes",
    "04_switch_shapes",
    "02_integer_widths",
    "24_merge_sort",
    "20_graph_bfs",
    "07_packet_parser",
)

#: Variant name -> the post-processing applied after `-O2 -g` compilation.
VARIANTS: tuple[str, ...] = (
    "dwarf",
    "strip",
    "sstrip",
    "upx",
    "upxg",
    "rename",
    "patchelf",
    "overlap",
    "encfn",
    "bare",
    "encfn_bare",
)

#: Builds that exist to supply ground truth for a variant that is not a
#: post-processing of `corpus.dwarf`. They must execute like anything else — a
#: control that does not run cannot be trusted to describe the variant — but
#: they are not measured as lanes.
CONTROLS: tuple[str, ...] = (
    "overlap_control",
    "encfn_control",
    "bare_control",
    "encfn_bare_control",
)

#: Every file the corpus produces.
BUILDS: tuple[str, ...] = VARIANTS + CONTROLS

#: Variant -> the build whose symbol table defines its ground-truth addresses
#: and whose analysis is the precision reference.
CONTROL_OF: dict[str, str] = {
    "dwarf": "dwarf",
    "strip": "dwarf",
    "sstrip": "dwarf",
    "upx": "dwarf",
    "upxg": "dwarf",
    "rename": "dwarf",
    "patchelf": "dwarf",
    "overlap": "overlap_control",
    "encfn": "encfn_control",
    "bare": "bare_control",
    "encfn_bare": "encfn_bare_control",
}

#: Tools whose version changes the bytes we produce, so a recall number taken
#: under one version is not comparable to one taken under another.
VERSIONED_TOOLS: tuple[str, ...] = (
    "gcc",
    "strip",
    "sstrip",
    "upx",
    "objcopy",
    "patchelf",
)

#: The `encfn` stream cipher. Eight bytes, repeating — deliberately trivial, so
#: that the variant tests what a reader does with unintelligible code bytes
#: rather than how good it is at breaking ciphers.
ENC_KEY: bytes = bytes((0x5A, 0x13, 0xC7, 0x21, 0x8E, 0x44, 0xF0, 0x9B))

#: `glaurung_enc_flag` in `.data`: the control build carries PLAIN and skips
#: decryption, the shipped variant carries CIPHER and decrypts on load.
ENC_FLAG_PLAIN = 0xA5
ENC_FLAG_CIPHER = 0x5A

#: Hand-written assembly probes, and what they must return. `main` calls each
#: one and refuses to print the corpus marker unless the answer is right, so a
#: build whose anti-disassembly accidentally broke the code cannot be measured.
OVERLAP_PROBES: tuple[tuple[str, int, int], ...] = (
    ("glaurung_overlap_probe", 7, 52),
    ("glaurung_overlap_maze", 7, 18),
)

#: The `encfn` probe lives in the driver, marked into `enctext` so that it is
#: encrypted along with the fixtures. If the constructor did not decrypt, this
#: call executes ciphertext and the process dies.
ENC_PROBE: tuple[str, int, int] = ("glaurung_enc_probe", 7, 52)


class CorpusError(RuntimeError):
    """A corpus build step failed in a way the caller cannot work around."""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _checked(cmd: list[str], what: str) -> subprocess.CompletedProcess:
    """Run a build step, raising `CorpusError` with its own diagnostics on failure."""
    r = _run(cmd)
    if r.returncode != 0:
        raise CorpusError(f"{what}: {(r.stderr or r.stdout).strip()[-600:]}")
    return r


def missing_tools() -> list[str]:
    """Which of the tools this module needs are not on PATH."""
    return [t for t in VERSIONED_TOOLS if shutil.which(t) is None]


def tool_versions() -> dict[str, str]:
    """First version line of each tool, for the manifest."""
    out: dict[str, str] = {}
    for tool in VERSIONED_TOOLS:
        if shutil.which(tool) is None:
            out[tool] = "MISSING"
            continue
        r = _run([tool, "--version"])
        out[tool] = (
            (r.stdout or r.stderr).splitlines()[0].strip()
            if (r.stdout or r.stderr)
            else "?"
        )
    return out


# ---------------------------------------------------------------------------
# ELF surgery. Small and hand-rolled on purpose: the whole point of the hostile
# variants is that the section header table may be absent, renamed or lying, so
# the post-processing has to find its way around with program headers and a
# symbol table taken from the control.
# ---------------------------------------------------------------------------

_PT_LOAD = 1


def _pt_load_segments(path: Path) -> list[tuple[int, int, int]]:
    """The `(vaddr, filesz, offset)` of every PT_LOAD in a 64-bit little-endian ELF."""
    b = path.read_bytes()
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        raise CorpusError(f"{path.name}: not a 64-bit little-endian ELF")
    (e_phoff,) = struct.unpack_from("<Q", b, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", b, 0x36)
    segs: list[tuple[int, int, int]] = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        (p_type,) = struct.unpack_from("<I", b, o)
        p_offset, p_vaddr = struct.unpack_from("<QQ", b, o + 8)
        (p_filesz,) = struct.unpack_from("<Q", b, o + 0x20)
        if p_type == _PT_LOAD:
            segs.append((p_vaddr, p_filesz, p_offset))
    return segs


def _vaddr_to_offset(path: Path, vaddr: int) -> int:
    """File offset of a virtual address, via program headers only."""
    for seg_vaddr, filesz, offset in _pt_load_segments(path):
        if seg_vaddr <= vaddr < seg_vaddr + filesz:
            return offset + (vaddr - seg_vaddr)
    raise CorpusError(f"{path.name}: vaddr {vaddr:#x} is in no PT_LOAD")


def _symbol_addrs(path: Path, names: set[str]) -> dict[str, int]:
    """Addresses of named defined symbols, read from a build's symbol table."""
    r = _checked(["nm", "--defined-only", str(path)], f"nm {path.name}")
    out: dict[str, int] = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in names:
            out[parts[2]] = int(parts[0], 16)
    if absent := names - out.keys():
        raise CorpusError(f"{path.name}: symbols not found: {sorted(absent)}")
    return out


# ---------------------------------------------------------------------------
# Compilation and the generated driver.
# ---------------------------------------------------------------------------


def _compile_objects(build: Path, suffix: str = "") -> list[Path]:
    """Compile each spec fixture to an object file, failing loudly on the first error."""
    objs: list[Path] = []
    for stem in SPEC:
        src = SRC / f"{stem}.c"
        if not src.exists():
            raise CorpusError(f"spec names {stem} but {src} does not exist")
        obj = build / f"{stem}{suffix}.o"
        _checked(
            ["gcc", "-O2", "-g", "-c", "-o", str(obj), str(src)], f"compiling {stem}"
        )
        objs.append(obj)
    return objs


def _global_text_symbols(objs: list[Path]) -> list[str]:
    """The `T` symbols across the objects — our ground truth, sorted for determinism."""
    r = _checked(
        ["nm", "--defined-only", *[str(o) for o in objs]], "nm on the spec objects"
    )
    names = {
        parts[2]
        for line in r.stdout.splitlines()
        if len(parts := line.split()) == 3 and parts[1] == "T"
    }
    return sorted(names)


_ENC_PREAMBLE = f"""
/* --- our own packer, at function granularity ----------------------------- */
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

extern char __start_enctext[], __stop_enctext[];

/* 0x{ENC_FLAG_PLAIN:02X} in the control build (bytes are honest, skip the
 * constructor); the post-processing step flips it to 0x{ENC_FLAG_CIPHER:02X}
 * in the file it has just encrypted. */
volatile unsigned char glaurung_enc_flag = 0x{ENC_FLAG_PLAIN:02X};

static const unsigned char GLAURUNG_ENC_KEY[{len(ENC_KEY)}] = {{
    {", ".join(f"0x{b:02X}" for b in ENC_KEY)}
}};

__attribute__((constructor)) static void glaurung_enc_decrypt(void) {{
    if (glaurung_enc_flag != 0x{ENC_FLAG_CIPHER:02X})
        return;
    long page = sysconf(_SC_PAGESIZE);
    char *lo = (char *)((uintptr_t)__start_enctext & ~(uintptr_t)(page - 1));
    size_t span = (size_t)(__stop_enctext - lo);
    if (mprotect(lo, span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        _exit(3);
    size_t n = (size_t)(__stop_enctext - __start_enctext);
    for (size_t i = 0; i < n; i++)
        __start_enctext[i] ^= GLAURUNG_ENC_KEY[i % {len(ENC_KEY)}];
    if (mprotect(lo, span, PROT_READ | PROT_EXEC) != 0)
        _exit(4);
}}

/* Encrypted alongside the fixtures: calling it proves the constructor ran. */
__attribute__((section("enctext"), noinline))
int {ENC_PROBE[0]}(int x) {{ return x * 7 + 3; }}
"""


def _driver_source(
    symbols: list[str],
    probes: tuple[tuple[str, int, int], ...] = (),
    enc: bool = False,
    table: bool = True,
) -> str:
    """A `main` for the corpus link.

    With `table`, `main` takes the address of every corpus function. Addresses
    only — never a call — so the declarations do not have to match the real
    prototypes. The exception is `probes`, which `main` calls and checks,
    because a hostile variant that silently computes the wrong answer must not
    be measurable.

    Without `table` there are no function-pointer initialisers at all. Nothing
    is lost: the fixture objects are named on the link line, not pulled out of
    an archive, so the linker keeps them whether or not anything refers to them.
    What goes away is the block of `R_X86_64_RELATIVE` relocations the table
    compiles to in a PIE — one per corpus function, each pointing at a function
    entry. That block hands a reader the whole ground-truth set without it
    decoding a single instruction, which makes the table-bearing builds unable
    to say anything about what the *code* analysis recovers.

    Args:
        symbols: Every corpus function, by name.
        probes: `(name, argument, expected)` triples that `main` must call.
        enc: Emit the `enctext` decryptor and define the encrypted probe here.
        table: Emit the address table.

    Returns:
        The C source of the driver.
    """
    probe_names = {p[0] for p in probes}
    externs = (
        "\n".join(f"extern void {s}(void);" for s in symbols if s not in probe_names)
        if table
        else ""
    )
    probe_decls = "\n".join(f"extern int {n}(int);" for n, _a, _e in probes if not enc)
    checks = "\n".join(
        f'    if ({n}({a}) != {e}) {{ printf("PROBE FAIL {n}\\n"); return 2; }}'
        for n, a, e in probes
    )
    if table:
        entries = "\n".join(f"    (void *)&{s}," for s in symbols)
        body = f"""static void *const table[] = {{
{entries}
}};

int main(int argc, char **argv) {{
    unsigned long acc = 0;
{checks}
    for (unsigned i = 0; i < sizeof(table) / sizeof(table[0]); i++)
        acc += (unsigned long)table[i];
    printf("glaurung-corpus %u entries acc=%lx argc=%d\\n",
           (unsigned)(sizeof(table) / sizeof(table[0])), acc, argc);
    return 0;
}}"""
    else:
        body = f"""int main(int argc, char **argv) {{
{checks}
    printf("glaurung-corpus 0 entries acc=0 argc=%d\\n", argc);
    return 0;
}}"""
    return f"""/* GENERATED by tools/realistic_corpus.py — do not edit. */
#include <stdio.h>
{_ENC_PREAMBLE if enc else ""}
{externs}
{probe_decls}

{body}
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runs(path: Path) -> bool:
    """A variant that does not execute is not evidence about anything."""
    try:
        r = _run([str(path)], timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and "glaurung-corpus" in r.stdout


# ---------------------------------------------------------------------------
# The adversarial variants.
# ---------------------------------------------------------------------------


def _build_rename(build: Path, stripped: Path) -> Path:
    """Give the real code a false name and hand `.text` to the read-only data.

    `objcopy --rename-section` rewrites nothing but `.shstrtab`: the section
    addresses, the program headers and the entry point come out byte for byte
    the same, which is what makes this an isolation experiment rather than
    simply a harder binary.
    """
    out = build / "corpus.rename"
    _checked(
        [
            "objcopy",
            "--rename-section",
            ".text=.rsrc",
            "--rename-section",
            ".rodata=.text",
            str(stripped),
            str(out),
        ],
        "renaming sections",
    )
    out.chmod(0o755)
    return out


def _build_patchelf(build: Path, stripped: Path) -> Path:
    """Rewrite the dynamic section out of its usual place.

    patchelf cannot grow `.dynstr` where it sits, so it appends new `PT_LOAD`s
    and relocates `.dynstr`, `.dynsym` and `PT_DYNAMIC` above the code. The
    result is a perfectly loadable file in which the dynamic metadata sits at a
    higher address than the code, in an order no linker produces.
    """
    out = build / "corpus.patchelf"
    shutil.copy2(stripped, out)
    _checked(
        [
            "patchelf",
            "--set-rpath",
            "$ORIGIN/../lib:/opt/glaurung/lib",
            "--add-needed",
            "libm.so.6",
            str(out),
        ],
        "patchelf rewriting the dynamic section",
    )
    return out


def _build_overlap(
    build: Path, objs: list[Path], symbols: list[str]
) -> tuple[Path, Path]:
    """Link the corpus with two anti-disassembly functions, then strip it.

    Returns:
        `(control, variant)` — the unstripped build the ground truth is read
        from, and the stripped build that gets measured.
    """
    asm = CORPUS_SRC / "overlap_probe.S"
    if not asm.exists():
        raise CorpusError(f"{asm} is missing")
    obj = build / "overlap_probe.o"
    _checked(
        ["gcc", "-O2", "-c", "-o", str(obj), str(asm)], "assembling overlap_probe.S"
    )

    names = sorted(set(symbols) | {p[0] for p in OVERLAP_PROBES})
    driver = build / "driver_overlap.c"
    driver.write_text(_driver_source(names, probes=OVERLAP_PROBES))

    control = build / "corpus.overlap_control"
    _checked(
        [
            "gcc",
            "-O2",
            "-g",
            "-o",
            str(control),
            str(driver),
            *map(str, objs),
            str(obj),
        ],
        "linking the overlap corpus",
    )
    variant = build / "corpus.overlap"
    shutil.copy2(control, variant)
    _checked(["strip", "--strip-all", str(variant)], "stripping the overlap corpus")
    return control, variant


def _enc_objects(build: Path) -> list[Path]:
    """The fixture objects with `.text` renamed to `enctext`, ready to encrypt.

    `enctext` is a valid C identifier, so the linker brackets the merged output
    section with `__start_enctext`/`__stop_enctext` for free — which is how the
    decryptor knows what to decrypt without a linker script.
    """
    objs = _compile_objects(build, suffix=".enc")
    for obj in objs:
        _checked(
            ["objcopy", "--rename-section", ".text=enctext", str(obj)],
            f"renaming .text in {obj.name}",
        )
    return objs


def _encrypt_in_place(variant: Path, control: Path) -> None:
    """XOR the `enctext` range of `variant` and flip its plaintext flag.

    The bounds come from `control`'s symbol table and the file offsets from
    `variant`'s own program headers, so this works after the section headers
    have been stripped or edited.
    """
    marks = _symbol_addrs(
        control, {"__start_enctext", "__stop_enctext", "glaurung_enc_flag"}
    )
    lo, hi = marks["__start_enctext"], marks["__stop_enctext"]
    if hi <= lo:
        raise CorpusError(f"empty enctext region [{lo:#x}, {hi:#x})")
    data = bytearray(variant.read_bytes())
    off = _vaddr_to_offset(variant, lo)
    for i in range(hi - lo):
        data[off + i] ^= ENC_KEY[i % len(ENC_KEY)]
    data[_vaddr_to_offset(variant, marks["glaurung_enc_flag"])] = ENC_FLAG_CIPHER
    variant.write_bytes(bytes(data))
    variant.chmod(0o755)


def _drop_unwind_tables(path: Path) -> None:
    """Remove `.eh_frame` and `.eh_frame_hdr`.

    Unwind tables enumerate one FDE per function, so they hand a reader every
    function's start address whatever the code bytes say. Compiled C on Linux
    almost always carries them; hand-written assembly and repacked samples
    frequently do not, and a measurement that leaves them in place cannot
    distinguish "recovered the function" from "read the list".
    """
    _checked(
        [
            "objcopy",
            "--remove-section",
            ".eh_frame",
            "--remove-section",
            ".eh_frame_hdr",
            str(path),
        ],
        f"removing unwind tables from {path.name}",
    )
    path.chmod(0o755)


def _build_encfn(build: Path, symbols: list[str]) -> tuple[Path, Path]:
    """Link the corpus into an `enctext` section, then encrypt that section in the file.

    The driver's constructor decrypts the range at load; this performs the
    matching encryption on disk.

    Returns:
        `(control, variant)` — the plaintext, symbol-bearing build the ground
        truth is read from, and the encrypted stripped build that gets measured.
    """
    objs = _enc_objects(build)
    driver = build / "driver_encfn.c"
    driver.write_text(_driver_source(symbols, probes=(ENC_PROBE,), enc=True))

    control = build / "corpus.encfn_control"
    _checked(
        ["gcc", "-O2", "-g", "-o", str(control), str(driver), *map(str, objs)],
        "linking the encfn corpus",
    )

    variant = build / "corpus.encfn"
    shutil.copy2(control, variant)
    _checked(["strip", "--strip-all", str(variant)], "stripping the encfn corpus")
    _encrypt_in_place(variant, control)
    return control, variant


def _build_bare(build: Path, objs: list[Path], symbols: list[str]) -> tuple[Path, Path]:
    """Honest bytes with nothing to read them off: no address table, no unwind tables.

    This is the control for `encfn_bare`, and it is the only lane in the corpus
    where discovery has to come out of the instruction stream. Every other lane
    has either a symbol table, a relocation block naming every function, or an
    FDE per function — so a high recall there says nothing about the sweep.
    """
    driver = build / "driver_bare.c"
    driver.write_text(_driver_source(symbols, table=False))

    control = build / "corpus.bare_control"
    _checked(
        ["gcc", "-O2", "-g", "-o", str(control), str(driver), *map(str, objs)],
        "linking the bare corpus",
    )
    variant = build / "corpus.bare"
    shutil.copy2(control, variant)
    _checked(["strip", "--strip-all", str(variant)], "stripping the bare corpus")
    _drop_unwind_tables(variant)
    return control, variant


def _build_encfn_bare(build: Path, symbols: list[str]) -> tuple[Path, Path]:
    """The packer with nothing left to read the function list off.

    `encfn` with the address table and the unwind tables removed as well. What
    remains on disk is a stripped ELF whose executable section is ciphertext and
    whose only surviving metadata is the entry point, the PLT and the dynamic
    symbols — which is what a real packed sample looks like.
    """
    objs = _enc_objects(build)
    driver = build / "driver_encfn_bare.c"
    driver.write_text(
        _driver_source(symbols, probes=(ENC_PROBE,), enc=True, table=False)
    )

    control = build / "corpus.encfn_bare_control"
    _checked(
        ["gcc", "-O2", "-g", "-o", str(control), str(driver), *map(str, objs)],
        "linking the encfn_bare corpus",
    )
    variant = build / "corpus.encfn_bare"
    shutil.copy2(control, variant)
    _checked(["strip", "--strip-all", str(variant)], "stripping the encfn_bare corpus")
    _drop_unwind_tables(variant)
    _encrypt_in_place(variant, control)
    return control, variant


# ---------------------------------------------------------------------------
# Orchestration.
# ---------------------------------------------------------------------------


def build(force: bool = False) -> dict:
    """Build every variant and return the manifest.

    Args:
        force: Rebuild even if a manifest already exists.

    Returns:
        The manifest: ground-truth symbols and their addresses in each control,
        per-build sha256/size/runs, and the toolchain versions the bytes depend
        on.
    """
    if missing := missing_tools():
        raise CorpusError(
            f"missing required tools: {', '.join(missing)}. "
            "Install with: sudo apt-get install -y upx-ucl elfkickers patchelf"
        )
    if MANIFEST.exists() and not force:
        cached = json.loads(MANIFEST.read_text())
        if cached.get("schema") == 2:
            return cached

    BUILD.mkdir(parents=True, exist_ok=True)
    objs = _compile_objects(BUILD)
    symbols = _global_text_symbols(objs)
    if not symbols:
        raise CorpusError("no global text symbols across the spec objects")

    driver = BUILD / "driver.c"
    driver.write_text(_driver_source(symbols))

    dwarf = BUILD / "corpus.dwarf"
    _checked(
        ["gcc", "-O2", "-g", "-o", str(dwarf), str(driver), *map(str, objs)],
        "linking corpus",
    )

    stripped = BUILD / "corpus.strip"
    shutil.copy2(dwarf, stripped)
    _checked(["strip", "--strip-all", str(stripped)], "stripping corpus")

    sstripped = BUILD / "corpus.sstrip"
    shutil.copy2(stripped, sstripped)
    _checked(["sstrip", str(sstripped)], "sstripping corpus")

    for name, base in (("upx", stripped), ("upxg", dwarf)):
        packed = BUILD / f"corpus.{name}"
        shutil.copy2(base, packed)
        _checked(["upx", "-9", "-q", "-f", str(packed)], f"packing {name}")

    _build_rename(BUILD, stripped)
    _build_patchelf(BUILD, stripped)
    overlap_control, _ = _build_overlap(BUILD, objs, symbols)
    encfn_control, _ = _build_encfn(BUILD, symbols)
    bare_control, _ = _build_bare(BUILD, objs, symbols)
    encfn_bare_control, _ = _build_encfn_bare(BUILD, symbols)

    manifest = {
        "schema": 2,
        "spec": list(SPEC),
        "ground_truth": symbols,
        "control_of": CONTROL_OF,
        "truth_addrs": {
            "dwarf": _symbol_addrs(dwarf, set(symbols)),
            "overlap_control": _symbol_addrs(
                overlap_control, set(symbols) | {p[0] for p in OVERLAP_PROBES}
            ),
            "encfn_control": _symbol_addrs(encfn_control, set(symbols)),
            "bare_control": _symbol_addrs(bare_control, set(symbols)),
            "encfn_bare_control": _symbol_addrs(encfn_bare_control, set(symbols)),
        },
        "toolchain": tool_versions(),
        "variants": {},
    }
    manifest["truth_addrs"] = {
        k: dict(sorted(v.items())) for k, v in manifest["truth_addrs"].items()
    }
    for v in BUILDS:
        p = BUILD / f"corpus.{v}"
        manifest["variants"][v] = {
            "sha256": _sha256(p),
            "size": p.stat().st_size,
            "runs": _runs(p),
        }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def variant_path(name: str) -> Path:
    """Path to one built variant or control, building the corpus first if needed."""
    if name not in BUILDS:
        raise CorpusError(f"unknown variant {name!r}; known: {', '.join(BUILDS)}")
    build()
    return BUILD / f"corpus.{name}"


def truth_addresses(variant: str) -> set[int]:
    """The ground-truth function addresses for one variant.

    Read from the symbol table of that variant's control, so it is a set we
    constructed rather than one the analysis inferred. For `upx` and `upxg` these
    are the addresses of the *unpacked* program, which nothing static can be
    expected to hit — that is the finding, not a defect in the measurement.
    """
    manifest = build()
    return set(manifest["truth_addrs"][manifest["control_of"][variant]].values())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--force", action="store_true", help="rebuild even if cached")
    ap.add_argument("--json", action="store_true", help="print the manifest as JSON")
    args = ap.parse_args(argv)

    if missing := missing_tools():
        print(f"missing tools: {', '.join(missing)}", file=sys.stderr)
        print(
            "install: sudo apt-get install -y upx-ucl elfkickers patchelf",
            file=sys.stderr,
        )
        return 1

    m = build(force=args.force)
    if args.json:
        print(json.dumps(m, indent=2))
        return 0

    print(
        f"corpus: {len(m['spec'])} fixtures, {len(m['ground_truth'])} ground-truth functions"
    )
    for tool, ver in m["toolchain"].items():
        print(f"  {tool:10s} {ver}")
    print(f"  {'variant':<16} {'size':>9}  {'runs':<5} sha256")
    for v, info in m["variants"].items():
        ok = "YES" if info["runs"] else "NO"
        print(f"  {v:<16} {info['size']:>9}  {ok:<5} {info['sha256'][:16]}")
    if not all(i["runs"] for i in m["variants"].values()):
        print(
            "\nA variant does not execute — it is not evidence about anything.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
