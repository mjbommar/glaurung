"""Build a WARP exact-match signature library from linked PEs plus their PDBs.

Why WARP and not FLIRT, for Windows
-----------------------------------

``build_flirt_library`` prefers an ``ar`` archive of unlinked ``.o`` members,
because a relocatable object carries the relocation table that says which
bytes the linker will overwrite, and masking exactly those bytes is what makes
a prologue signature survive a relink. **Microsoft ships no such input.** There
is no ``.lib`` or ``.obj`` for ``ntdll`` or ``ntoskrnl`` anywhere -- not in the
SDK, not in the WDK, not in the symbol server, and not in the corpus this
module was written against. What Microsoft does publish is the linked image and
a PDB full of names for it.

WARP is the scheme that takes exactly that pair as input. Its GUID is a UUIDv5
over *relocation-masked* instruction bytes, and the masking is derived by
decoding the image rather than by reading a relocation table, so a linked PE is
a first-class input rather than a contaminated one. See
``docs/reference/function-identity-warp.md``.

What that buys and what it does not: a WARP GUID is invariant to address and
relocation and to **nothing else**. It will not carry a name across an
optimisation-level change, a compiler change, or a source change. For Windows
system code that is a much better bet than it sounds, because Microsoft rebuilds
the same source with the same toolchain every month: most of a DLL is
byte-identical between two Patch Tuesdays, and the measured cross-build recall
tables in ``docs/reference/function-signature-libraries.md`` are what that is
worth in practice.

The key
-------

``(name, version, variant, arch, platform)``, as
``docs/reference/function-signature-libraries.md`` requires and as
``siglib.get_or_create_siglib`` stores:

``name``
    The module's file name, lowercased -- ``ntdll.dll``, ``tcpip.sys``.
``version``
    The ``VS_VERSIONINFO`` ``FileVersion``, e.g. ``10.0.26100.8457``. This is
    the field Microsoft actually increments per servicing build, and it is the
    string an analyst reads off the file's properties page. Falls back to the
    ``CodeView`` ``GUID+age`` key when a module carries no version resource,
    which is rarer than it sounds but does happen for a few kernel components.
``variant``
    ``msvc-<major>.<minor>-b<build>`` from the PE optional header's linker
    version and the Rich header's toolset build id (see
    :func:`rich_toolset_build` and :attr:`PeFacts.variant`), or
    ``link-<major>.<minor>`` for an image with no Rich header, which is not an
    MSVC link.
    The variant is part of the identity, not metadata about it: two builds of
    one source by two toolsets are two libraries sharing a name.
``arch``
    ``x86_64`` or ``x86``, from the COFF machine field. WARP implements those
    two only.
``platform``
    ``windows``.

ICF, and why an ambiguous entry is kept whole
---------------------------------------------

The MSVC linker folds identical functions (``/OPT:ICF``), and Windows system
DLLs are full of the result: dozens of one-line accessors and thunks collapse
onto a single address, and the PDB then names that address once while the
*source* had many names for it. Even without folding, WARP deliberately never
prunes colliding GUIDs.

So this builder emits **one entry per ``(guid, name)`` pair**, exactly the shape
``siglib_function``'s ``UNIQUE (siglib_id, scheme, identity, name)`` stores, and
marks every entry whose GUID carries more than one name ``ambiguous``. It never
picks one. A WARP hit is written at a provenance rank that outranks ``auto``, so
a coin flip there does not degrade an answer -- it outranks the correct one.
``siglib.match_warp_library`` enforces the same rule at match time.

``occurrences`` counts how many discovered functions across the source PEs
produced that ``(guid, name)`` pair -- Lumina's "popularity", the cheapest
false-positive signal there is.

Usage
-----

::

    # One module, keyed from its own version resource and Rich header:
    python -m glaurung.tools.build_warp_library \\
        --pdb-cache /nas4/data/symbol-cache/microsoft \\
        --output-dir ~/.cache/glaurung/system-libs/warp \\
        /nas4/.../windows-11-x64/ntdll.dll

    # A whole build directory, one library per module that resolves a PDB:
    python -m glaurung.tools.build_warp_library \\
        --pdb-cache /nas4/data/symbol-cache/microsoft \\
        --output-dir ~/.cache/glaurung/system-libs/warp \\
        --index --skip-without-pdb \\
        /nas4/.../windows-11-x64

The output files hold GUIDs, names and sizes. They contain **no Microsoft
bytes**: not a prologue, not a mask, not a pattern -- which is the property
that makes a FLIRT-family signature set redistributable, and the reason this
builder records a masked-byte count but never masked bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import glaurung as g

from glaurung.llm.kb.siglib import base_name_of

#: The on-disk shape of a library file produced here.
SCHEMA_VERSION = "1"

#: What the ``identity`` of every entry is. Tracks
#: ``glaurung.analysis.warp_scheme()`` / ``siglib.WARP_FUNCTION_GUID_V1``; a
#: test asserts the three agree, because two spellings would split the table.
WARP_SCHEME = "warp-function-guid-v1"

#: ``library.platform`` for everything this builder produces.
PLATFORM = "windows"

#: Which entries carry their WARP constraints into the file.
#:
#: Constraints are the input to a future ``warp-constraint`` disambiguation
#: level that no matcher implements yet (see ``function-signature-libraries.md``
#: "Not done here"), and a large module emits ten or more per function -- on
#: ``ntoskrnl`` that is an order of magnitude more JSON than the entries
#: themselves. ``ambiguous`` is the honest default: a constraint can only ever
#: break a tie, and only ambiguous entries have a tie to break.
CONSTRAINT_MODES = ("none", "ambiguous", "all")

#: Smallest function a match is trusted from, in unmasked image bytes.
#:
#: **Measured, not chosen**, over 48 MinGW-built PEs in
#: ``samples/binaries/platforms/windows/`` (6,368 functions) against a union
#: library of 226,346 Windows GUIDs -- a corpus with which they share no code
#: at all, so every hit is a false positive:
#:
#: === ===================  ==============================
#: min  false positives      recall cost (ntoskrnl, PT pair)
#: === ===================  ==============================
#:   0  2,396                 --
#:   8    130                 0.905 -> 0.900
#:  16      4                 0.905 -> 0.890
#:  48      0                 0.905 -> 0.797
#: === ===================  ==============================
#:
#: 2,070 of the 2,396 hits at no floor are **six bytes**: `jmp qword
#: [rip+disp32]`, the import thunk, whose displacement WARP masks -- so every
#: import thunk in every PE ever linked carries the same GUID. That is not a
#: collision in the hash, it is the scheme correctly reporting that six masked
#: bytes are six masked bytes.
#:
#: 16 is where the curve turns: it removes 99.8% of the false positives for
#: about one point of recall, and 48 buys the last four for eleven. The number
#: landing on FLIRT's own measured ``min_fixed_bytes`` floor is a coincidence
#: of two different mechanisms reaching the same place.
MIN_EVIDENCE_BYTES = 16

_MACHINE_TO_ARCH = {
    0x014C: "x86",
    0x8664: "x86_64",
    0xAA64: "aarch64",
    0x01C4: "armv7",
}


# ---------------------------------------------------------------------------
# PE header reading
#
# Pure `struct`, for the same reason `pdb_fetch.read_codeview` is: this needs
# three small facts (machine, linker version, version resource) that the native
# side does not expose to Python, and pulling a PE library in to get them would
# be a dependency for sixty lines of parsing.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PeFacts:
    """The header facts that key a library."""

    arch: str
    linker_version: str
    rich_build: Optional[int]
    file_version: Optional[str]

    @property
    def variant(self) -> str:
        """``msvc-<linker major>.<minor>-b<toolset build>``.

        The ``msvc-`` prefix is claimed only when the Rich header is there to
        justify it: the Rich header is written by the Microsoft linker and by
        nothing else, so its absence means the image was linked by some other
        toolchain (GNU ``ld`` through MinGW, LLVM ``lld``) whose optional-header
        linker version means something different. Those get a bare
        ``link-<major>.<minor>``, which does not assert a compiler it cannot
        see.
        """
        if self.rich_build is None:
            return f"link-{self.linker_version}"
        return f"msvc-{self.linker_version}-b{self.rich_build}"


def _sections(data: bytes, coff: int, num_sections: int, opt_size: int):
    table = coff + 20 + opt_size
    out = []
    for i in range(num_sections):
        off = table + i * 40
        if off + 40 > len(data):
            break
        vsz, va = struct.unpack_from("<II", data, off + 8)
        rsz, praw = struct.unpack_from("<II", data, off + 16)
        out.append((va, vsz, praw, rsz))
    return out


def _rva_to_off(rva: int, sections) -> Optional[int]:
    for va, vsz, praw, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return praw + (rva - va)
    return None


def rich_toolset_build(data: bytes) -> Optional[int]:
    """The MSVC toolset build id recorded in the PE's Rich header.

    The Rich header is a XOR-obfuscated list of ``(product id, build id,
    count)`` triples the linker writes between the DOS stub and the PE
    signature: one triple per tool that contributed objects to the link. The
    build id of the *toolset* is the one that appears in the most triples --
    the compiler, the assembler, the CVTRES and the linker of a given Visual
    Studio release all stamp the same number, while a stale object linked in
    from an older build contributes one lonely triple with an older one.

    Returns ``None`` when the header is absent (some signed system images have
    had it stripped) or malformed.
    """
    dos = data[:0x1000]
    marker = dos.find(b"Rich")
    if marker < 0 or marker + 8 > len(dos):
        return None
    key = struct.unpack_from("<I", dos, marker + 4)[0]
    start = None
    for off in range(marker - 4, 0x3C, -4):
        if struct.unpack_from("<I", dos, off)[0] ^ key == 0x536E6144:  # "DanS"
            start = off
            break
    if start is None:
        return None
    values = [
        struct.unpack_from("<I", dos, off)[0] ^ key
        for off in range(start + 16, marker, 4)
    ]
    builds: Counter[int] = Counter()
    for i in range(0, len(values) - 1, 2):
        build = values[i] & 0xFFFF
        if build:
            builds[build] += 1
    if not builds:
        return None
    # Most triples wins; a tie goes to the larger id, which is the newer tool.
    return max(builds.items(), key=lambda kv: (kv[1], kv[0]))[0]


def _version_resource(data: bytes, coff: int, opt_size: int, sections) -> Optional[str]:
    """``FileVersion`` from ``VS_FIXEDFILEINFO``, as ``a.b.c.d``.

    Read off the fixed-size struct rather than the ``StringFileInfo`` block:
    the string table is localised and its ``FileVersion`` is free-form (some
    modules write ``10.0.26100.8457 (WinBuild.160101.0800)``), while
    ``VS_FIXEDFILEINFO`` is four ``u16``s in a defined order.
    """
    opt = coff + 20
    if opt + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt)[0]
    dd_off = opt + (112 if magic == 0x20B else 96)
    resource_index = 2
    entry = dd_off + resource_index * 8
    if entry + 8 > len(data):
        return None
    res_rva, res_size = struct.unpack_from("<II", data, entry)
    if not res_rva or not res_size:
        return None
    base = _rva_to_off(res_rva, sections)
    if base is None:
        return None

    def walk(offset: int, want: Optional[int]) -> Optional[int]:
        """Return the offset of the first matching child directory/entry."""
        if offset + 16 > len(data):
            return None
        named, ids = struct.unpack_from("<HH", data, offset + 12)
        for i in range(named + ids):
            e = offset + 16 + i * 8
            if e + 8 > len(data):
                return None
            name, child = struct.unpack_from("<II", data, e)
            if want is None:
                return child
            # Named entries sort before ID entries; only IDs can equal `want`.
            if name & 0x80000000 or name != want:
                continue
            return child
        return None

    # RT_VERSION (16) -> first name -> first language -> data entry.
    type_dir = walk(base, 16)
    if type_dir is None or not (type_dir & 0x80000000):
        return None
    name_dir = walk(base + (type_dir & 0x7FFFFFFF), None)
    if name_dir is None or not (name_dir & 0x80000000):
        return None
    leaf = walk(base + (name_dir & 0x7FFFFFFF), None)
    if leaf is None or leaf & 0x80000000:
        return None
    data_entry = base + leaf
    if data_entry + 8 > len(data):
        return None
    blob_rva, blob_size = struct.unpack_from("<II", data, data_entry)
    blob_off = _rva_to_off(blob_rva, sections)
    if blob_off is None:
        return None
    blob = data[blob_off : blob_off + min(blob_size, 0x10000)]
    sig = blob.find(struct.pack("<I", 0xFEEF04BD))
    if sig < 0 or sig + 20 > len(blob):
        return None
    ms, ls = struct.unpack_from("<II", blob, sig + 8)
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def pe_facts(path: Path | str) -> Optional[PeFacts]:
    """Read the header facts that key a library, or ``None`` for a non-PE."""
    data = Path(path).read_bytes()
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return None
    coff = e_lfanew + 4
    machine, num_sections = struct.unpack_from("<HH", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    sections = _sections(data, coff, num_sections, opt_size)
    return PeFacts(
        arch=_MACHINE_TO_ARCH.get(machine, f"machine-{machine:#06x}"),
        linker_version=f"{data[opt + 2]}.{data[opt + 3]}",
        rich_build=rich_toolset_build(data),
        file_version=_version_resource(data, coff, opt_size, sections),
    )


def library_key(path: Path | str, facts: Optional[PeFacts] = None) -> Dict[str, str]:
    """The ``(name, version, variant, arch, platform)`` key for one module."""
    path = Path(path)
    facts = facts or pe_facts(path)
    if facts is None:
        raise ValueError(f"not a PE: {path}")
    version = facts.file_version
    if version is None:
        cv = _codeview_key(path)
        version = f"cv-{cv}" if cv else "unknown"
    return {
        "name": path.name.lower(),
        "version": version,
        "variant": facts.variant,
        "arch": facts.arch,
        "platform": PLATFORM,
    }


def _codeview_key(path: Path) -> Optional[str]:
    from glaurung.pdb_fetch import read_codeview

    try:
        cv = read_codeview(path)
    except (OSError, struct.error, ValueError):
        return None
    return cv.guid_age_key if cv else None


def resolve_pdb(path: Path, pdb_cache: Path) -> Optional[Path]:
    """The cached PDB this PE's CodeView record points at, if present.

    Mirrors ``CodeViewRsds::resolve_pdb_path`` (``src/formats/pe/directories/
    debug.rs``): symbol-server layout ``<cache>/<pdb>/<GUID+AGE>/<pdb>`` first,
    then the flat layout, then the lowercased name. Reported separately from
    ``g.symbols.pdb_symbol_map`` so a run can say *why* a module produced no
    names -- no CodeView record, cache miss, or a PDB with no publics are three
    different problems and the map returns an empty dict for all three.
    """
    from glaurung.pdb_fetch import read_codeview

    try:
        cv = read_codeview(path)
    except (OSError, struct.error, ValueError):
        return None
    if cv is None:
        return None
    for name in (cv.pdb_name, cv.pdb_name.lower()):
        candidate = pdb_cache / name / cv.guid_age_key / name
        if candidate.is_file():
            return candidate
        flat = pdb_cache / name
        if flat.is_file():
            return flat
    return None


# ---------------------------------------------------------------------------
# Harvesting
# ---------------------------------------------------------------------------


@dataclass
class SourceSummary:
    """What one input PE contributed, and how much of it was named."""

    path: str
    sha256: str
    file_version: Optional[str]
    pdb_path: Optional[str]
    functions: int = 0
    named: int = 0
    pdb_named: int = 0

    @property
    def pdb_resolved_fraction(self) -> float:
        return (self.pdb_named / self.functions) if self.functions else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "file_version": self.file_version,
            "pdb_path": self.pdb_path,
            "functions": self.functions,
            "named": self.named,
            "pdb_named": self.pdb_named,
            "pdb_resolved_fraction": round(self.pdb_resolved_fraction, 6),
        }


@dataclass
class _Entry:
    guid: str
    name: str
    block_count: int
    byte_len: int
    occurrences: int = 1
    constraints: List[Dict[str, Any]] = field(default_factory=list)


def _is_placeholder(name: str) -> bool:
    """``sub_<hex>`` is discovery saying it has no name, not a name.

    Ingesting one would be worse than useless: it is address-derived, so it
    encodes the very layout WARP masks out, and it would match every unnamed
    function whose GUID happened to agree while claiming library provenance.
    """
    return not name or name.startswith("sub_")


def harvest_pe(
    pe_path: Path | str,
    *,
    pdb_cache: Optional[Path | str],
    constraints: str = "ambiguous",
) -> Tuple[List[_Entry], SourceSummary]:
    """WARP GUIDs for one PE, named from its PDB where the cache has one.

    Names come from the PDB's public symbols by entry VA
    (``g.symbols.pdb_symbol_map``, the same lookup the decompile pipeline
    performs), falling back to whatever discovery knew -- exports, mostly --
    and skipping ``sub_*`` placeholders entirely.

    Returns one ``_Entry`` per named function, *before* deduplication: two
    functions that folded onto the same GUID both appear, which is what lets
    :func:`build_library` see the collision.
    """
    pe_path = Path(pe_path)
    data = pe_path.read_bytes()
    facts = pe_facts(pe_path)
    cache = Path(pdb_cache) if pdb_cache else None
    pdb_path = resolve_pdb(pe_path, cache) if cache is not None else None
    symbols: Dict[int, str] = {}
    if cache is not None and pdb_path is not None:
        symbols = g.symbols.pdb_symbol_map(str(pe_path), str(cache))

    summary = SourceSummary(
        path=str(pe_path),
        sha256=hashlib.sha256(data).hexdigest(),
        file_version=facts.file_version if facts else None,
        pdb_path=str(pdb_path) if pdb_path else None,
    )

    out: List[_Entry] = []
    for fn in g.analysis.warp_function_guids_path(str(pe_path)):
        summary.functions += 1
        pdb_name = symbols.get(int(fn.entry_va))
        name = pdb_name or fn.name
        if pdb_name:
            summary.pdb_named += 1
        if _is_placeholder(name):
            continue
        summary.named += 1
        out.append(
            _Entry(
                guid=str(fn.guid),
                name=name,
                block_count=len(fn.block_guids),
                byte_len=int(fn.byte_len),
                constraints=(
                    [
                        {"kind": c.kind, "guid": c.guid, "offset": c.offset}
                        for c in fn.constraints
                    ]
                    if constraints != "none"
                    else []
                ),
            )
        )
    return out, summary


def build_library(
    pe_paths: Sequence[Path | str],
    *,
    pdb_cache: Optional[Path | str],
    name: Optional[str] = None,
    version: Optional[str] = None,
    variant: Optional[str] = None,
    arch: Optional[str] = None,
    platform: str = PLATFORM,
    constraints: str = "ambiguous",
) -> Dict[str, Any]:
    """Build one library dict from one or more PEs.

    More than one PE is for a *union* library -- the false-positive control in
    ``docs/reference/function-signature-libraries.md`` is run against one --
    and in that case ``name`` must be given explicitly, because a union of
    ``ntdll`` and ``tcpip`` is not either of them. Any key field left ``None``
    falls back to what the **first** input PE reports, which is right for the
    one-module case and arbitrary for a union, so a union should give
    ``version`` and ``variant`` too.

    Raises:
        ValueError: ``constraints`` is not one of :data:`CONSTRAINT_MODES`, no
            input parsed as a PE, or several PEs were given without an explicit
            library name.
    """
    if constraints not in CONSTRAINT_MODES:
        raise ValueError(f"constraints must be one of {CONSTRAINT_MODES}")
    paths = [Path(p) for p in pe_paths]
    if not paths:
        raise ValueError("no input PEs")
    if len(paths) > 1 and name is None:
        raise ValueError("a library built from several PEs needs an explicit --name")

    started = time.time()
    key = library_key(paths[0])
    key.update(
        {
            k: v
            for k, v in (
                ("name", name),
                ("version", version),
                ("variant", variant),
                ("arch", arch),
                ("platform", platform),
            )
            if v is not None
        }
    )

    # (guid, name) -> entry. Two functions that folded onto one GUID keep both
    # names; the same function seen in two input PEs bumps `occurrences`.
    merged: Dict[Tuple[str, str], _Entry] = {}
    names_by_guid: Dict[str, set] = {}
    sources: List[SourceSummary] = []
    for path in paths:
        rows, summary = harvest_pe(path, pdb_cache=pdb_cache, constraints=constraints)
        sources.append(summary)
        for row in rows:
            names_by_guid.setdefault(row.guid, set()).add(row.name)
            prior = merged.get((row.guid, row.name))
            if prior is None:
                merged[(row.guid, row.name)] = row
            else:
                prior.occurrences += 1

    entries: List[Dict[str, Any]] = []
    for (guid, fname), row in sorted(merged.items()):
        ambiguous = len(names_by_guid[guid]) > 1
        keep = constraints == "all" or (constraints == "ambiguous" and ambiguous)
        entries.append(
            {
                "guid": guid,
                "name": fname,
                "base_name": base_name_of(fname),
                "block_count": row.block_count,
                "byte_len": row.byte_len,
                "occurrences": row.occurrences,
                "ambiguous": ambiguous,
                "constraints": row.constraints if keep else [],
            }
        )

    guids = set(names_by_guid)
    ambiguous_guids = sum(1 for n in names_by_guid.values() if len(n) > 1)
    return {
        "schema_version": SCHEMA_VERSION,
        "scheme": WARP_SCHEME,
        "library": key,
        "sources": [s.to_dict() for s in sources],
        "entries": entries,
        "stats": {
            "functions_discovered": sum(s.functions for s in sources),
            "functions_named": sum(s.named for s in sources),
            "functions_pdb_named": sum(s.pdb_named for s in sources),
            "pdb_resolved_fraction": round(
                sum(s.pdb_named for s in sources)
                / max(1, sum(s.functions for s in sources)),
                6,
            ),
            "entries": len(entries),
            "guids": len(guids),
            "guids_unique": len(guids) - ambiguous_guids,
            "guids_ambiguous": ambiguous_guids,
            "constraints_mode": constraints,
            "build_seconds": round(time.time() - started, 3),
        },
    }


# ---------------------------------------------------------------------------
# Measurement: what a library is worth against a build it was not made from
# ---------------------------------------------------------------------------


@dataclass
class MatchScore:
    """What one library named in one PE, scored against that PE's own PDB.

    The denominators are the point, so each is a field rather than a ratio.
    ``scored`` -- functions the target's PDB names, which is the only
    population where "correct" and "wrong" can be told apart -- is the one to
    quote recall against; ``functions`` is every function discovery found,
    including the unnamed ones no library could be graded on.
    """

    functions: int = 0
    scored: int = 0
    guid_shared: int = 0
    #: Of those, how many the library names unambiguously -- the count that
    #: would actually become a name. The rest are GUID collisions the library
    #: itself records, and no name is applied to them.
    guid_shared_unique: int = 0
    guid_shared_ambiguous: int = 0
    below_floor: int = 0
    matched: int = 0
    correct: int = 0
    wrong: int = 0
    ambiguous: int = 0
    unmatched: int = 0
    wrong_but_same_base_name: int = 0
    wrong_examples: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def recall(self) -> float:
        """Correctly named, over the functions the target's PDB names."""
        return (self.correct / self.scored) if self.scored else 0.0

    @property
    def precision(self) -> float:
        """Correct, over the scored functions a name was actually applied to."""
        applied = self.correct + self.wrong
        return (self.correct / applied) if applied else 0.0

    @property
    def guid_shared_fraction(self) -> float:
        """How much of the target is byte-identical (GUID-equal) to the source."""
        return (self.guid_shared / self.functions) if self.functions else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "functions": self.functions,
            "scored": self.scored,
            "below_floor": self.below_floor,
            "guid_shared": self.guid_shared,
            "guid_shared_unique": self.guid_shared_unique,
            "guid_shared_ambiguous": self.guid_shared_ambiguous,
            "guid_shared_fraction": round(self.guid_shared_fraction, 6),
            "matched": self.matched,
            "correct": self.correct,
            "wrong": self.wrong,
            "ambiguous": self.ambiguous,
            "unmatched": self.unmatched,
            "wrong_but_same_base_name": self.wrong_but_same_base_name,
            "recall": round(self.recall, 6),
            "precision": round(self.precision, 6),
        }


def match_pe_against_library(
    library: Dict[str, Any],
    pe_path: Path | str,
    *,
    truth_pdb_cache: Optional[Path | str] = None,
    min_bytes: int = MIN_EVIDENCE_BYTES,
) -> MatchScore:
    """Name ``pe_path``'s functions from ``library``, then grade the result.

    The matching half consults **only** the library: the target's own PDB is
    never used to produce a name, which is what makes this a measurement of
    what the library is worth against a build it was not made from rather than
    a measurement of the PDB cache.

    The grading half needs ground truth, so ``truth_pdb_cache`` is read
    *after* every name has been decided, and only functions it names are
    scored. A GUID carrying more than one library name is counted
    ``ambiguous`` and no name is applied -- "no name beats a wrong name" --
    so an ambiguous hit is never scored correct and never scored wrong.
    """
    pe_path = Path(pe_path)
    by_guid: Dict[str, set] = {}
    for entry in library.get("entries", []):
        if int(entry.get("byte_len", 0)) < min_bytes:
            continue
        by_guid.setdefault(entry["guid"], set()).add(entry["name"])

    truth: Dict[int, str] = {}
    if truth_pdb_cache is not None:
        truth = g.symbols.pdb_symbol_map(str(pe_path), str(Path(truth_pdb_cache)))

    score = MatchScore()
    for fn in g.analysis.warp_function_guids_path(str(pe_path)):
        score.functions += 1
        small = int(fn.byte_len) < min_bytes
        names = None if small else by_guid.get(str(fn.guid))
        if names:
            score.guid_shared += 1
            if len(names) > 1:
                score.guid_shared_ambiguous += 1
            else:
                score.guid_shared_unique += 1
        expected = truth.get(int(fn.entry_va))
        if expected is None:
            continue
        score.scored += 1
        if small:
            score.below_floor += 1
            continue
        if not names:
            score.unmatched += 1
            continue
        if len(names) > 1:
            score.ambiguous += 1
            continue
        score.matched += 1
        applied = next(iter(names))
        if applied == expected:
            score.correct += 1
        else:
            score.wrong += 1
            if base_name_of(applied) == base_name_of(expected):
                score.wrong_but_same_base_name += 1
            if len(score.wrong_examples) < 10:
                score.wrong_examples.append((applied, expected))
    return score


def write_library(output: Path, library: Dict[str, Any]) -> int:
    """Write a library file deterministically; return its byte size.

    ``sort_keys`` and a trailing newline, so rebuilding an unchanged input
    produces a zero-line diff.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(library, indent=2, sort_keys=True) + "\n"
    output.write_text(text)
    return len(text.encode())


def library_filename(key: Dict[str, str]) -> str:
    """``<name>-<version>-<variant>.<arch>.warp.json``, filesystem-safe."""

    def clean(s: str) -> str:
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)

    return (
        f"{clean(key['name'])}-{clean(key['version'])}-"
        f"{clean(key['variant'])}.{clean(key['arch'])}.warp.json"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _expand(roots: Iterable[Path]) -> List[Path]:
    out: List[Path] = []
    seen: set = set()
    for root in roots:
        candidates = [root] if root.is_file() else sorted(root.rglob("*"))
        for p in candidates:
            if not p.is_file():
                continue
            key = str(p.resolve())
            if key in seen:
                continue
            with p.open("rb") as fh:
                if fh.read(2) != b"MZ":
                    continue
            seen.add(key)
            out.append(p)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m glaurung.tools.build_warp_library",
        description="Build a WARP exact-match signature library from PEs + PDBs.",
    )
    p.add_argument("roots", nargs="+", type=Path, help="PE files or directories.")
    p.add_argument(
        "--pdb-cache",
        type=Path,
        default=None,
        help="Microsoft-style symbol cache: <cache>/<pdb>/<GUID+AGE>/<pdb>.",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for the library files (and --index).",
    )
    p.add_argument(
        "--union-name",
        default=None,
        help="Build ONE library from every input under this name, instead of "
        "one library per module.",
    )
    p.add_argument("--union-version", default="union")
    p.add_argument("--union-variant", default="mixed")
    p.add_argument("--arch", default=None, help="Override the detected arch tag.")
    p.add_argument(
        "--constraints",
        choices=CONSTRAINT_MODES,
        default="ambiguous",
        help="Which entries carry WARP constraints (default: ambiguous only).",
    )
    p.add_argument(
        "--skip-without-pdb",
        action="store_true",
        help="Skip modules whose PDB is not in the cache.",
    )
    p.add_argument(
        "--index",
        action="store_true",
        help="Write index.json summarising every library in --output-dir.",
    )
    p.add_argument(
        "--kb",
        type=Path,
        default=None,
        help=(
            "Also ingest every library written into this .glaurung knowledge "
            "base, so `function_match` rows can name which library resolved a "
            "hit. Created if absent."
        ),
    )
    args = p.parse_args(argv)

    pes = _expand(args.roots)
    if not pes:
        print("no PE inputs found", file=sys.stderr)
        return 1

    if args.pdb_cache and args.skip_without_pdb:
        pes = [p for p in pes if resolve_pdb(p, args.pdb_cache)]
        if not pes:
            print("no input resolved a PDB in the cache", file=sys.stderr)
            return 1

    written: List[Dict[str, Any]] = []
    groups: List[Tuple[Optional[str], List[Path]]]
    if args.union_name:
        groups = [(args.union_name, pes)]
    else:
        groups = [(None, [p]) for p in pes]

    for union_name, group in groups:
        try:
            lib = build_library(
                group,
                pdb_cache=args.pdb_cache,
                name=union_name,
                version=args.union_version if union_name else None,
                variant=args.union_variant if union_name else None,
                arch=args.arch,
                constraints=args.constraints,
            )
        except ValueError as exc:
            print(f"skip {group[0]}: {exc}", file=sys.stderr)
            continue
        out = args.output_dir / library_filename(lib["library"])
        size = write_library(out, lib)
        stats = lib["stats"]
        written.append(
            {
                "file": out.name,
                "library": lib["library"],
                "entries": stats["entries"],
                "guids": stats["guids"],
                "guids_unique": stats["guids_unique"],
                "guids_ambiguous": stats["guids_ambiguous"],
                "functions_discovered": stats["functions_discovered"],
                "pdb_resolved_fraction": stats["pdb_resolved_fraction"],
                "build_seconds": stats["build_seconds"],
                "bytes": size,
            }
        )
        print(
            f"{out.name}: {stats['entries']} entries, {stats['guids']} guids "
            f"({stats['guids_ambiguous']} ambiguous), "
            f"pdb {stats['pdb_resolved_fraction']:.3f}, "
            f"{stats['build_seconds']:.1f}s, {size} bytes"
        )

    if args.kb is not None and written:
        # Imported here rather than at module scope: the builder itself needs
        # nothing from the KB layer except `base_name_of`, and a --kb-less run
        # should not pay for sqlite and the schema script.
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase
        from glaurung.llm.kb.siglib import ingest_warp_library_file

        kb = PersistentKnowledgeBase.open(args.kb, binary_path=str(pes[0]))
        total = 0
        for row in written:
            total += ingest_warp_library_file(
                kb, str(args.output_dir / row["file"])
            ).functions_ingested
        print(f"kb: {total} siglib_function rows in {args.kb}")

    if args.index:
        # Deduplicated by file name, keeping the last write. Two inputs can
        # share a key and therefore a file: `ndfltr.sys` is byte-identical and
        # identically versioned in the Windows 10 and Windows 11 trees, so it
        # is *one* library and the second build overwrote the first. Listing
        # it twice would make the index claim a file that does not exist
        # separately, and would double-count its entries in any total taken
        # from this file.
        unique = {row["file"]: row for row in written}
        index_path = args.output_dir / "index.json"
        index_path.write_text(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "scheme": WARP_SCHEME,
                    "libraries": sorted(unique.values(), key=lambda r: r["file"]),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        print(
            f"index: {index_path} ({len(unique)} libraries"
            + (
                f", {len(written) - len(unique)} inputs shared a key)"
                if len(written) != len(unique)
                else ")"
            )
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
