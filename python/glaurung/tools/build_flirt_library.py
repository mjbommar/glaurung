"""Build a FLIRT-style signature library (#158).

Two input classes, and the difference between them is the whole point.

**Archives (``--archive``, preferred).** An ``ar`` archive holds *unlinked*
``.o`` members, and a relocatable object carries the relocation table that
says, byte for byte, which parts of the text the linker will overwrite.
Masking exactly those bytes is what makes a signature survive relinking.
This mode calls
:func:`glaurung.analysis.flirt_signatures_from_archive_path`, which reads
the relocations with the ``object`` crate, and emits schema version ``2``:
pattern, variant-byte mask, a FLIRT CRC16 over the bytes after the pattern
up to the first variant byte, the function length, and the referenced
names that act as a second-level disambiguator.

**Linked binaries (positional roots, legacy).** Kept because it is how the
original 30-signature library was made and because it is occasionally the
only input available. It cannot mask anything: a linked image has no
relocation table, so every ``call rel32`` and RIP-relative ``lea`` in the
window is an absolute the linker chose. It emits schema version ``1``
(exact byte equality), and the matcher still reads that -- an absent mask
means every byte is fixed.

A library is keyed by ``(name, version, variant, arch)``. No exact or
masked scheme crosses an optimisation level, so a corpus spanning gcc and
clang across ``-O0`` to ``-O3`` is not one library; it is N libraries
sharing a name. Cross-variant matching is a different rung of the identity
ladder (see ``docs/history/program-measures-2026-09-02.md``).

Usage:
    # From an archive, with relocation-derived masks (preferred):
    python -m glaurung.tools.build_flirt_library \\
        --archive samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a \\
        --library-name mathlib --library-version 1.0.0 \\
        --variant gcc-O2 --arch x86_64 \\
        --output data/sigs/mathlib-1.0.0-gcc-O2.x86_64.flirt.json

    # From linked binaries, exact match only (legacy):
    python -m glaurung.tools.build_flirt_library \\
        --output data/sigs/glaurung-base.x86_64.flirt.json \\
        --arch x86_64 \\
        samples/binaries/platforms/linux/amd64/export/native/clang/debug
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional

import glaurung as g

PROLOGUE_LEN = 32

#: Exact byte equality, no mask. What the linked-binary path can produce.
SCHEMA_VERSION = "1"

#: Masks, CRC16 and referenced names. What the archive path produces.
SCHEMA_VERSION_MASKED = "2"

_EXEC_MAGICS = (
    b"\x7fELF",
    b"MZ",
    b"\xca\xfe\xba\xbe",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
)


def _looks_like_binary(p: Path) -> bool:
    if not p.is_file():
        return False
    if any(p.name.endswith(s) for s in (".json", ".md", ".txt", ".c", ".cpp", ".f90")):
        return False
    try:
        with p.open("rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return any(head.startswith(m) for m in _EXEC_MAGICS)


def _is_useful_name(name: str) -> bool:
    """Skip `sub_*` placeholders and obvious noise."""
    if not name:
        return False
    if name.startswith("sub_"):
        return False
    return True


@dataclass
class Signature:
    name: str
    prologue_hex: str
    source_binary: str


def _read_prologue(binary: Path, va: int, raw: bytes) -> Optional[bytes]:
    try:
        off = g.analysis.va_to_file_offset_path(
            str(binary),
            int(va),
            100_000_000,
            100_000_000,
        )
    except Exception:
        return None
    if off is None:
        return None
    off = int(off)
    if off < 0 or off + PROLOGUE_LEN > len(raw):
        return None
    return raw[off : off + PROLOGUE_LEN]


def _harvest_one(binary: Path) -> List[Signature]:
    try:
        funcs, _cg = g.analysis.analyze_functions_path(str(binary))
    except Exception:
        return []
    raw = binary.read_bytes()
    out: list[Signature] = []
    for f in funcs:
        if not _is_useful_name(f.name):
            continue
        if not f.basic_blocks:
            continue
        proto = _read_prologue(binary, int(f.entry_point.value), raw)
        if proto is None:
            continue
        if all(b == 0 for b in proto):
            continue
        out.append(
            Signature(
                name=f.name,
                prologue_hex=proto.hex(),
                source_binary=str(binary),
            )
        )
    return out


def build_library(binaries: Iterable[Path], arch: str) -> dict:
    """Collect signatures, deduplicate by prologue, return a JSON-ready dict."""
    by_proto: dict[str, Signature] = {}
    ambiguous_protos: set[str] = set()
    name_seen: set[str] = set()
    counts = {"binaries": 0, "raw_signatures": 0}

    for b in binaries:
        sigs = _harvest_one(b)
        if sigs:
            counts["binaries"] += 1
        for s in sigs:
            counts["raw_signatures"] += 1
            if s.prologue_hex in ambiguous_protos:
                continue
            if s.prologue_hex in by_proto:
                # Same prologue, different name → ambiguous, drop both.
                if by_proto[s.prologue_hex].name != s.name:
                    ambiguous_protos.add(s.prologue_hex)
                    del by_proto[s.prologue_hex]
                continue
            if s.name in name_seen:
                # Same name, second prologue. Keep the first deterministically.
                continue
            name_seen.add(s.name)
            by_proto[s.prologue_hex] = s

    entries = sorted(by_proto.values(), key=lambda s: s.name)
    # Build first-4-bytes prefix → entry-index map for fast lookup.
    index: dict[str, list[int]] = {}
    for i, e in enumerate(entries):
        prefix = e.prologue_hex[:8]  # 4 bytes = 8 hex chars
        index.setdefault(prefix, []).append(i)

    return {
        "schema_version": SCHEMA_VERSION,
        "arch": arch,
        "prologue_len": PROLOGUE_LEN,
        "entries": [asdict(e) for e in entries],
        "index": index,
        "stats": {
            "binaries_scanned": counts["binaries"],
            "raw_signatures": counts["raw_signatures"],
            "unique_signatures": len(entries),
            "dropped_ambiguous": len(ambiguous_protos),
        },
    }


def _masked_pattern(prologue_hex: str, mask_hex: str | None) -> str:
    """The pattern with every variant byte zeroed.

    Two signatures with the same value here are indistinguishable to the
    matcher, whatever their raw bytes say, so this is the identity the
    ambiguity check has to use.
    """
    if not mask_hex:
        return prologue_hex
    pattern = bytes.fromhex(prologue_hex)
    mask = bytes.fromhex(mask_hex)
    return bytes(p & m for p, m in zip(pattern, mask)).hex()


def build_library_from_archive(
    archive: Path,
    *,
    library_name: str,
    version: str,
    variant: str,
    arch: str,
    prologue_len: int = PROLOGUE_LEN,
    min_function_len: int = 8,
    min_fixed_bytes: int = 16,
) -> dict:
    """Build a masked signature library from one ``ar`` archive.

    The masks come from the relocation tables of the archive's ``.o``
    members, read by :func:`glaurung.analysis.flirt_signatures_from_archive_path`.
    That is the only mask source that is *exact*: it is the linker's own
    record of which bytes it is going to rewrite.

    Args:
        archive: Path to a ``.a`` archive of unlinked objects.
        library_name: Library name, e.g. ``mathlib``.
        version: Library version, e.g. ``1.0.0``.
        variant: Compiler and flags, e.g. ``gcc-O2``. Part of the key, not
            metadata: no masked scheme crosses an optimisation level.
        arch: Architecture tag, e.g. ``x86_64``.
        prologue_len: Pattern length in bytes.
        min_function_len: Skip symbols smaller than this.
        min_fixed_bytes: Skip signatures that would compare fewer than this
            many bytes after masking. The default of 16 is measured, not
            chosen: at 8 the four shortest signatures in the shipped archive
            produced four false positives across the fixture corpus. See
            ``ArchiveOptions`` in ``src/flirt/archive.rs``.

    Returns:
        A JSON-ready dict in schema version 2.

    Raises:
        ValueError: the file is not an ``ar`` archive.
    """
    raw = g.analysis.flirt_signatures_from_archive_path(
        str(archive), prologue_len, min_function_len, min_fixed_bytes
    )

    # Two functions that are indistinguishable to the matcher -- same *masked*
    # pattern, same mask, same CRC -- but carrying different names are dropped,
    # both of them. A FLIRT hit writes a name at `set_by=flirt`, which outranks
    # `auto`; a coin flip there is worse than no name at all.
    #
    # The key is the masked pattern, not the raw one. Variant bytes are never
    # compared, so two signatures that differ only there are the same signature
    # as far as matching is concerned -- and keying on the raw hex would let
    # both into the library and let whichever came first win.
    by_key: dict[tuple[str, str, object, int], dict] = {}
    ambiguous: set[tuple[str, str, object, int]] = set()
    for row in raw:
        key = (
            _masked_pattern(row["prologue_hex"], row["mask_hex"]),
            row["mask_hex"] or "",
            row["crc16"],
            int(row["crc_len"]),
        )
        if key in ambiguous:
            continue
        prior = by_key.get(key)
        if prior is not None:
            if prior["name"] != row["name"]:
                ambiguous.add(key)
                del by_key[key]
            continue
        by_key[key] = row

    entries: list[dict[str, Any]] = []
    index: dict[str, list[int]] = {}
    for row in sorted(by_key.values(), key=lambda r: (r["name"], r["prologue_hex"])):
        pattern_hex = str(row["prologue_hex"])
        mask_hex = str(row["mask_hex"]) if row["mask_hex"] else None
        entries.append(
            {
                "name": row["name"],
                "prologue_hex": pattern_hex,
                "source_binary": row["source_binary"],
                "mask_hex": mask_hex,
                "crc16": row["crc16"],
                "crc_len": int(row["crc_len"]),
                "function_len": row["function_len"],
                "refs": [
                    {"offset": int(r["offset"]), "name": r["name"]} for r in row["refs"]
                ],
            }
        )
        # The prefix index keys on the first four bytes, so it is only usable
        # when those four are fixed. An entry whose prologue starts variant is
        # left out of the index rather than filed under bytes that will change.
        if (mask_hex or "ff" * (len(pattern_hex) // 2))[:8] == "ffffffff":
            index.setdefault(pattern_hex[:8], []).append(len(entries) - 1)

    masked = sum(1 for r in raw if int(r["masked_bytes"]) > 0)
    return {
        "schema_version": SCHEMA_VERSION_MASKED,
        "arch": arch,
        "prologue_len": prologue_len,
        "library": {
            "name": library_name,
            "version": version,
            "variant": variant,
            "arch": arch,
        },
        "entries": entries,
        "index": index,
        "stats": {
            "archive": str(archive),
            "raw_signatures": len(raw),
            "unique_signatures": len(entries),
            "dropped_ambiguous": len(ambiguous),
            "signatures_with_masked_bytes": masked,
            "signatures_with_crc": sum(1 for e in entries if int(e["crc_len"]) > 0),
            "signatures_with_refs": sum(1 for e in entries if e["refs"]),
        },
    }


def _expand_roots(roots: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for r in roots:
        if r.is_file():
            rp = r.resolve()
            if str(rp) not in seen and _looks_like_binary(r):
                seen.add(str(rp))
                out.append(r)
            continue
        for p in sorted(r.rglob("*")):
            if not _looks_like_binary(p):
                continue
            rp = p.resolve()
            if str(rp) in seen:
                continue
            seen.add(str(rp))
            out.append(p)
    return out


def _write(output: Path, lib: dict) -> None:
    """Write a library file deterministically.

    ``sort_keys`` plus a trailing newline so a rebuild that changed nothing
    produces a zero-line diff, which is what makes the committed library
    reviewable.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(lib, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m glaurung.tools.build_flirt_library",
        description="Build a FLIRT-style prologue signature library (#158).",
    )
    p.add_argument(
        "roots",
        nargs="*",
        type=Path,
        help=(
            "Directories or files of LINKED binaries to harvest exact "
            "signatures from. Legacy: cannot mask. Prefer --archive."
        ),
    )
    p.add_argument(
        "--archive",
        type=Path,
        help=(
            "An ar archive of unlinked objects. Masks are derived from its "
            "relocation tables, which is what makes a signature survive "
            "relinking."
        ),
    )
    p.add_argument(
        "--library-name", default=None, help="Library name for --archive, e.g. mathlib."
    )
    p.add_argument(
        "--library-version", default="unknown", help="Library version for --archive."
    )
    p.add_argument(
        "--variant",
        default="unknown",
        help=(
            "Compiler and flags for --archive, e.g. gcc-O2. Part of the key: "
            "no masked scheme crosses an optimisation level."
        ),
    )
    p.add_argument(
        "--min-function-len",
        type=int,
        default=8,
        help="Skip symbols smaller than this many bytes (--archive only).",
    )
    p.add_argument(
        "--min-fixed-bytes",
        type=int,
        default=16,
        help=(
            "Skip signatures that would compare fewer than this many bytes "
            "after masking (--archive only). Lowering it admits short "
            "functions that cannot be identified by their bytes."
        ),
    )
    p.add_argument(
        "--output", type=Path, required=True, help="JSON library output path."
    )
    p.add_argument("--arch", default="x86_64", help="Target architecture tag.")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    if args.archive and args.roots:
        print(
            "error: --archive and positional roots are different input classes "
            "(unlinked vs linked) producing different schema versions; build "
            "them into separate library files",
            file=sys.stderr,
        )
        return 2

    if args.archive:
        if not args.archive.is_file():
            print(f"error: {args.archive} is not a file", file=sys.stderr)
            return 2
        try:
            lib = build_library_from_archive(
                args.archive,
                library_name=args.library_name or args.archive.stem.removeprefix("lib"),
                version=args.library_version,
                variant=args.variant,
                arch=args.arch,
                min_function_len=args.min_function_len,
                min_fixed_bytes=args.min_fixed_bytes,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        _write(args.output, lib)
        if not args.quiet:
            s = lib["stats"]
            print(
                f"wrote {args.output}  "
                f"(raw={s['raw_signatures']}, "
                f"unique={s['unique_signatures']}, "
                f"dropped_ambiguous={s['dropped_ambiguous']}, "
                f"masked={s['signatures_with_masked_bytes']}, "
                f"with_crc={s['signatures_with_crc']}, "
                f"with_refs={s['signatures_with_refs']})",
                file=sys.stderr,
            )
        return 0

    binaries = _expand_roots(args.roots)
    if not binaries:
        print("error: no binaries found under given roots", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"harvesting from {len(binaries)} binaries…", file=sys.stderr)
    lib = build_library(binaries, args.arch)
    _write(args.output, lib)
    if not args.quiet:
        s = lib["stats"]
        print(
            f"wrote {args.output}  "
            f"(binaries={s['binaries_scanned']}, "
            f"raw={s['raw_signatures']}, "
            f"unique={s['unique_signatures']}, "
            f"dropped_ambiguous={s['dropped_ambiguous']})",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
