"""Build a FLIRT-style signature library from named functions in debug binaries (#158).

Walks every input binary, extracts each function's first N bytes from
its entry VA, and writes a JSON library that the Rust matcher can load
to rename `sub_*` functions in stripped binaries.

V1 design choices (deliberate simplifications):
  - **Exact match**, no per-byte mask. Two functions with identical
    prologue bytes are *both dropped* from the library — ambiguous
    matches are worse than no match.
  - **32-byte prologue.** Long enough to discriminate, short enough
    to fit comfortably in cache.
  - **Deduplicate by name**, keep the first occurrence. Build order
    determines preference; prefer well-named binaries first.

Usage:
    python -m glaurung.tools.build_flirt_library \\
        --output data/sigs/glaurung-base.x86_64.flirt.json \\
        --arch x86_64 \\
        samples/binaries/platforms/linux/amd64/export/native/clang/debug \\
        samples/binaries/platforms/linux/amd64/export/native/gcc/debug
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Optional

import glaurung as g

PROLOGUE_LEN = 32
SCHEMA_VERSION = "1"

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
            str(binary), int(va), 100_000_000, 100_000_000,
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


def build_library(
    binaries: Iterable[Path], arch: str
) -> dict:
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m glaurung.tools.build_flirt_library",
        description="Build a FLIRT-style prologue signature library (#158).",
    )
    p.add_argument(
        "roots", nargs="+", type=Path,
        help="One or more directories or files to harvest signatures from.",
    )
    p.add_argument("--output", type=Path, required=True, help="JSON library output path.")
    p.add_argument("--arch", default="x86_64", help="Target architecture tag.")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    binaries = _expand_roots(args.roots)
    if not binaries:
        print("error: no binaries found under given roots", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"harvesting from {len(binaries)} binaries…", file=sys.stderr)
    lib = build_library(binaries, args.arch)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(lib, indent=2, sort_keys=True))
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
