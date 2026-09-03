#!/usr/bin/env python3
"""Measure how much two signature libraries actually share.

This is the number that decides whether the corpus is one library per
`(distro, release, arch, package version)` or something smaller. It is not the
same question as "do these two releases ship the same source version": two
builds of identical glibc source with different `dpkg-buildflags` produce
different bytes in the first 32 instructions of most functions, and a signature
is those bytes.

Identity here is the tuple the matcher actually compares -- **masked pattern,
mask, CRC16 and CRC length** -- over the names present in both libraries. The
masked pattern is the prologue with every variant byte zeroed, so two functions
that differ only where the linker was going to rewrite them count as identical,
which is exactly what a relink-surviving signature is for. `function_len` is
deliberately *not* in the key: the builder puts it in its ambiguity key but the
matcher never compares it, so including it here would report two entries as
distinct that no match can tell apart.

Usage:
    uv run python tools/sig_library_overlap.py \\
        --sigs ~/.cache/glaurung/system-libs/sigs \\
        --archive libc --triplet x86_64-linux-gnu --markdown
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


def masked_pattern(prologue_hex: str, mask_hex: str | None) -> str:
    """Zero every byte the mask marks as variant.

    Args:
        prologue_hex: The recorded prologue bytes, hex.
        mask_hex: The per-byte mask, hex, ``ff`` fixed and ``00`` variant.
            ``None`` means schema 1, where every byte is fixed.

    Returns:
        The pattern with variant bytes zeroed, hex.
    """
    if not mask_hex:
        return prologue_hex
    pattern = bytes.fromhex(prologue_hex)
    mask = bytes.fromhex(mask_hex)
    width = min(len(pattern), len(mask))
    return bytes(pattern[i] & mask[i] for i in range(width)).hex()


def signature_key(entry: dict[str, Any]) -> tuple[str, str, int, int]:
    """Return what the matcher compares, and nothing else."""
    return (
        masked_pattern(entry.get("prologue_hex", ""), entry.get("mask_hex")),
        entry.get("mask_hex") or "",
        int(entry.get("crc16") or 0),
        int(entry.get("crc_len") or 0),
    )


def load_library(path: Path) -> dict[str, tuple[str, str, int, int]]:
    """Return ``name -> signature key`` for one built library."""
    data = json.loads(path.read_text())
    return {
        str(entry["name"]): signature_key(entry)
        for entry in data.get("entries", [])
        if entry.get("name")
    }


def compare(left: Path, right: Path) -> dict[str, Any]:
    """Compare two libraries over the names they both define.

    Returns:
        ``{shared_names, identical, fraction}``. ``fraction`` is ``0.0`` when
        the two share no names at all, which is itself a result -- it is what
        an aarch64 library against an x86_64 one looks like.
    """
    a, b = load_library(left), load_library(right)
    shared = sorted(set(a) & set(b))
    identical = sum(1 for name in shared if a[name] == b[name])
    return {
        "left": left.name,
        "right": right.name,
        "shared_names": len(shared),
        "identical": identical,
        "fraction": (identical / len(shared)) if shared else 0.0,
    }


def select(sigs: Path, archive: str, triplet: str) -> list[tuple[str, Path]]:
    """Return ``(cell, path)`` for one archive name and one target triplet.

    Selection reads the set's own ``index.json`` rather than splitting the
    filename. The filenames look parseable -- ``<cell>.<triplet>.<stem>`` -- and
    they are not: ``alpine-v3.21-x86_64`` has a dot in the release and
    ``libm-2.39`` has one in the stem, so a `str.split(".")` puts ``21-x86_64``
    where the triplet should be and silently selects nothing. The index states
    all three fields.

    The triplet matters, not the cell's architecture name: one Docker harvest
    image carries eight of them -- ``linux-amd64`` holds an x86_64 ``libc.a``,
    an aarch64 one and five more -- so comparing on the cell alone puts
    different instruction sets in the same row, where they share every name and
    no bytes and the 0% means nothing.

    Args:
        sigs: The signature-set directory, holding ``index.json``.
        archive: An archive stem, e.g. ``libc``. ``.a`` is appended, so ``libc``
            does not also select ``libc_nonshared``.
        triplet: A GNU triplet, e.g. ``x86_64-linux-gnu``. Empty means all.

    Returns:
        ``(cell, path)`` pairs for libraries that were built and have entries,
        sorted by cell.

    Raises:
        HarvestIndexMissing: There is no index to read.
    """
    index_path = sigs / "index.json"
    if not index_path.is_file():
        raise FileNotFoundError(index_path)
    index = json.loads(index_path.read_text())
    out: list[tuple[str, Path]] = []
    for row in index.get("libraries", []):
        if row.get("archive") != f"{archive}.a":
            continue
        if triplet and row.get("triplet") != triplet:
            continue
        if not int(row.get("unique_signatures", 0)):
            continue
        path = sigs / str(row["output"])
        if path.is_file():
            out.append((str(row["image"]), path))
    out.sort(key=lambda pair: pair[0])
    return out


def _row(result: dict[str, Any], label_left: str, label_right: str) -> str:
    return (
        f"| {label_left} | {label_right} | {result['shared_names']} | "
        f"{result['identical']} | {result['fraction'] * 100:.1f}% |"
    )


def adjacent_pairs(items: Iterable[Any]) -> list[tuple[Any, Any]]:
    """Pair each item with the next one in the given order."""
    ordered = list(items)
    return list(zip(ordered, ordered[1:]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sig_library_overlap.py",
        description="Measure signature-level overlap between built libraries.",
    )
    parser.add_argument(
        "--sigs",
        type=Path,
        default=Path.home() / ".cache" / "glaurung" / "system-libs" / "sigs",
        help="Directory of .flirt.json libraries.",
    )
    parser.add_argument("--archive", default="libc", help="Archive stem to compare.")
    parser.add_argument(
        "--triplet",
        default="",
        help=(
            "Target triplet, e.g. x86_64-linux-gnu. Give one: a harvest image "
            "carries several, and comparing across them is meaningless."
        ),
    )
    parser.add_argument(
        "--pair",
        action="append",
        default=[],
        nargs=2,
        metavar=("LEFT", "RIGHT"),
        help="Compare two explicit cells instead of every pair; repeatable.",
    )
    parser.add_argument("--markdown", action="store_true", help="Emit a table.")
    args = parser.parse_args(argv)

    sigs = args.sigs.expanduser()
    try:
        selected = select(sigs, args.archive, args.triplet)
    except FileNotFoundError as exc:
        print(f"error: {exc} not found", file=sys.stderr)
        return 2
    if not selected:
        print(
            f"error: no {args.archive}.a libraries for triplet "
            f"{args.triplet or '<any>'} under {sigs}",
            file=sys.stderr,
        )
        return 2

    by_cell = dict(selected)
    if args.pair:
        pairs: list[tuple[str, str]] = []
        for left, right in args.pair:
            if left not in by_cell or right not in by_cell:
                print(f"error: unknown cell {left} or {right}", file=sys.stderr)
                return 2
            pairs.append((left, right))
    else:
        cells = [cell for cell, _ in selected]
        pairs = [(a, b) for i, a in enumerate(cells) for b in cells[i + 1 :]]

    if args.markdown:
        print("| left | right | shared names | identical | identical % |")
        print("|---|---|---|---|---|")
    for left, right in pairs:
        result = compare(by_cell[left], by_cell[right])
        if args.markdown:
            print(_row(result, left, right))
        else:
            print(
                f"{left} vs {right}: {result['identical']}/"
                f"{result['shared_names']} ({result['fraction'] * 100:.1f}%)"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
