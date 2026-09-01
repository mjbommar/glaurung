#!/usr/bin/env python3
"""Build seed corpora for the fuzz targets out of binaries this repo already has.

Why seed at all
---------------

libFuzzer starting from nothing spends its first minutes rediscovering that an
ELF begins with ``\\x7fELF``. Every one of our targets consumes a *structured*
input -- a container header, a mangled symbol, a stream of instruction bytes --
and the repository is full of real examples of each. Seeding turns the first
minutes of a run from format discovery into actual exploration.

Why generated, not committed
----------------------------

The inputs are slices of binaries already tracked here, so committing them
would store the same bytes twice -- the exact defect
``docs/test-inventory/findings.md`` records as 18.8 MB of duplication. This
script is the corpus; run it before a campaign.

Usage
-----

    uv run python fuzz/seed_corpus.py            # seed every target
    uv run python fuzz/seed_corpus.py --target demangle_all
    cargo fuzz run demangle_all                  # then fuzz

``cargo fuzz cmin <target>`` minimizes afterwards, which is worth doing once a
corpus has grown past a few hundred inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS = Path(__file__).resolve().parent / "corpus"

#: Where to find real binaries. The fixture build directory is gitignored and
#: may be absent; that is not an error, it just yields fewer seeds.
BINARY_ROOTS = [
    REPO / "samples" / "binaries",
    REPO / "samples" / "packed",
    REPO / "samples" / "adversarial",
    REPO / "tests" / "decompiler_fixtures" / "build",
]

#: A seed larger than this teaches the fuzzer little and slows every execution.
MAX_SEED_BYTES = 64 * 1024


def binaries(limit: int) -> list[Path]:
    """Real binaries from the tracked corpora, newest-largest first."""
    found: list[Path] = []
    for root in BINARY_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.stat().st_size > 64:
                found.append(path)
    return found[:limit]


def write_seed(target: str, data: bytes) -> bool:
    """Write one seed, named by content hash so reruns do not duplicate."""
    if not data or len(data) > MAX_SEED_BYTES:
        return False
    out = CORPUS / target
    out.mkdir(parents=True, exist_ok=True)
    name = hashlib.sha256(data).hexdigest()[:16]
    path = out / name
    if path.exists():
        return False
    path.write_bytes(data)
    return True


def seed_headers(targets: list[str], limit: int) -> dict[str, int]:
    """Header prefixes, for the container-parsing targets."""
    counts = dict.fromkeys(targets, 0)
    for path in binaries(limit):
        data = path.read_bytes()[:4096]
        for target in targets:
            counts[target] += write_seed(target, data)
    return counts


def seed_demangle(limit: int) -> int:
    """Mangled symbol names, from the symbol tables of real binaries.

    Uses ``nm`` rather than a Rust helper so this script has no build step. A
    binary with no symbol table simply contributes nothing.
    """
    written = 0
    mangled = re.compile(rb"^(_Z|_R|\?)[\x21-\x7e]{2,1000}$")
    for path in binaries(limit):
        try:
            proc = subprocess.run(
                ["nm", "--no-demangle", "-P", str(path)],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        for line in proc.stdout.splitlines():
            symbol = line.split(b" ", 1)[0]
            if mangled.match(symbol):
                written += write_seed("demangle_all", symbol)
    return written


def seed_disasm(limit: int) -> int:
    """Executable bytes, prefixed with the architecture selector byte.

    ``disasm_decode`` consumes its first byte as an architecture selector, so a
    raw ``.text`` slice would exercise one decoder and lose its first
    instruction. Each slice is emitted once per selector value.
    """
    written = 0
    for path in binaries(limit):
        try:
            proc = subprocess.run(
                [
                    "objcopy",
                    "-O",
                    "binary",
                    "--only-section=.text",
                    str(path),
                    "/dev/stdout",
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = proc.stdout[:2048]
        if len(text) < 16:
            continue
        for selector in range(4):
            written += write_seed("disasm_decode", bytes([selector]) + text)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="seed only this target")
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="maximum binaries to draw from (default: 200)",
    )
    args = parser.parse_args()

    header_targets = [
        "headers_validate",
        "containers_detect",
        "sniffers_sniff",
        "parsers_parse",
        "entropy_analyze",
        "formats_parse",
    ]
    if args.target:
        header_targets = [t for t in header_targets if t == args.target]

    written: dict[str, int] = {}
    if header_targets:
        written.update(seed_headers(header_targets, args.limit))
    if args.target in (None, "demangle_all"):
        written["demangle_all"] = seed_demangle(args.limit)
    if args.target in (None, "disasm_decode"):
        written["disasm_decode"] = seed_disasm(args.limit)

    if not written:
        print(f"no such target: {args.target}")
        return 2
    total = 0
    for target, count in sorted(written.items()):
        held = (
            len(list((CORPUS / target).glob("*"))) if (CORPUS / target).is_dir() else 0
        )
        print(f"  {target:<20} +{count:<5} ({held} total)")
        total += count
    print(f"{total} new seeds under {CORPUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
