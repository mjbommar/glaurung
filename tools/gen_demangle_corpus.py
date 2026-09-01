#!/usr/bin/env python3
"""Build a demangler test corpus from real symbols, checked against real tools.

Why this exists
---------------

``src/demangle/`` implements three separate grammars -- Itanium C++, Rust v0,
and MSVC -- and has **one** unit test between them. Demanglers are also the
kind of code that rots quietly: a name that demangles wrongly still produces a
plausible-looking string, so nothing downstream complains.

What makes this cheap is that the corpus does not have to be invented. Every
C++ and Rust binary in ``samples/`` carries hundreds of real mangled names in
its symbol table, and ``llvm-cxxfilt`` / ``rustfilt`` are reference
implementations that will say what each one means.

Not circular
------------

Expectations come from the reference tools, **never** from glaurung's own
output, and glaurung is not consulted here at all. A corpus regenerated from
our own answers would pin whatever we do today, including the bugs, and then
assert we keep doing it.

Comparing the two is the *test's* job, not this script's, precisely so that a
disagreement surfaces as a failing test a human has to look at rather than as
a diff this script could quietly absorb on its next run.

A name the reference tool echoes back unchanged is dropped: that is the tool
saying it could not parse the name, which is an absence of an expectation
rather than an expectation of the identity.

Usage
-----

    uv run python tools/gen_demangle_corpus.py            # regenerate
    uv run python tools/gen_demangle_corpus.py --check    # exit 1 if stale

Output is ``tests/fixtures/demangle/corpus.jsonl``, one object per line:

    {"mangled": "_Z3foov", "expected": "foo()", "flavor": "itanium",
     "source": "llvm-cxxfilt"}
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "tests" / "fixtures" / "demangle" / "corpus.jsonl"

#: Where to look for binaries carrying mangled names. C++ and Rust builds are
#: the productive ones; C binaries contribute nothing and cost a subprocess.
BINARY_ROOTS = [
    REPO / "samples" / "binaries",
    REPO / "tests" / "decompiler_fixtures" / "build",
]

#: Itanium (`_Z`), Rust v0 (`_R`), MSVC (`?`). Anchored, printable-only, and
#: length-bounded: an unbounded name is a fuzzing input, not a corpus entry.
MANGLED = re.compile(
    r"^(_Z[\x21-\x7e]{2,900}|_R[\x21-\x7e]{2,900}|\?[\x21-\x7e]{2,900})$"
)

FLAVORS = {"_Z": "itanium", "_R": "rust_v0", "?": "msvc"}


def flavor_of(mangled: str) -> str:
    for prefix, name in FLAVORS.items():
        if mangled.startswith(prefix):
            return name
    return "unknown"


def reference_tool(flavor: str) -> str | None:
    """The reference demangler for a flavor, if it is installed."""
    candidates = {
        "itanium": ["llvm-cxxfilt", "c++filt"],
        "rust_v0": ["rustfilt"],
        "msvc": ["llvm-undname"],
    }.get(flavor, [])
    for tool in candidates:
        if shutil.which(tool):
            return tool
    return None


def harvest(limit: int) -> set[str]:
    """Mangled names from the symbol tables of tracked binaries."""
    names: set[str] = set()
    seen_files = 0
    for root in BINARY_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.stat().st_size < 1024:
                continue
            if seen_files >= limit:
                break
            seen_files += 1
            try:
                proc = subprocess.run(
                    ["nm", "--no-demangle", "-P", str(path)],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            for line in proc.stdout.splitlines():
                symbol = line.split(" ", 1)[0]
                if MANGLED.match(symbol):
                    names.add(symbol)
    return names


def demangle_with(tool: str, names: list[str]) -> dict[str, str]:
    """Run a reference demangler over many names in one subprocess."""
    if not names:
        return {}
    try:
        proc = subprocess.run(
            [tool],
            input="\n".join(names) + "\n",
            capture_output=True,
            text=True,
            errors="replace",
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    lines = proc.stdout.splitlines()
    if len(lines) != len(names):
        # A tool that does not answer one line per input cannot be aligned;
        # better no data than misaligned data.
        return {}
    return {
        name: out.strip()
        for name, out in zip(names, lines)
        # A demangler echoes back what it cannot parse. That is not an
        # expectation, it is an absence of one.
        if out.strip() and out.strip() != name
    }


def build(limit: int) -> list[dict[str, str]]:
    names = harvest(limit)
    by_flavor: dict[str, list[str]] = {}
    for name in sorted(names):
        by_flavor.setdefault(flavor_of(name), []).append(name)

    entries: list[dict[str, str]] = []
    for flavor, flavor_names in sorted(by_flavor.items()):
        tool = reference_tool(flavor)
        if tool is None:
            print(
                f"  {flavor:<10} SKIPPED: no reference tool installed", file=sys.stderr
            )
            continue
        answers = demangle_with(tool, flavor_names)
        for mangled, expected in sorted(answers.items()):
            entries.append(
                {
                    "mangled": mangled,
                    "expected": expected,
                    "flavor": flavor,
                    "source": tool,
                }
            )
        print(f"  {flavor:<10} {len(answers)} pairs via {tool}", file=sys.stderr)
    return entries


def serialize(entries: list[dict[str, str]]) -> str:
    return "".join(
        json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in entries
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit", type=int, default=400, help="maximum binaries to scan (default: 400)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the committed corpus differs from a fresh generation",
    )
    args = parser.parse_args()

    entries = build(args.limit)
    if not entries:
        print(
            "no pairs generated -- are nm and llvm-cxxfilt installed?", file=sys.stderr
        )
        return 2
    text = serialize(entries)

    if args.check:
        if not CORPUS.is_file():
            print(f"missing: {CORPUS}", file=sys.stderr)
            return 1
        if CORPUS.read_text(encoding="utf-8") != text:
            print(f"STALE: {CORPUS} differs from a fresh generation", file=sys.stderr)
            return 1
        print(f"current: {len(entries)} pairs")
        return 0

    CORPUS.parent.mkdir(parents=True, exist_ok=True)
    CORPUS.write_text(text, encoding="utf-8")
    print(f"wrote {len(entries)} pairs to {CORPUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
