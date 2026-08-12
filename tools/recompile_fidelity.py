#!/usr/bin/env python3
"""Measure how close RECOMPILED recovered C is to the code it came from.

WHY
---
Every gate in this repo asks what the recovered code *does*: the 656-case
fixture harness and `arch_roundtrip` execute it, `decbench_matrix` scores 56
synthetic cells. None of them asks what the recovered code *looks like when a
compiler is handed it back* — and that is exactly what DecBench's `byte_match`
scores. A 16 % `byte_match` drop reached `master` and survived four commits with
every one of those gates green.

Scoring the real holdout takes ~30 min per column (ingest drives Joern). This is
the same question asked locally, on our own fixtures, in seconds — fast enough
to A/B a code change, which is what makes it useful for finding a regression
rather than only reporting one.

WHAT IT MEASURES
----------------
For each function: compile the fixture, decompile that one function, recompile
the recovered C on its own, then compare the two instruction streams as
*mnemonic sequences* (operands are dropped: register allocation and literal
addresses are not what we are asking about). The score is a difflib similarity
ratio in [0, 1].

This is a PROXY, not DecBench's metric, and it is deliberately not calibrated
against it. Its value is differential: run it before and after a change and see
which way it moves.

KNOWN DIVERGENCE FROM byte_match — READ BEFORE TRUSTING A LARGE MOVE
--------------------------------------------------------------------
This tool compiles the WHOLE emitted translation unit. DecBench does not: its
`evalkit ingest` slices the submission with `split_c_functions`, which begins
each snippet at the function's SIGNATURE line and discards everything above it.
So every file-scope construct we emit — the portable `static unsigned char
glaurung_global_*[16]` objects above all — is present here and absent there.

That difference is not cosmetic. In a whole TU an uninitialised `static` array
is provably zero, so -O2 constant-folds every guard that reads it and deletes
the code behind it. Measured on 25 holdout functions: 20 compile SMALLER as a
whole TU than as the DecBench snippet (one went 3 instructions vs 130). A change
that suppresses those definitions therefore shows a large win HERE and exactly
zero on the holdout (A/B 2026-08-04: 227/250 compile, byte_match 0.2005 over
250, identical to the ULP both ways) while costing 4 of 656 execution-differential
cases. Before acting on a big move in this score, confirm it on
`tools/decbench_holdout.py`.

USAGE
-----
    tools/recompile_fidelity.py                     # x86-64, both opt levels
    tools/recompile_fidelity.py --arch aarch64
    tools/recompile_fidelity.py --json out.json     # for A/B comparison
    tools/recompile_fidelity.py --compare a.json    # diff against an earlier run
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "decompiler_fixtures" / "src"

TARGETS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "x86_64": ("gcc", (), "objdump"),
    "i386": ("gcc", ("-m32",), "objdump"),
    "aarch64": (
        "aarch64-linux-gnu-gcc",
        ("-march=armv8-a",),
        "aarch64-linux-gnu-objdump",
    ),
    "armv7": (
        "arm-linux-gnueabihf-gcc",
        ("-march=armv7-a", "-mfpu=vfpv3-d16", "-mthumb"),
        "arm-linux-gnueabihf-objdump",
    ),
}

#: A line of `objdump -d` output carrying one instruction.
INSN = re.compile(r"^\s+[0-9a-f]+:\s+(?:[0-9a-f]{2} )+\s*(\S+)")


def _run(argv: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )


def mnemonics(binary: Path, objdump: str, symbol: str | None = None) -> list[str]:
    """Mnemonic sequence for `symbol`, or the whole object when symbol is None."""
    done = _run([objdump, "-d", "--no-show-raw-insn", str(binary)])
    if done.returncode != 0:
        return []
    out: list[str] = []
    inside = symbol is None
    for line in done.stdout.splitlines():
        header = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if header:
            inside = symbol is None or header.group(1) == symbol
            continue
        if not inside:
            continue
        m = re.match(r"^\s+[0-9a-f]+:\s+(\S+)", line)
        if m and m.group(1) not in ("...",):
            out.append(m.group(1))
    return out


def score_function(
    arch: str,
    opt: str,
    source: Path,
    function: str,
    workdir: Path,
    rebuild_flags: tuple[str, ...] = (),
) -> float | None:
    cc, cflags, objdump = TARGETS[arch]
    original = workdir / f"{source.stem}-{arch}{opt}.so"
    built = _run(
        [
            cc,
            "-shared",
            "-fPIC",
            "-g",
            opt,
            "-w",
            *cflags,
            "-o",
            str(original),
            str(source),
        ]
    )
    if built.returncode != 0:
        return None

    decompiled = _run(
        [
            "glaurung",
            "decompile",
            str(original),
            "--func",
            function,
            "--style",
            "decbench",
            "--no-color",
        ],
        timeout=600,
    )
    if decompiled.returncode != 0 or not decompiled.stdout.strip():
        return None

    recovered_c = workdir / f"{function}-{arch}{opt}.c"
    recovered_c.write_text(decompiled.stdout)
    rebuilt = workdir / f"{function}-{arch}{opt}-rebuilt.so"
    again = _run(
        [
            cc,
            "-shared",
            "-fPIC",
            opt,
            "-w",
            *cflags,
            *rebuild_flags,
            "-o",
            str(rebuilt),
            str(recovered_c),
        ]
    )
    if again.returncode != 0:
        return 0.0  # does not recompile at all: the floor, not a skip

    before = mnemonics(original, objdump, function)
    after = mnemonics(rebuilt, objdump, function)
    if not before or not after:
        return None
    return difflib.SequenceMatcher(None, before, after).ratio()


def source_functions(source: Path) -> list[str]:
    """Top-level function names defined in a fixture source."""
    text = source.read_text(errors="replace")
    names = re.findall(
        r"^[A-Za-z_][\w \*]*?\b(\w+)\s*\([^;]*?\)\s*\{", text, re.MULTILINE
    )
    return [
        n for n in dict.fromkeys(names) if n not in ("if", "for", "while", "switch")
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arch", action="append", choices=sorted(TARGETS))
    ap.add_argument("--opt", action="append", choices=["-O0", "-O2"])
    ap.add_argument(
        "--fixture", action="append", help="fixture stem, e.g. 03_loop_shapes"
    )
    ap.add_argument("--json", type=Path, help="write per-function scores here")
    ap.add_argument(
        "--compare", type=Path, help="compare against an earlier --json run"
    )
    ap.add_argument("--limit", type=int, default=6, help="functions per fixture")
    ap.add_argument(
        "--rebuild-flag",
        action="append",
        default=[],
        help="extra flag for the REBUILD only, e.g. -fno-stack-protector",
    )
    args = ap.parse_args()

    arches = args.arch or ["x86_64"]
    opts = args.opt or ["-O0", "-O2"]
    sources = sorted(FIXTURES.glob("*.c"))
    if args.fixture:
        wanted = set(args.fixture)
        sources = [s for s in sources if s.stem in wanted]

    scores: dict[str, float] = {}
    with tempfile.TemporaryDirectory(prefix="fidelity-") as tmp:
        workdir = Path(tmp)
        for arch in arches:
            if shutil.which(TARGETS[arch][0]) is None:
                print(f"skip {arch}: no compiler", file=sys.stderr)
                continue
            for opt in opts:
                for source in sources:
                    for function in source_functions(source)[: args.limit]:
                        value = score_function(
                            arch,
                            opt,
                            source,
                            function,
                            workdir,
                            tuple(args.rebuild_flag),
                        )
                        if value is None:
                            continue
                        scores[f"{arch}::{opt}::{source.stem}::{function}"] = value

    if not scores:
        print("no functions scored", file=sys.stderr)
        return 1

    mean = sum(scores.values()) / len(scores)
    print(f"recompile fidelity: n={len(scores)} mean={mean:.4f}")

    if args.json:
        args.json.write_text(json.dumps(scores, indent=1, sort_keys=True) + "\n")
        print(f"wrote {args.json}")

    if args.compare and args.compare.is_file():
        old = json.loads(args.compare.read_text())
        common = sorted(set(old) & set(scores))
        if common:
            old_mean = sum(old[k] for k in common) / len(common)
            new_mean = sum(scores[k] for k in common) / len(common)
            better = sum(1 for k in common if scores[k] > old[k] + 1e-9)
            worse = sum(1 for k in common if scores[k] < old[k] - 1e-9)
            print(
                f"\nvs {args.compare.name}: n={len(common)} "
                f"{old_mean:.4f} -> {new_mean:.4f} ({new_mean - old_mean:+.4f}) "
                f"better={better} worse={worse}"
            )
            for k in sorted(common, key=lambda k: scores[k] - old[k])[:8]:
                if scores[k] < old[k] - 1e-9:
                    print(f"   {old[k]:.3f} -> {scores[k]:.3f}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
