#!/usr/bin/env python3
"""How much of each tool's output is even syntactically C.

    compilable.py <outdir> [--filter substr]

`gcc -fsyntax-only` with a deliberately permissive prelude that typedefs the
dialect scalars each tool invents (Ghidra's `undefined8`/`uint`, RetDec's
`int128_t`, angr's bit-width names). Implicit declarations, missing headers and
unknown struct tags are all downgraded to warnings, because the question is
"is this C" and not "would this link".

This is the one metric here that Glaurung's chosen output style is explicitly
designed to win — its decbench mode emits `extern` prototypes and typedefs so
the artifact stands alone — so read it as "did the tool intend to be
recompilable", not as a quality ranking. Ghidra makes no such claim and is not
being criticised for failing a test it never entered.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

TOOLS = ("glaurung", "ghidra", "angr", "retdec")

PRELUDE = r"""
/* Macros any C file would get from a header. Withholding them would score
   RetDec down for writing NULL, which is not a decompilation defect. */
#define NULL ((void *)0)
#define true 1
#define false 0
typedef signed char int8_t; typedef unsigned char uint8_t;
typedef short int16_t; typedef unsigned short uint16_t;
typedef int int32_t; typedef unsigned int uint32_t;
typedef long int64_t; typedef unsigned long uint64_t;
typedef __int128 int128_t; typedef unsigned __int128 uint128_t;
typedef unsigned char undefined, undefined1, byte;
typedef unsigned short undefined2, ushort, word;
typedef unsigned int undefined3, undefined4, uint, dword;
typedef unsigned long undefined5, undefined6, undefined7, undefined8, ulong, qword;
typedef unsigned long ulonglong; typedef long longlong;
typedef float float10; typedef double undefined10;
typedef void _Bool_; typedef unsigned long size_t; typedef long ssize_t;
typedef unsigned long __SIZE_TYPE__t;
typedef void *code; typedef unsigned long uintptr_t;
typedef struct { long q[2]; } unkbyte9, unkbyte10, unkuint9, unkuint10;
typedef union { long l[2]; } undefined16;
typedef unsigned long __dev_t, __ino_t, __off_t, __mode_t, __uid_t, __gid_t;
typedef long __time_t, __blksize_t, __blkcnt_t, __nlink_t;
typedef void FILE; typedef void stat; typedef void passwd; typedef void servent;
typedef void group; typedef void hostent; typedef void netent; typedef void protoent;
typedef void iconv_t; typedef void utsname; typedef void timeval; typedef void tm;
"""


def check(code: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as fh:
        fh.write(PRELUDE + "\n" + code + "\n")
        path = fh.name
    try:
        p = subprocess.run(
            [
                "gcc",
                "-fsyntax-only",
                "-std=gnu11",
                "-w",
                "-fpermissive",
                # GCC 14 made int/pointer confusion a hard error. Every
                # decompiler here produces it constantly and it says nothing
                # about whether the output is well-formed C, which is the
                # question; leaving it fatal would score all four on how
                # closely they match a 2024 conformance change instead.
                "-Wno-implicit-function-declaration",
                "-Wno-int-conversion",
                "-Wno-incompatible-pointer-types",
                "-Wno-implicit-int",
                "-Wno-builtin-declaration-mismatch",
                path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if p.returncode == 0:
            return True, ""
        first = next(
            (ln for ln in p.stderr.splitlines() if " error:" in ln), p.stderr[:120]
        )
        return False, first.split(" error: ")[-1][:90]
    except subprocess.TimeoutExpired:
        return False, "gcc timeout"
    finally:
        Path(path).unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--filter", default="")
    ap.add_argument("--max-per-tool", type=int, default=200)
    args = ap.parse_args()
    outdir = Path(args.outdir)
    needles = [s for s in args.filter.split(",") if s]

    tally = {t: [0, 0] for t in TOOLS}
    reasons: dict[str, dict[str, int]] = {t: defaultdict(int) for t in TOOLS}
    for tool in TOOLS:
        for p in sorted(outdir.glob(f"{tool}_*.json")):
            tag = p.name[len(tool) + 1 : -5]
            if not all(n in tag for n in needles):
                continue
            data = json.loads(p.read_text())
            for f in data.get("functions", []):
                if not f.get("code"):
                    continue
                if tally[tool][1] >= args.max_per_tool:
                    break
                ok, why = check(f["code"])
                tally[tool][1] += 1
                tally[tool][0] += int(ok)
                if not ok:
                    reasons[tool][why] += 1

    print("| tool | parses as C | sample size | most common failure |")
    print("|---|---|---|---|")
    for tool in TOOLS:
        ok, n = tally[tool]
        top = sorted(reasons[tool].items(), key=lambda kv: -kv[1])[:1]
        why = f"`{top[0][0]}` ({top[0][1]}x)" if top else "—"
        rate = f"{100 * ok / n:.0f}%" if n else "—"
        print(f"| {tool} | {rate} | {n} | {why} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
