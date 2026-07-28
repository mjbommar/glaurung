#!/usr/bin/env python3
"""Put the source and our decompiled C next to each other, with a verdict.

Reading the output is the check that originally caught what the metrics could not:
`structs:dist2` once scored a perfect graph edit distance while reading undefined
overlapping locals. The execution harness now recovers bounded integer-only DWARF
aggregates and executes that case, but the lesson remains: compressed text metrics
do not establish behavioural correctness.

So this exists to make looking cheap:

    tools/roundtrip_review.py                       # whole corpus -> markdown
    tools/roundtrip_review.py structs fixedpoint    # just these
    tools/roundtrip_review.py --only-broken         # skip what already works
    tools/roundtrip_review.py --compiler clang --opt O2

Each function gets its source, our C, and the execution-differential verdict, which
is the only one of the three that knows whether the code is right.

`structural` in the verdict column means NOT CHECKED, not "fine": function-pointer
parameters, complex/multi-eightbyte aggregates, pointer returns, and fragmented O2
DWARF can still prevent a safe execution differential.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "decbench_corpus" / "src"
FIXTURES = ROOT / "tests" / "decompiler_fixtures" / "src"

VERDICT_MARK = {
    "pass": "correct",
    "fail": "WRONG",
    "structural": "not checked",
    "timeout": "did not terminate",
    "missing": "MISSING",
    "nocases": "no test inputs",
}


def exported_functions(so: Path) -> list[str]:
    r = subprocess.run(["nm", "-D", "--defined-only", str(so)],
                       capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "T":
            out.append(parts[2])
    return out


def source_of(src: Path, name: str) -> str | None:
    """The function's source text, by brace matching from its signature.

    Deliberately simple: the corpus is plain C with one function per construct. A
    real parser would be more robust and is not what makes this useful.
    """
    text = src.read_text()
    m = re.search(rf"^[^\n]*\b{re.escape(name)}\s*\(", text, re.M)
    if not m:
        return None
    start = text.rfind("\n", 0, m.start()) + 1
    i = text.find("{", m.end())
    if i < 0:
        return None
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return text[start : j + 1]


def decompiled(so: Path, name: str) -> str | None:
    r = subprocess.run(
        ["nm", "-D", "--defined-only", str(so)], capture_output=True, text=True
    )
    va = None
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[1] == "T" and p[2] == name:
            va = int(p[0], 16)
    if va is None:
        return None
    r = subprocess.run(
        ["glaurung", "decompile", str(so), "--vas", hex(va), "--style", "decbench"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() or None


def verdicts(so: Path, src: Path, fixture: str) -> dict:
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "diff_decompile.py"), str(so), str(src),
         "--fixture", fixture, "--json"],
        capture_output=True, text=True, timeout=1800,
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return {}


def review(program: str, src: Path, compiler: str, opt: str, only_broken: bool,
           workdir: Path) -> tuple[str, dict]:
    so = workdir / f"rt-{program}-{compiler}-{opt}.so"
    build = subprocess.run(
        [compiler, "-shared", "-fPIC", "-g", f"-{opt}", "-o", str(so), str(src)],
        capture_output=True, text=True,
    )
    if build.returncode != 0:
        return f"## {program}\n\nDID NOT BUILD:\n\n```\n{build.stderr.strip()}\n```\n", {}

    v = verdicts(so, src, program)
    lines = [f"## {program}  ({compiler} -{opt})", ""]
    counts: dict[str, int] = {}
    for name in sorted(exported_functions(so)):
        status = v.get(name, {}).get("status", "not run")
        counts[status] = counts.get(status, 0) + 1
        if only_broken and status == "pass":
            continue
        srctext = source_of(src, name)
        if srctext is None:
            continue  # a CRT stub, not one of ours
        ours = decompiled(so, name) or "(decompile produced nothing)"
        detail = v.get(name, {}).get("detail", "")
        lines += [
            f"### `{name}` — **{VERDICT_MARK.get(status, status)}**"
            + (f"  \n`{detail}`" if detail else ""),
            "",
            "SOURCE:",
            "```c",
            srctext.strip(),
            "```",
            "OURS:",
            "```c",
            ours,
            "```",
            "",
        ]
    return "\n".join(lines), counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("programs", nargs="*", help="default: the whole DecBench corpus")
    ap.add_argument("--compiler", default="gcc")
    ap.add_argument("--opt", default="O0")
    ap.add_argument("--only-broken", action="store_true",
                    help="skip functions whose behaviour already matches")
    ap.add_argument("--fixtures", action="store_true",
                    help="review the fixture corpus instead")
    ap.add_argument("--out", default=None, help="write here instead of stdout")
    ap.add_argument("--workdir", default="/tmp")
    args = ap.parse_args()

    src_dir = FIXTURES if args.fixtures else CORPUS
    srcs = sorted(src_dir.glob("*.c"))
    if args.programs:
        want = set(args.programs)
        srcs = [s for s in srcs if s.stem in want]
        if not srcs:
            print(f"no such program in {src_dir}", file=sys.stderr)
            return 2

    workdir = Path(args.workdir)
    body, totals = [], {}
    for src in srcs:
        text, counts = review(src.stem, src, args.compiler, args.opt,
                              args.only_broken, workdir)
        body.append(text)
        for k, n in counts.items():
            totals[k] = totals.get(k, 0) + n

    executed = totals.get("pass", 0) + totals.get("fail", 0)
    rate = f"{100 * totals.get('pass', 0) // executed}%" if executed else "n/a"
    header = [
        f"# Round-trip review — {args.compiler} -{args.opt}",
        "",
        "The verdict is the execution differential: our decompiled C is recompiled and",
        "run against the original on the same inputs. It is the only one of our three",
        "measurements that knows whether the code is RIGHT.",
        "",
        f"**{totals.get('pass', 0)} of {executed} executed functions behave correctly ({rate}).**",
        "",
        "| verdict | count | meaning |",
        "|---|---|---|",
        f"| correct | {totals.get('pass', 0)} | same answer as the original on every input |",
        f"| WRONG | {totals.get('fail', 0)} | different answer, crash, or mutated buffer |",
        f"| not checked | {totals.get('structural', 0)} | no safe execution differential — NOT a pass |",
        f"| did not terminate | {totals.get('timeout', 0)} | ran past the per-call budget |",
        "",
        "`not checked` is the row to distrust: it is not a pass. The harness executes",
        "plain integer-only aggregates that fit one ABI eightbyte, but unsupported type",
        "shapes and fragmented DWARF still require direct output review.",
        "",
    ]
    text = "\n".join(header) + "\n".join(body)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}  ({totals.get('pass', 0)}/{executed} correct)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
